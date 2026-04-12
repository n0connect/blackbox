//! TPM 2.0 Hardware Security Module Integration
//!
//! Native TPM 2.0 HMAC key generation and signing.
//! The HMAC key is created as a primary key in the Owner hierarchy
//! and NEVER leaves the TPM chip.
//!
//! Platform support:
//! - Linux: /dev/tpmrm0 (kernel resource manager)

#![cfg(target_os = "linux")]

use crate::HardwareEnclave;
use scb_vka_common::error::{VaultError, VaultErrorKind};
use sha3::{Digest, Sha3_512};
use tracing::{debug, error, warn};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    structures::{
        Digest as TpmDigest, KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters,
    },
    Context, TctiNameConf,
};
use zeroize::Zeroize;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Domain separator for TPM HMAC operations (16 bytes, null-terminated)
const DOMAIN_SEPARATOR: &[u8; 16] = b"BLACKBOX_TPM_V1\0";

/// Domain separator for MR expansion
const MR_EXPANDER_DOMAIN: &[u8] = b"BLACKBOX_MR_EXPANDER";

// =============================================================================
// TPM ENCLAVE
// =============================================================================

/// TPM 2.0 Hardware Enclave
///
/// Uses a persistent HMAC key bound to the TPM Owner hierarchy.
/// The key material never leaves the physical TPM chip.
pub struct TpmEnclave {
    /// Cached TCTI configuration (computed lazily on first use)
    tcti_cache: std::sync::OnceLock<String>,
}

impl TpmEnclave {
    /// Create a new TPM Enclave instance.
    ///
    /// Does not connect to TPM until first use (lazy initialization).
    /// Device detection is deferred to avoid TOCTOU issues.
    pub fn new() -> Self {
        Self {
            tcti_cache: std::sync::OnceLock::new(),
        }
    }

    /// Get TCTI configuration string, detecting device lazily.
    ///
    /// SECURITY: Ignores TSS2_TCTI environment variable to prevent hijacking.
    fn get_tcti(&self) -> &str {
        self.tcti_cache.get_or_init(|| {
            // Linux: Kernel TPM Resource Manager (preferred)
            // Detection happens at connection time, not construction
            if std::path::Path::new("/dev/tpmrm0").exists() {
                debug!("Using TPM resource manager: /dev/tpmrm0");
                "device:/dev/tpmrm0".to_string()
            } else if std::path::Path::new("/dev/tpm0").exists() {
                warn!("Using raw TPM device /dev/tpm0 - resource manager recommended");
                "device:/dev/tpm0".to_string()
            } else {
                // Fallback to tabrmd (TPM2 Access Broker & Resource Manager Daemon)
                debug!("Attempting tabrmd connection");
                "tabrmd:".to_string()
            }
        })
    }

    /// Connect to TPM and return a context.
    ///
    /// SECURITY: Does NOT honor TSS2_TCTI environment variable to prevent
    /// TPM communication hijacking attacks.
    fn connect(&self) -> Result<Context, VaultError> {
        // SECURITY: Parse ONLY our trusted TCTI string, ignore environment
        let tcti_str = self.get_tcti();
        let tcti_conf = tcti_str.parse::<TctiNameConf>().map_err(|e| {
            error!("Failed to parse TCTI configuration '{}': {:?}", tcti_str, e);
            VaultError::new(VaultErrorKind::HardwareUnavailable)
        })?;

        Context::new(tcti_conf).map_err(|e| {
            error!("Failed to connect to TPM: {:?}", e);
            VaultError::new(VaultErrorKind::HardwareUnavailable)
        })
    }

    /// Create the HMAC primary key in TPM and return its handle.
    ///
    /// The key is created with:
    /// - Algorithm: HMAC-SHA256 (hardware accelerated)
    /// - Hierarchy: Owner (persistent across reboots with same owner auth)
    /// - Attributes: sign_encrypt, sensitive_data_origin, user_with_auth
    ///
    /// The private key material NEVER leaves the TPM.
    fn create_primary_hmac_key(&self, ctx: &mut Context) -> Result<KeyHandle, VaultError> {
        // Build HMAC key template
        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_fixed_tpm(true) // Key cannot be duplicated outside TPM
            .with_fixed_parent(true) // Key is bound to parent hierarchy
            .build()
            .map_err(|e| {
                error!("Failed to build TPM object attributes: {:?}", e);
                VaultError::new(VaultErrorKind::OperationFailed)
            })?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(TpmDigest::default())
            .build()
            .map_err(|e| {
                error!("Failed to build TPM public key template: {:?}", e);
                VaultError::new(VaultErrorKind::OperationFailed)
            })?;

        // Create primary key in Owner hierarchy
        // This key is deterministically derived from the hierarchy seed,
        // so the same key is regenerated on each boot (no persistence needed)
        let primary_key = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
            })
            .map_err(|e| {
                // Provide specific guidance for common errors
                let kind = if format!("{:?}", e).contains("AuthFail")
                    || format!("{:?}", e).contains("BAD_AUTH")
                {
                    error!(
                        "TPM Owner hierarchy requires authentication. \
                         Ensure TPM Owner password is not set or provide auth."
                    );
                    VaultErrorKind::AuthenticationFailed
                } else {
                    error!("Failed to create TPM primary key: {:?}", e);
                    VaultErrorKind::OperationFailed
                };
                VaultError::new(kind)
            })?;

        Ok(primary_key.key_handle)
    }

    /// Execute HMAC operation inside TPM with proper resource cleanup.
    ///
    /// The UR (User Root) is sent to TPM, HMACed with the hardware key,
    /// and the result is returned. The hardware key NEVER leaves the TPM.
    fn execute_tpm_hmac(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError> {
        let mut ctx = self.connect()?;
        let key_handle = self.create_primary_hmac_key(&mut ctx)?;

        // Ensure key handle is flushed even on error
        let result = self.do_hmac_operation(&mut ctx, key_handle, ur);

        // CRITICAL: Always flush the key handle to prevent resource exhaustion
        if let Err(e) = ctx.flush_context(key_handle.into()) {
            warn!("Failed to flush TPM key handle (non-fatal): {:?}", e);
        }

        result
    }

    /// Perform the actual HMAC operation.
    fn do_hmac_operation(
        &self,
        ctx: &mut Context,
        key_handle: KeyHandle,
        ur: &[u8; 64],
    ) -> Result<[u8; 64], VaultError> {
        // Prepare input: domain separator + UR
        // Using Zeroizing wrapper for automatic cleanup
        let mut input_data =
            zeroize::Zeroizing::new(Vec::with_capacity(DOMAIN_SEPARATOR.len() + 64));
        input_data.extend_from_slice(DOMAIN_SEPARATOR);
        input_data.extend_from_slice(ur);

        // Create MaxBuffer - note: we can't easily zeroize inside MaxBuffer,
        // but the data is just domain_separator + UR which isn't highly sensitive
        let buffer = MaxBuffer::try_from(input_data.as_slice()).map_err(|e| {
            error!("Failed to create TPM buffer: {:?}", e);
            VaultError::new(VaultErrorKind::OperationFailed)
        })?;

        // Execute HMAC inside TPM
        let hmac_result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(key_handle, buffer, HashingAlgorithm::Sha256)
            })
            .map_err(|e| {
                error!("TPM HMAC operation failed: {:?}", e);
                VaultError::new(VaultErrorKind::OperationFailed)
            })?;

        // TPM HMAC-SHA256 returns 32 bytes
        // Expand to 64 bytes using SHA3-512 for consistency with key hierarchy
        // Wrap in Zeroizing for automatic cleanup
        let mut hmac_bytes = zeroize::Zeroizing::new([0u8; 32]);
        let result_bytes = hmac_result.as_bytes();
        if result_bytes.len() != 32 {
            error!(
                "Unexpected HMAC result length: {} (expected 32)",
                result_bytes.len()
            );
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        hmac_bytes.copy_from_slice(result_bytes);

        let mut expander = Sha3_512::new();
        expander.update(MR_EXPANDER_DOMAIN);
        expander.update(hmac_bytes.as_ref());
        let mut expanded = expander.finalize();

        let mut mr = [0u8; 64];
        mr.copy_from_slice(&expanded);
        expanded.zeroize();

        Ok(mr)
    }
}

impl Default for TpmEnclave {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareEnclave for TpmEnclave {
    fn sign_with_hardware_key(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError> {
        self.execute_tpm_hmac(ur)
    }

    fn provider_name(&self) -> &'static str {
        "TPM 2.0 (Linux)"
    }

    fn clear_hardware_keys(&self) -> Result<(), VaultError> {
        // TPM primary keys in BlackBox are generated transiently from the Owner hierarchy seed.
        // They are never stored persistently in NVRAM by this application.
        // To definitively destroy them, the user must clear the TPM Owner hierarchy at the OS/BIOS level.
        tracing::info!(
            "TPM keys are transiently derived. No persistent application keys to delete."
        );
        Ok(())
    }

    fn init_hardware_keys(&self) -> Result<(), VaultError> {
        // Native TPM implementation handles primary keys dynamically in Owner hierarchy.
        // No persistent configuration needed.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcti_detection() {
        let enclave = TpmEnclave::new();
        let tcti = enclave.get_tcti();
        // Should return a valid TCTI string
        assert!(!tcti.is_empty());
        // Should be one of the expected formats
        assert!(tcti.starts_with("device:") || tcti.starts_with("tabrmd:"));
    }

    #[test]
    #[ignore = "Requires physical TPM hardware"]
    fn test_tpm_hmac_deterministic() {
        let enclave = TpmEnclave::new();
        let ur = [0xAB; 64];

        let mr1 = enclave.sign_with_hardware_key(&ur).unwrap();
        let mr2 = enclave.sign_with_hardware_key(&ur).unwrap();

        // Same UR should produce same MR (deterministic)
        assert_eq!(mr1, mr2);
    }

    #[test]
    #[ignore = "Requires physical TPM hardware"]
    fn test_tpm_hmac_different_inputs() {
        let enclave = TpmEnclave::new();
        let ur1 = [0xAB; 64];
        let ur2 = [0xCD; 64];

        let mr1 = enclave.sign_with_hardware_key(&ur1).unwrap();
        let mr2 = enclave.sign_with_hardware_key(&ur2).unwrap();

        // Different UR should produce different MR
        assert_ne!(mr1, mr2);
    }

    #[test]
    #[ignore = "Requires physical TPM hardware"]
    fn test_tpm_resource_cleanup() {
        let enclave = TpmEnclave::new();
        let ur = [0xAB; 64];

        // Call multiple times to ensure handles are being cleaned up
        for i in 0..50 {
            let result = enclave.sign_with_hardware_key(&ur);
            assert!(
                result.is_ok(),
                "Failed on iteration {}: {:?}",
                i,
                result.err()
            );
        }
    }
}
