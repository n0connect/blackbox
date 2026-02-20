//! TPM 2.0 Hardware Security Module Integration
//!
//! Native TPM 2.0 HMAC key generation and signing.
//! The HMAC key is created as a primary key in the Owner hierarchy
//! and NEVER leaves the TPM chip.
//!
//! Platform support:
//! - Linux: /dev/tpmrm0 (kernel resource manager)
//! - Windows: TBS (TPM Base Services)

#![cfg(any(target_os = "linux", target_os = "windows"))]

use crate::HardwareEnclave;
use scb_vka_common::error::{VaultError, VaultErrorKind};
use sha3::{Digest, Sha3_512};
use std::sync::Mutex;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::ObjectHandle,
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

/// TPM 2.0 Hardware Enclave
///
/// Uses a persistent HMAC key bound to the TPM Owner hierarchy.
/// The key material never leaves the physical TPM chip.
pub struct TpmEnclave {
    /// TCTI connection string
    tcti: String,
    /// Cached key handle (lazily initialized)
    key_handle: Mutex<Option<ObjectHandle>>,
}

impl TpmEnclave {
    /// Create a new TPM Enclave instance.
    ///
    /// Does not connect to TPM until first use (lazy initialization).
    pub fn new() -> Self {
        // Platform-specific TCTI configuration
        let tcti = if cfg!(target_os = "windows") {
            // Windows: TPM Base Services
            "tbs:".to_string()
        } else {
            // Linux: Kernel TPM Resource Manager (preferred)
            // Fallback order: tpmrm0 > tpm0
            if std::path::Path::new("/dev/tpmrm0").exists() {
                "device:/dev/tpmrm0".to_string()
            } else if std::path::Path::new("/dev/tpm0").exists() {
                "device:/dev/tpm0".to_string()
            } else {
                // Use tabrmd if available (TPM2 Access Broker & Resource Manager Daemon)
                "tabrmd:".to_string()
            }
        };

        Self {
            tcti,
            key_handle: Mutex::new(None),
        }
    }

    /// Connect to TPM and return a context
    fn connect(&self) -> Result<Context, VaultError> {
        let tcti_conf = TctiNameConf::from_environment_variable()
            .or_else(|_| self.tcti.parse::<TctiNameConf>())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        Context::new(tcti_conf).map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))
    }

    /// Create or retrieve the HMAC primary key in TPM.
    ///
    /// The key is created with:
    /// - Algorithm: HMAC-SHA256 (hardware accelerated)
    /// - Hierarchy: Owner (persistent across reboots with same owner auth)
    /// - Attributes: sign_encrypt, sensitive_data_origin, user_with_auth
    ///
    /// The private key material NEVER leaves the TPM.
    fn get_or_create_hmac_key(&self, ctx: &mut Context) -> Result<ObjectHandle, VaultError> {
        // Check cache first (handle poisoned mutex gracefully)
        {
            let cache = self
                .key_handle
                .lock()
                .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
            if let Some(handle) = *cache {
                return Ok(handle);
            }
        }

        // Build HMAC key template
        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_fixed_tpm(true) // Key cannot be duplicated outside TPM
            .with_fixed_parent(true) // Key is bound to parent hierarchy
            .build()
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(TpmDigest::default())
            .build()
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        // Create primary key in Owner hierarchy
        // This key is deterministically derived from the hierarchy seed,
        // so the same key is regenerated on each boot (no persistence needed)
        let primary_key = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
            })
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        let handle = primary_key.key_handle.into();

        // Cache the handle (handle poisoned mutex gracefully)
        {
            let mut cache = self
                .key_handle
                .lock()
                .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
            *cache = Some(handle);
        }

        Ok(handle)
    }

    /// Execute HMAC operation inside TPM.
    ///
    /// The UR (User Root) is sent to TPM, HMACed with the hardware key,
    /// and the result is returned. The hardware key NEVER leaves the TPM.
    fn execute_tpm_hmac(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError> {
        let mut ctx = self.connect()?;
        let key_handle = self.get_or_create_hmac_key(&mut ctx)?;

        // TPM HMAC has a max buffer size, so we may need to hash in chunks
        // For 64 bytes, we're well within the limit (typically 1024+ bytes)

        // Prepare input: domain separator + UR
        let mut input_data = Vec::with_capacity(64 + 16);
        input_data.extend_from_slice(b"BLACKBOX_TPM_V1\0"); // 16 bytes domain separator
        input_data.extend_from_slice(ur);

        let buffer = MaxBuffer::try_from(input_data.clone())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        input_data.zeroize();

        // Execute HMAC inside TPM
        let hmac_result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.hmac(key_handle, buffer, HashingAlgorithm::Sha256)
            })
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        // TPM HMAC-SHA256 returns 32 bytes
        // Expand to 64 bytes using SHA3-512 for consistency with key hierarchy
        let mut expander = Sha3_512::new();
        expander.update(b"BLACKBOX_MR_EXPANDER");
        expander.update(hmac_result.as_bytes());
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
        if cfg!(target_os = "windows") {
            "TPM 2.0 (Windows TBS)"
        } else {
            "TPM 2.0 (Linux)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
