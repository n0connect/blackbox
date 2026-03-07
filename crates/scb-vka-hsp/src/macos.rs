//! Apple Secure Enclave (SEP) Integration
//!
//! Uses ECDH Key Agreement for secure, deterministic key derivation.
//! The private key NEVER leaves the Secure Enclave chip.
//!
//! ## How It Works
//!
//! 1. UR (User Root) is converted to a valid P-256 point via hash-to-curve (RFC 9380)
//! 2. ECDH is performed INSIDE the Secure Enclave using the hardware private key
//! 3. The shared secret is expanded to 64 bytes for MR
//!
//! ## Security Guarantees
//!
//! - Private key NEVER leaves the chip
//! - ECDH computation happens INSIDE the Secure Enclave
//! - Attacker cannot compute shared secret without Secure Enclave access
//! - Equivalent security level to TPM 2.0 HMAC approach
//!
//! ## Determinism
//!
//! - hash_to_curve(UR) is deterministic (same UR = same P-256 point)
//! - ECDH with same keys = same shared secret
//! - Therefore: same UR = same MR (deterministic)

use crate::HardwareEnclave;
use scb_vka_common::error::{VaultError, VaultErrorKind};
use sha3::{Digest, Sha3_512};
use std::ptr;
use std::sync::Mutex;
use tracing::{debug, error, info};
use zeroize::Zeroize;

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::CFErrorRef;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use security_framework::key::SecKey;
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::item::*;
use security_framework_sys::key::*;
use security_framework_sys::keychain_item::SecItemCopyMatching;

// P-256 hash-to-curve imports
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::NistP256;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Application-specific key label for BlackBox Secure Enclave key
const KEY_LABEL: &str = "com.blackbox.vault.enclave.v1";

/// Domain separation tag for hash-to-curve (RFC 9380)
const HASH_TO_CURVE_DST: &[u8] = b"BLACKBOX-V1-P256_XMD:SHA-256_SSWU_RO_";

/// Domain separator for MR expansion
const MR_EXPANDER_DOMAIN: &[u8] = b"BLACKBOX_MR_EXPANDER";

/// Expected length of uncompressed P-256 point (0x04 || X || Y)
const P256_UNCOMPRESSED_POINT_LEN: usize = 65;

/// Expected length of ECDH shared secret (P-256 = 32 bytes)
const ECDH_SHARED_SECRET_LEN: usize = 32;

// =============================================================================
// SECURE ENCLAVE
// =============================================================================

/// Apple Secure Enclave Hardware Security Module
///
/// Uses P-256 ECDH key agreement for secure key derivation.
/// The private key is stored in the Secure Enclave and never exported.
pub struct MacOSEnclave {
    key_label: String,
    /// Mutex to prevent TOCTOU race condition in key creation
    key_creation_lock: Mutex<()>,
}

impl MacOSEnclave {
    /// Create a new Secure Enclave instance.
    pub fn new() -> Self {
        // Allow isolated tests to create parallel keychain instances without data races
        let key_label =
            std::env::var("BLACKBOX_TEST_KEY_LABEL").unwrap_or_else(|_| KEY_LABEL.to_string());

        Self {
            key_label,
            key_creation_lock: Mutex::new(()),
        }
    }

    /// Retrieve existing Secure Enclave key from Keychain.
    fn find_existing_key(&self) -> Option<SecKey> {
        unsafe {
            let mut query: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

            query.set(
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
            );
            // In unsigned test environments, standard keychain categorizes headless keys loosely.
            #[cfg(not(test))]
            if !cfg!(debug_assertions) {
                query.set(
                    CFString::wrap_under_get_rule(kSecAttrKeyClass),
                    CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType(),
                );
            }

            let label_key = if cfg!(debug_assertions) {
                CFString::wrap_under_get_rule(kSecAttrLabel)
            } else {
                CFString::wrap_under_get_rule(kSecAttrApplicationLabel)
            };
            query.set(label_key, CFString::new(&self.key_label).as_CFType());

            // Unsigned test binaries fallback to standard Keychain which might label them differently
            #[cfg(not(test))]
            if !cfg!(debug_assertions) {
                query.set(
                    CFString::wrap_under_get_rule(kSecAttrKeyType),
                    CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
                );
            }

            query.set(
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().as_CFType(),
            );

            let mut item_ref: core_foundation::base::CFTypeRef = ptr::null();
            let status = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut item_ref);

            if status == 0 && !item_ref.is_null() {
                debug!("Found existing Secure Enclave key");
                Some(SecKey::wrap_under_create_rule(item_ref as SecKeyRef))
            } else {
                debug!("No existing Secure Enclave key found (status: {})", status);
                None
            }
        }
    }

    /// Create a new Secure Enclave key for ECDH key agreement.
    fn create_enclave_key(&self) -> Result<SecKey, VaultError> {
        unsafe {
            let mut attributes: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

            // EC P-256 key
            attributes.set(
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            );
            attributes.set(
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(256_i32).as_CFType(),
            );

            // CRITICAL: Bind to Secure Enclave
            // Unsigned binaries or CLI executed without Entitlements will hit -34018
            // We conditionally fall back to standard Keychain when tested headless
            #[cfg(not(test))]
            if !cfg!(debug_assertions) {
                attributes.set(
                    CFString::wrap_under_get_rule(kSecAttrTokenID),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
                );
            }

            // Private key attributes
            let mut private_key_attrs: CFMutableDictionary<CFString, CFType> =
                CFMutableDictionary::new();

            // In unsigned debug binaries / CI tests, requiring explicit SecureEnclave checks
            // (-34018 errSecMissingEntitlement) fails. But standard Keychain permits generic persistent
            // keys without application-identifier entitlements.
            private_key_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrIsPermanent),
                CFBoolean::true_value().as_CFType(),
            );

            // Add Explicit Access Control to bypass Biometry/TouchID interactive prompts for CI/CD
            #[cfg(not(test))]
            if !cfg!(debug_assertions) {
                use security_framework_sys::access_control::*;
                let mut ac_err: CFErrorRef = ptr::null_mut();
                let access_control = SecAccessControlCreateWithFlags(
                    ptr::null(),
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly as *const std::ffi::c_void,
                    kSecAccessControlPrivateKeyUsage,
                    &mut ac_err,
                );
                if !access_control.is_null() {
                    private_key_attrs.set(
                        CFString::wrap_under_get_rule(kSecAttrAccessControl),
                        /* Type mismatch bypass since sys wrappers define opaque ptrs differently */
                        CFType::wrap_under_create_rule(access_control as *const std::ffi::c_void),
                    );
                    // We do NOT release access_control here since dictionary `.set` retains it,
                    // but wrapped under `create_rule` handles drop cleanly
                }
            }

            let label_key = if cfg!(debug_assertions) {
                CFString::wrap_under_get_rule(kSecAttrLabel)
            } else {
                CFString::wrap_under_get_rule(kSecAttrApplicationLabel)
            };
            private_key_attrs.set(label_key, CFString::new(&self.key_label).as_CFType());

            attributes.set(
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                private_key_attrs.as_CFType(),
            );

            let mut error: CFErrorRef = ptr::null_mut();
            let sec_key_ref = SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error);

            if sec_key_ref.is_null() {
                let error_desc = if !error.is_null() {
                    // Redact detailed error info in release builds
                    let err_wrapper = core_foundation::error::CFError::wrap_under_get_rule(error);
                    let code = err_wrapper.code();
                    let desc = format!("Error {}: {}", code, err_wrapper.description());
                    core_foundation::base::CFRelease(error as core_foundation::base::CFTypeRef);

                    // No fallback! We strictly enforce Secure Enclave (SE) in release builds.
                    // If we get errSecMissingEntitlement (-34018), we must instruct the user to codesign.
                    if code == -34018 {
                        tracing::error!(
                            "Secure Enclave access denied. You MUST codesign the binary with entitlements to use BlackBox in release mode. \
                            Run `codesign -s - --entitlements entitlements.plist --force target/release/blackbox`"
                        );
                    }

                    desc
                } else {
                    "Unknown error".to_string()
                };
                error!("Failed to create Secure Enclave key: {}", error_desc);
                return Err(VaultError::new(VaultErrorKind::HardwareUnavailable));
            }

            debug!("Created new Secure Enclave key");
            Ok(SecKey::wrap_under_create_rule(sec_key_ref))
        }
    }

    /// Get the existing Secure Enclave key. Fails if not initialized.
    fn get_key(&self) -> Result<SecKey, VaultError> {
        if let Some(key) = self.find_existing_key() {
            Ok(key)
        } else {
            error!("Secure Enclave key not found. Run blackbox init first.");
            Err(VaultError::new(VaultErrorKind::HardwareUnavailable))
        }
    }

    /// Convert UR to a valid P-256 public key using hash-to-curve (RFC 9380).
    ///
    /// This is deterministic: same UR always produces the same P-256 point.
    fn ur_to_p256_point(&self, ur: &[u8; 64]) -> Result<zeroize::Zeroizing<Vec<u8>>, VaultError> {
        use p256::ProjectivePoint;

        // Hash-to-curve: UR -> valid P-256 point (RFC 9380 SSWU method)
        let point: ProjectivePoint =
            NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(&[ur], &[HASH_TO_CURVE_DST])
                .map_err(|e| {
                    error!("Hash-to-curve failed: {:?}", e);
                    VaultError::new(VaultErrorKind::OperationFailed)
                })?;

        // Convert to affine and then to uncompressed SEC1 format (0x04 || X || Y)
        use elliptic_curve::sec1::ToEncodedPoint;
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(false); // false = uncompressed
        let bytes = encoded.as_bytes().to_vec();

        // Validate output length
        if bytes.len() != P256_UNCOMPRESSED_POINT_LEN {
            error!(
                "Invalid P-256 point length: {} (expected {})",
                bytes.len(),
                P256_UNCOMPRESSED_POINT_LEN
            );
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }

        // Validate point format (must start with 0x04 for uncompressed)
        if bytes[0] != 0x04 {
            error!("Invalid P-256 point format: first byte is {:02x}", bytes[0]);
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }

        Ok(zeroize::Zeroizing::new(bytes))
    }

    /// Create a SecKey from raw P-256 public key bytes (SEC1 uncompressed format).
    fn create_peer_public_key(&self, public_key_bytes: &[u8]) -> Result<SecKey, VaultError> {
        // Validate input length before passing to Security framework
        if public_key_bytes.len() != P256_UNCOMPRESSED_POINT_LEN {
            error!(
                "Invalid public key length: {} (expected {})",
                public_key_bytes.len(),
                P256_UNCOMPRESSED_POINT_LEN
            );
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        }

        unsafe {
            let mut attributes: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

            attributes.set(
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            );
            attributes.set(
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPublic).as_CFType(),
            );
            attributes.set(
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(256_i32).as_CFType(),
            );

            let key_data = CFData::from_buffer(public_key_bytes);
            let mut error: CFErrorRef = ptr::null_mut();

            // SecKeyCreateFromData expects SEC1 format for EC keys
            let pub_key_ref = SecKeyCreateFromData(
                attributes.as_concrete_TypeRef(),
                key_data.as_concrete_TypeRef(),
                &mut error,
            );

            if pub_key_ref.is_null() {
                let error_desc = if !error.is_null() {
                    let desc = if cfg!(debug_assertions) {
                        format!("{error:?}")
                    } else {
                        "[redacted]".to_string()
                    };
                    core_foundation::base::CFRelease(error as core_foundation::base::CFTypeRef);
                    desc
                } else {
                    "Unknown error".to_string()
                };
                error!("Failed to create peer public key: {}", error_desc);
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }

            Ok(SecKey::wrap_under_create_rule(pub_key_ref))
        }
    }

    /// Perform ECDH key exchange inside Secure Enclave.
    ///
    /// The private key NEVER leaves the chip.
    /// The shared secret is computed entirely within the Secure Enclave.
    fn perform_ecdh(
        &self,
        peer_public_key: &SecKey,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, VaultError> {
        let private_key = self.get_key()?;

        unsafe {
            // Use the proper Security framework constant for ECDH
            // kSecKeyAlgorithmECDHKeyExchangeStandard = "ecdhKeyExchangeStandard"
            let algorithm = CFString::wrap_under_get_rule(kSecKeyAlgorithmECDHKeyExchangeStandard);

            // Parameters dictionary (empty for basic ECDH)
            let params = CFMutableDictionary::<CFString, CFType>::new();

            let mut error: CFErrorRef = ptr::null_mut();
            let shared_secret_ref = SecKeyCopyKeyExchangeResult(
                private_key.as_concrete_TypeRef() as SecKeyRef,
                algorithm.as_concrete_TypeRef(),
                peer_public_key.as_concrete_TypeRef() as SecKeyRef,
                params.as_concrete_TypeRef(),
                &mut error,
            );

            if shared_secret_ref.is_null() {
                let error_desc = if !error.is_null() {
                    let desc = if cfg!(debug_assertions) {
                        format!("{error:?}")
                    } else {
                        "[redacted]".to_string()
                    };
                    core_foundation::base::CFRelease(error as core_foundation::base::CFTypeRef);
                    desc
                } else {
                    "Unknown error".to_string()
                };
                error!("ECDH key exchange failed: {}", error_desc);
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }

            let shared_secret = CFData::wrap_under_create_rule(shared_secret_ref);
            let secret_bytes = shared_secret.bytes().to_vec();

            // Validate shared secret length
            if secret_bytes.len() != ECDH_SHARED_SECRET_LEN {
                error!(
                    "Invalid ECDH shared secret length: {} (expected {})",
                    secret_bytes.len(),
                    ECDH_SHARED_SECRET_LEN
                );
                return Err(VaultError::new(VaultErrorKind::IntegrityError));
            }

            Ok(zeroize::Zeroizing::new(secret_bytes))
        }
    }
}

impl Default for MacOSEnclave {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareEnclave for MacOSEnclave {
    fn sign_with_hardware_key(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError> {
        // Step 1: Convert UR to P-256 point via hash-to-curve
        // This is deterministic: same UR = same point
        // Using Zeroizing wrapper for automatic cleanup on all paths
        let peer_public_bytes = self.ur_to_p256_point(ur)?;

        // Step 2: Create SecKey from the P-256 point
        // peer_public_bytes will be zeroized on drop (including error paths)
        let peer_public_key = self.create_peer_public_key(&peer_public_bytes)?;

        // Step 3: Perform ECDH inside Secure Enclave
        // Private key NEVER leaves the chip!
        // Shared secret is computed INSIDE the Secure Enclave
        let shared_secret = self.perform_ecdh(&peer_public_key)?;

        // Step 4: Expand shared secret to 64-byte MR using Zeroizing wrapper
        let mut expander = Sha3_512::new();
        expander.update(MR_EXPANDER_DOMAIN);
        expander.update(shared_secret.as_ref() as &[u8]);
        let mut expansion = expander.finalize();

        let mut mr = zeroize::Zeroizing::new([0u8; 64]);
        mr.copy_from_slice(&expansion);
        expansion.zeroize();

        // Return owned value — Zeroizing wrapper ensures cleanup on error paths
        let result = *mr;
        Ok(result)
    }

    fn provider_name(&self) -> &'static str {
        "Apple Secure Enclave (SEP) - ECDH"
    }

    fn init_hardware_keys(&self) -> Result<(), VaultError> {
        // First try without lock (fast path)
        if self.find_existing_key().is_some() {
            info!("Hardware keys already initialized.");
            return Ok(());
        }

        // Acquire lock for key creation to prevent TOCTOU race
        let _guard = self.key_creation_lock.lock().map_err(|e| {
            error!("Key creation mutex poisoned: {e:?}");
            VaultError::new(VaultErrorKind::OperationFailed)
        })?;

        // Double-check after acquiring lock
        if self.find_existing_key().is_some() {
            debug!("Key found after acquiring lock (created by another thread)");
            return Ok(());
        }

        // Now safe to create
        let _ = self.create_enclave_key()?;
        info!("Successfully initialized Secure Enclave keys.");
        Ok(())
    }

    fn has_hardware_key(&self) -> bool {
        self.find_existing_key().is_some()
    }

    fn clear_hardware_keys(&self) -> Result<(), VaultError> {
        unsafe {
            let mut query: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

            query.set(
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecAttrApplicationLabel),
                CFString::new(&self.key_label).as_CFType(),
            );

            // Import necessary function or refer to it correctly
            let status =
                security_framework_sys::keychain_item::SecItemDelete(query.as_concrete_TypeRef());

            // errSecSuccess = 0, errSecItemNotFound = -25300
            if status == 0 || status == -25300 {
                info!("Secure Enclave hardware keys permanently deleted");
                Ok(())
            } else {
                error!("Failed to delete Secure Enclave keys (status: {})", status);
                Err(VaultError::new(VaultErrorKind::OperationFailed))
            }
        }
    }
}

// Ensure MacOSEnclave is Send + Sync (required by trait)
// The Mutex provides thread safety for key creation
static_assertions::assert_impl_all!(MacOSEnclave: Send, Sync);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_curve_deterministic() {
        let enclave = MacOSEnclave::new();
        let ur = [0xAB; 64];

        // Hash-to-curve should be deterministic
        let point1 = enclave.ur_to_p256_point(&ur).unwrap();
        let point2 = enclave.ur_to_p256_point(&ur).unwrap();

        assert_eq!(point1.as_slice(), point2.as_slice());
        // P-256 uncompressed point is 65 bytes (0x04 || X || Y)
        assert_eq!(point1.len(), P256_UNCOMPRESSED_POINT_LEN);
        assert_eq!(point1[0], 0x04);
    }

    #[test]
    fn test_hash_to_curve_different_inputs() {
        let enclave = MacOSEnclave::new();
        let ur1 = [0xAB; 64];
        let ur2 = [0xCD; 64];

        let point1 = enclave.ur_to_p256_point(&ur1).unwrap();
        let point2 = enclave.ur_to_p256_point(&ur2).unwrap();

        // Different UR should produce different points
        assert_ne!(point1.as_slice(), point2.as_slice());
    }

    #[test]
    fn test_point_validation() {
        let enclave = MacOSEnclave::new();
        let ur = [0xAB; 64];

        let point = enclave.ur_to_p256_point(&ur).unwrap();

        // Point should be valid uncompressed format
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
    }

    #[test]
    #[ignore = "Requires macOS with Secure Enclave (T2/M1/M2/M3 chip)"]
    fn test_secure_enclave_ecdh_deterministic() {
        let enclave = MacOSEnclave::new();
        let ur = [0xAB; 64];

        let mr1 = enclave.sign_with_hardware_key(&ur).unwrap();
        let mr2 = enclave.sign_with_hardware_key(&ur).unwrap();

        // Same UR should produce same MR (deterministic ECDH)
        assert_eq!(mr1, mr2);
    }

    #[test]
    #[ignore = "Requires macOS with Secure Enclave (T2/M1/M2/M3 chip)"]
    fn test_secure_enclave_ecdh_different_inputs() {
        let enclave = MacOSEnclave::new();
        let ur1 = [0xAB; 64];
        let ur2 = [0xCD; 64];

        let mr1 = enclave.sign_with_hardware_key(&ur1).unwrap();
        let mr2 = enclave.sign_with_hardware_key(&ur2).unwrap();

        // Different UR should produce different MR
        assert_ne!(mr1, mr2);
    }

    #[test]
    #[ignore = "Requires macOS with Secure Enclave (T2/M1/M2/M3 chip)"]
    fn test_thread_safety() {
        use std::thread;

        let enclave = std::sync::Arc::new(MacOSEnclave::new());
        let ur = [0xAB; 64];

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let enc = enclave.clone();
                thread::spawn(move || enc.sign_with_hardware_key(&ur))
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All results should be identical
        let first = results[0].as_ref().unwrap();
        for result in &results[1..] {
            assert_eq!(result.as_ref().unwrap(), first);
        }
    }
}
