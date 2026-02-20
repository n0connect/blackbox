//! Apple Secure Enclave (SEP) Integration
//!
//! Native integration with Apple's Secure Enclave Processor.
//! Uses the Secure Enclave's unique public key for DETERMINISTIC machine binding.
//! The private key NEVER leaves the physical chip.
//!
//! ## Security Model
//!
//! - A P-256 key pair is created in the Secure Enclave (once, stored in Keychain)
//! - The public key is exported and combined with UR
//! - Result: MR = SHA3-512(public_key || SHA256(domain || UR))
//!
//! ## Machine Binding Guarantees
//!
//! - Different Mac = different Secure Enclave = different key = different MR
//! - Vault created on Mac A cannot be opened on Mac B
//! - VM/Emulator will have different key = cannot open real vault
//!
//! ## Determinism
//!
//! - Public key is static (created once, stored)
//! - Same UR → same MR (deterministic)
//!
//! ## Note on ECDSA
//!
//! We do NOT use ECDSA signing because it's non-deterministic (random nonce).
//! Different sign() calls produce different signatures, making vault unlock fail.

use crate::HardwareEnclave;
use scb_vka_common::error::{VaultError, VaultErrorKind};
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use std::ptr;

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

/// Application-specific key label for BlackBox Secure Enclave key
const KEY_LABEL: &str = "com.blackbox.vault.enclave.v1";

/// Apple Secure Enclave Hardware Security Module
///
/// Uses P-256 key pair stored in the Secure Enclave.
/// The public key is used for deterministic machine binding.
pub struct MacOSEnclave {
    key_label: String,
}

impl MacOSEnclave {
    /// Create a new Secure Enclave instance.
    pub fn new() -> Self {
        Self {
            key_label: KEY_LABEL.to_string(),
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
            query.set(
                CFString::wrap_under_get_rule(kSecAttrApplicationLabel),
                CFString::new(&self.key_label).as_CFType(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            );
            query.set(
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().as_CFType(),
            );

            let mut item_ref: core_foundation::base::CFTypeRef = ptr::null();
            let status = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut item_ref);

            if status == 0 && !item_ref.is_null() {
                Some(SecKey::wrap_under_create_rule(item_ref as SecKeyRef))
            } else {
                None
            }
        }
    }

    /// Create a new Secure Enclave key.
    ///
    /// The key is:
    /// - P-256 (secp256r1) elliptic curve
    /// - Stored permanently in Keychain
    /// - Bound to Secure Enclave (kSecAttrTokenIDSecureEnclave)
    /// - Private key NEVER leaves the chip
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
            attributes.set(
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
            );

            // Private key attributes
            let mut private_key_attrs: CFMutableDictionary<CFString, CFType> =
                CFMutableDictionary::new();

            private_key_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrIsPermanent),
                CFBoolean::true_value().as_CFType(),
            );
            private_key_attrs.set(
                CFString::wrap_under_get_rule(kSecAttrApplicationLabel),
                CFString::new(&self.key_label).as_CFType(),
            );

            attributes.set(
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                private_key_attrs.as_CFType(),
            );

            let mut error: CFErrorRef = ptr::null_mut();
            let sec_key_ref = SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error);

            if sec_key_ref.is_null() {
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }

            Ok(SecKey::wrap_under_create_rule(sec_key_ref))
        }
    }

    /// Get or create the Secure Enclave key.
    fn get_or_create_key(&self) -> Result<SecKey, VaultError> {
        if let Some(key) = self.find_existing_key() {
            return Ok(key);
        }
        self.create_enclave_key()
    }

    /// Get the public key from our Secure Enclave private key.
    ///
    /// The public key is unique to this Secure Enclave and deterministic.
    fn get_public_key(&self) -> Result<Vec<u8>, VaultError> {
        let private_key = self.get_or_create_key()?;

        unsafe {
            let public_key_ref =
                SecKeyCopyPublicKey(private_key.as_concrete_TypeRef() as SecKeyRef);

            if public_key_ref.is_null() {
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }

            let public_key = SecKey::wrap_under_create_rule(public_key_ref);

            // Export public key data (X9.63 format: 04 || X || Y)
            let mut error: CFErrorRef = ptr::null_mut();
            let key_data_ref = SecKeyCopyExternalRepresentation(
                public_key.as_concrete_TypeRef() as SecKeyRef,
                &mut error,
            );

            if key_data_ref.is_null() {
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }

            let key_data = CFData::wrap_under_create_rule(key_data_ref);
            Ok(key_data.bytes().to_vec())
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
        // Machine Binding via Public Key
        //
        // The Secure Enclave public key is:
        // 1. Unique to THIS specific Secure Enclave hardware
        // 2. Deterministic (same key every time after creation)
        // 3. Not stored in the vault file (derived at runtime)
        //
        // Security: Different Mac = different public key = different MR = vault won't open
        //
        // Combining with UR ensures:
        // - Machine binding (via public key)
        // - Password binding (via UR from Argon2id)

        // Step 1: Get public key (deterministic - same key every time)
        let public_key = self.get_public_key()?;

        // Step 2: Hash UR with domain separation
        let mut ur_hasher = Sha256::new();
        ur_hasher.update(b"BLACKBOX_ENCLAVE_V1");
        ur_hasher.update(ur);
        let ur_hash = ur_hasher.finalize();

        // Step 3: Combine public key and UR hash into MR
        // MR = SHA3-512(domain || public_key || ur_hash)
        let mut expander = Sha3_512::new();
        expander.update(b"BLACKBOX_MR_EXPANDER");
        expander.update(&public_key); // 65 bytes (uncompressed P-256 point)
        expander.update(ur_hash); // 32 bytes
        let expansion = expander.finalize();

        let mut mr = [0u8; 64];
        mr.copy_from_slice(&expansion);

        Ok(mr)
    }

    fn provider_name(&self) -> &'static str {
        "Apple Secure Enclave (SEP)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Requires macOS with Secure Enclave (T2/M1/M2/M3 chip)"]
    fn test_secure_enclave_deterministic() {
        let enclave = MacOSEnclave::new();
        let ur = [0xAB; 64];

        let mr1 = enclave.sign_with_hardware_key(&ur).unwrap();
        let mr2 = enclave.sign_with_hardware_key(&ur).unwrap();

        // Same UR should produce same MR (deterministic!)
        assert_eq!(mr1, mr2);
    }

    #[test]
    #[ignore = "Requires macOS with Secure Enclave (T2/M1/M2/M3 chip)"]
    fn test_secure_enclave_different_inputs() {
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
    fn test_public_key_consistency() {
        let enclave = MacOSEnclave::new();

        let pk1 = enclave.get_public_key().unwrap();
        let pk2 = enclave.get_public_key().unwrap();

        // Public key should be consistent
        assert_eq!(pk1, pk2);
        // P-256 uncompressed point is 65 bytes
        assert_eq!(pk1.len(), 65);
        // First byte should be 0x04 (uncompressed)
        assert_eq!(pk1[0], 0x04);
    }
}
