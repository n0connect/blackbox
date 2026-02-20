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

/// Application-specific key label for BlackBox Secure Enclave key
const KEY_LABEL: &str = "com.blackbox.vault.enclave.v1";

/// Domain separation tag for hash-to-curve (RFC 9380)
const HASH_TO_CURVE_DST: &[u8] = b"BLACKBOX-V1-P256_XMD:SHA-256_SSWU_RO_";

/// Apple Secure Enclave Hardware Security Module
///
/// Uses P-256 ECDH key agreement for secure key derivation.
/// The private key is stored in the Secure Enclave and never exported.
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

    /// Convert UR to a valid P-256 public key using hash-to-curve (RFC 9380).
    ///
    /// This is deterministic: same UR always produces the same P-256 point.
    fn ur_to_p256_point(&self, ur: &[u8; 64]) -> Result<Vec<u8>, VaultError> {
        use p256::ProjectivePoint;

        // Hash-to-curve: UR -> valid P-256 point (RFC 9380 SSWU method)
        let point: ProjectivePoint =
            NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(&[ur], &[HASH_TO_CURVE_DST])
                .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        // Convert to affine and then to uncompressed SEC1 format (0x04 || X || Y)
        use elliptic_curve::sec1::ToEncodedPoint;
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(false); // false = uncompressed

        Ok(encoded.as_bytes().to_vec())
    }

    /// Create a SecKey from raw P-256 public key bytes (SEC1 uncompressed format).
    fn create_peer_public_key(&self, public_key_bytes: &[u8]) -> Result<SecKey, VaultError> {
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
            // Parameter order: parameters dict first, then key data
            let pub_key_ref = SecKeyCreateFromData(
                attributes.as_concrete_TypeRef(),
                key_data.as_concrete_TypeRef(),
                &mut error,
            );

            if pub_key_ref.is_null() {
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }

            Ok(SecKey::wrap_under_create_rule(pub_key_ref))
        }
    }

    /// Perform ECDH key exchange inside Secure Enclave.
    ///
    /// The private key NEVER leaves the chip.
    /// The shared secret is computed entirely within the Secure Enclave.
    fn perform_ecdh(&self, peer_public_key: &SecKey) -> Result<Vec<u8>, VaultError> {
        let private_key = self.get_or_create_key()?;

        unsafe {
            // Use ECDH with cofactor (standard ECDH for P-256)
            // kSecKeyAlgorithmECDHKeyExchangeStandard
            let algorithm = CFString::new("ecdhKeyExchangeStandard");

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
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }

            let shared_secret = CFData::wrap_under_create_rule(shared_secret_ref);
            Ok(shared_secret.bytes().to_vec())
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
        let peer_public_bytes = self.ur_to_p256_point(ur)?;

        // Step 2: Create SecKey from the P-256 point
        let peer_public_key = self.create_peer_public_key(&peer_public_bytes)?;

        // Step 3: Perform ECDH inside Secure Enclave
        // Private key NEVER leaves the chip!
        // Shared secret is computed INSIDE the Secure Enclave
        let shared_secret = self.perform_ecdh(&peer_public_key)?;

        // Step 4: Expand shared secret to 64-byte MR
        let mut expander = Sha3_512::new();
        expander.update(b"BLACKBOX_MR_EXPANDER");
        expander.update(&shared_secret);
        let expansion = expander.finalize();

        let mut mr = [0u8; 64];
        mr.copy_from_slice(&expansion);

        Ok(mr)
    }

    fn provider_name(&self) -> &'static str {
        "Apple Secure Enclave (SEP) - ECDH"
    }
}

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

        assert_eq!(point1, point2);
        // P-256 uncompressed point is 65 bytes (0x04 || X || Y)
        assert_eq!(point1.len(), 65);
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
        assert_ne!(point1, point2);
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
}
