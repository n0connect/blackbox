//! # scb-vka-crypto/engine
//!
//! ## HARDENED IMPLEMENTATION
//!
//! - `ConsumedNonce`: Enforces linearity.
//! - `AadPurpose`: Enum restriction.
//! - `Epoch`: `PartialOrd` checks.

use aead::{Aead, KeyInit, Payload};
use argon2::Argon2;
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::Mac;
use sha3::{Sha3_256, Sha3_512};

use scb_vka_common::config::{
    ARGON2_MAX_ITERATIONS, ARGON2_MAX_MEMORY_KIB, ARGON2_MAX_PARALLELISM, ARGON2_MIN_ITERATIONS,
    ARGON2_MIN_MEMORY_KIB, ARGON2_MIN_PARALLELISM, ARGON2_OUTPUT_LEN, CRYPTO_VERSION,
    CSPRNG_MAX_LEN, KEY_LEN, LABEL_CR, LABEL_LEAFS, MAC_LEN, NONCE_LEN, SALT_LEN, TAG_LEN,
};
use scb_vka_common::error::{VaultError, VaultErrorKind};

use crate::{CryptoVersion, Epoch, KeyCK, KeyCR, KeyKEK, KeyMK, KeyMR, KeyUR, Nonce, ObjectId};
use scb_vka_memory::SecureBuffer;

// Aliases for internal use
type HmacSha3_256 = hmac::Hmac<Sha3_256>;
type HmacSha3_512 = hmac::Hmac<Sha3_512>;

// =============================================================================
// PUBLIC UTILITIES (Types)
// =============================================================================

/// AAD Purpose Enum (Restricted, no raw strings)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive] // Future-proofing
pub enum AadPurpose {
    /// Header authentication
    Header,
    /// Object data authentication
    ObjectData,
    /// User defined purpose (bytes)
    UserPurpose([u8; 32]),
}

impl AadPurpose {
    /// Get bytes for purpose
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            AadPurpose::Header => b"header".to_vec(),
            AadPurpose::ObjectData => b"object_data".to_vec(),
            AadPurpose::UserPurpose(bytes) => {
                let len = bytes.iter().position(|&c| c == 0).unwrap_or(32);
                if len == 0 {
                    // Canonical representation for empty purpose to prevent collision
                    // Use a single null byte to distinguish from truly empty AAD
                    vec![0u8]
                } else {
                    bytes[..len].to_vec()
                }
            }
        }
    }
}

/// Linear Nonce Type (Consumed on use)
#[must_use]
pub struct ConsumedNonce(Nonce);

impl ConsumedNonce {
    /// Wrap nonce for consumption
    pub fn new(nonce: Nonce) -> Self {
        Self(nonce)
    }
}

/// Strict AAD Builder
#[must_use]
pub struct AadBuilder {
    object_id: Option<ObjectId>,
    version: Option<CryptoVersion>,
    epoch: Option<Epoch>,
    purpose: Option<AadPurpose>,
}

/// AAD Context
pub struct AadContext {
    pub(crate) data: Vec<u8>,
}

impl AadBuilder {
    /// New Builder
    pub fn new() -> Self {
        Self {
            object_id: None,
            version: None,
            epoch: None,
            purpose: None,
        }
    }

    /// Set Object ID
    pub fn object_id(mut self, oid: ObjectId) -> Self {
        self.object_id = Some(oid);
        self
    }

    /// Set Version
    pub fn version(mut self, ver: CryptoVersion) -> Self {
        self.version = Some(ver);
        self
    }

    /// Set Epoch
    pub fn epoch(mut self, epoch: Epoch) -> Self {
        self.epoch = Some(epoch);
        self
    }

    /// Set Purpose
    pub fn purpose(mut self, purpose: AadPurpose) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Build context
    ///
    /// # Errors
    /// Returns `VaultError` on validation failure.
    pub fn build(self) -> Result<AadContext, VaultError> {
        let oid = self
            .object_id
            .ok_or(VaultError::new(VaultErrorKind::InvalidInput))?;
        let ver = self
            .version
            .ok_or(VaultError::new(VaultErrorKind::InvalidInput))?;
        let ep = self
            .epoch
            .ok_or(VaultError::new(VaultErrorKind::InvalidInput))?;
        let pur = self
            .purpose
            .ok_or(VaultError::new(VaultErrorKind::InvalidInput))?;

        // Strict Construction: OID || Version(BE) || Epoch(BE) || PurposeBytes
        let pur_bytes = pur.as_bytes();
        let mut data = Vec::with_capacity(16 + 4 + 8 + pur_bytes.len());
        data.extend_from_slice(oid.as_bytes());
        data.extend_from_slice(&ver.value().to_be_bytes());
        data.extend_from_slice(&ep.value().to_be_bytes());
        data.extend_from_slice(&pur_bytes);

        Ok(AadContext { data })
    }
}

impl Default for AadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Centralized Nonce Factory (!Sync — must not be shared across threads)
pub struct NonceFactory {
    _marker: std::marker::PhantomData<*const ()>,
}

// SAFETY: NonceFactory is stateless — Send is fine. !Sync is enforced by PhantomData<*const ()>.
#[allow(unsafe_code)]
unsafe impl Send for NonceFactory {}

impl NonceFactory {
    /// Generate a nonce with counter portion zeroed for streaming safety
    ///
    /// Nonce format: [random: 16 bytes][counter: 8 bytes]
    /// The counter portion is zeroed to ensure safe increment in streaming operations.
    ///
    /// # Errors
    /// Returns `VaultError` if CSPRNG fails.
    pub fn generate() -> Result<Nonce, VaultError> {
        let mut bytes = [0u8; NONCE_LEN];
        // Only randomize the first 16 bytes; last 8 bytes are counter (start at 0)
        getrandom::getrandom(&mut bytes[..16])
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        // bytes[16..24] remains zeroed for counter
        Ok(Nonce::new(bytes))
    }

    /// Generate a fully random nonce (for non-streaming single-shot operations)
    ///
    /// # Errors
    /// Returns `VaultError` if CSPRNG fails.
    pub fn generate_random() -> Result<Nonce, VaultError> {
        let mut bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        Ok(Nonce::new(bytes))
    }
}

/// KDF parameters
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Memory in KiB
    pub memory_kib: u32,
    /// Iterations
    pub iterations: u32,
    /// Parallelism
    pub parallelism: u32,
}

impl KdfParams {
    /// Validate parameters against safety bounds
    ///
    /// # Errors
    /// Returns `VaultError` if parameters are invalid.
    pub fn validate(&self) -> Result<(), VaultError> {
        if self.memory_kib < ARGON2_MIN_MEMORY_KIB || self.memory_kib > ARGON2_MAX_MEMORY_KIB {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        if self.iterations < ARGON2_MIN_ITERATIONS || self.iterations > ARGON2_MAX_ITERATIONS {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        if self.parallelism < ARGON2_MIN_PARALLELISM || self.parallelism > ARGON2_MAX_PARALLELISM {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        Ok(())
    }
}

// =============================================================================
// TRAIT DEFINITION
// =============================================================================

/// Core Crypto Engine Trait
pub trait CryptoEngine {
    /// Orchestrated Root Derivation
    ///
    /// # SAFETY INVARIANTS
    /// 1.  **Parameters**: Must be validated via `params.validate()` before use.
    /// 2.  **Salt**: Must be fresh (caller responsibility, but typed).
    /// 3.  **Output**: Returns Role-Separated Keys.
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn derive_root_keys(
        &self,
        password: &[u8],
        salt: &[u8; SALT_LEN],
        enclave: &dyn scb_vka_hsp::HardwareEnclave,
        vid: &[u8; 16],
        timestamp: u64,
        params: &KdfParams,
    ) -> Result<(KeyKEK, KeyMK, KeyCK), VaultError>;

    /// Encrypt object (Strict AAD required, Consumes Nonce)
    ///
    /// # SAFETY INVARIANTS
    /// 1.  **Nonce Uniqueness**: `nonce` is consumed (moved). It CANNOT be reused.
    /// 2.  **AAD Integrity**: `aad` must be built via `AadBuilder`, ensuring context binding.
    /// 3.  **Key Role**: `dek` must be a `KeyKEK`.
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn encrypt_object(
        &self,
        dek: &KeyKEK,
        plaintext: &[u8],
        aad: &AadContext,
        nonce: ConsumedNonce, // Must pass a new nonce
    ) -> Result<(Vec<u8>, [u8; TAG_LEN]), VaultError>;

    /// Decrypt object
    ///
    /// # SAFETY INVARIANTS
    /// 1.  **Authentication**: Tag must match. If not, returns `AuthenticationFailed`.
    /// 2.  **Context**: AAD must match encryption context exactly.
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn decrypt_object(
        &self,
        dek: &KeyKEK,
        nonce: Nonce,
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        aad: &AadContext,
    ) -> Result<Vec<u8>, VaultError>;

    /// Wrap DEK
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn wrap_dek(
        &self,
        kek: &KeyKEK,
        dek: &KeyKEK,
        aad: &AadContext,
    ) -> Result<[u8; NONCE_LEN + KEY_LEN + TAG_LEN], VaultError>;

    /// Unwrap DEK
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn unwrap_dek(
        &self,
        kek: &KeyKEK,
        wrapped: &[u8; NONCE_LEN + KEY_LEN + TAG_LEN],
        aad: &AadContext,
    ) -> Result<KeyKEK, VaultError>;

    /// Compute MAC
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn compute_header_mac(
        &self,
        mk: &KeyMK,
        header_data: &[u8],
    ) -> Result<[u8; MAC_LEN], VaultError>;

    /// Verify MAC
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn verify_header_mac(
        &self,
        mk: &KeyMK,
        header_data: &[u8],
        mac: &[u8; MAC_LEN],
    ) -> Result<bool, VaultError>;

    /// Generate ephemeral DEK
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn generate_dek(&self) -> Result<KeyKEK, VaultError>;

    /// Get random bytes
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn csprng(&self, len: usize) -> Result<Vec<u8>, VaultError>;

    /// Encrypt stream (Chunked)
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn encrypt_stream(
        &self,
        dek: &KeyKEK,
        reader: &mut dyn std::io::Read,
        writer: &mut dyn std::io::Write,
        aad: &AadContext,
        base_nonce: ConsumedNonce,
    ) -> Result<u64, VaultError>;

    /// Decrypt stream (Chunked)
    ///
    /// # Errors
    /// Returns `VaultError` on failure.
    fn decrypt_stream(
        &self,
        dek: &KeyKEK,
        reader: &mut dyn std::io::Read,
        writer: &mut dyn std::io::Write,
        aad: &AadContext,
        base_nonce: Nonce,
        expected_data_len: u64,
    ) -> Result<u64, VaultError>;
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

/// Default Engine
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCryptoEngine;

impl CryptoEngine for DefaultCryptoEngine {
    fn derive_root_keys(
        &self,
        password: &[u8],
        salt: &[u8; SALT_LEN],
        enclave: &dyn scb_vka_hsp::HardwareEnclave,
        vid: &[u8; 16],
        timestamp: u64,
        params: &KdfParams,
    ) -> Result<(KeyKEK, KeyMK, KeyCK), VaultError> {
        params.validate()?;

        // 1. UR
        let argon_params = argon2::Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|_| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        );

        let mut ur_bytes = [0u8; 64];
        argon2
            .hash_password_into(password, salt, &mut ur_bytes)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        let ur = KeyUR::new(ur_bytes);

        // 2. MR (Hardware Enclave Signing)
        // Send the fully hashed User Root (UR) into the physical chip.
        // The chip uses its Non-Exportable key to sign the UR, turning it into the Master Root (MR).
        let mr_bytes = enclave.sign_with_hardware_key(ur.as_bytes())?;
        drop(ur); // EAGER ZEROIZE: UR's job is done. ZeroizeOnDrop wipes 64 bytes immediately.

        let mr = KeyMR::new(mr_bytes);

        // 3. CR
        let mut context_mac = <HmacSha3_512 as Mac>::new_from_slice(mr.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        drop(mr); // EAGER ZEROIZE: MR fed into HMAC, no longer needed.

        // Context Fusion: VID || Timestamp
        context_mac.update(vid);
        context_mac.update(&timestamp.to_le_bytes()); // Keep LE for timestamp logic
        context_mac.update(LABEL_CR);
        context_mac.update(&CRYPTO_VERSION.to_be_bytes());
        let cr_bytes: [u8; 64] = context_mac.finalize().into_bytes().into();
        let cr = KeyCR::new(cr_bytes);

        // 4. Leaf Keys
        let hkdf_leaf = Hkdf::<Sha3_512>::new(None, cr.as_bytes());
        drop(cr); // EAGER ZEROIZE: CR fed into HKDF, no longer needed.

        let mut leaf_info = Vec::new();
        leaf_info.extend_from_slice(LABEL_LEAFS);
        leaf_info.extend_from_slice(&CRYPTO_VERSION.to_be_bytes());

        let mut okm = [0u8; 96];
        hkdf_leaf
            .expand(&leaf_info, &mut okm)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        let kek = KeyKEK::new(
            okm[0..32]
                .try_into()
                .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?,
        );
        let mk = KeyMK::new(
            okm[32..64]
                .try_into()
                .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?,
        );
        let ck = KeyCK::new(
            okm[64..96]
                .try_into()
                .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?,
        );

        Ok((kek, mk, ck))
    }

    fn encrypt_object(
        &self,
        dek: &KeyKEK,
        plaintext: &[u8],
        aad: &AadContext,
        nonce: ConsumedNonce,
    ) -> Result<(Vec<u8>, [u8; TAG_LEN]), VaultError> {
        let cipher = XChaCha20Poly1305::new_from_slice(dek.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        let nonce_inner = nonce.0;
        let nonce_ga = aead::generic_array::GenericArray::from_slice(nonce_inner.as_bytes());

        let payload = Payload {
            msg: plaintext,
            aad: &aad.data,
        };

        let ciphertext = cipher
            .encrypt(nonce_ga, payload)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        let mut tag = [0u8; TAG_LEN];
        let ct_len = ciphertext.len() - TAG_LEN;
        tag.copy_from_slice(&ciphertext[ct_len..]);

        Ok((ciphertext[..ct_len].to_vec(), tag))
    }

    fn decrypt_object(
        &self,
        dek: &KeyKEK,
        nonce: Nonce,
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        aad: &AadContext,
    ) -> Result<Vec<u8>, VaultError> {
        let cipher = XChaCha20Poly1305::new_from_slice(dek.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        let mut combined = ciphertext.to_vec();
        combined.extend_from_slice(tag);

        let nonce_ga = aead::generic_array::GenericArray::from_slice(nonce.as_bytes());
        let payload = Payload {
            msg: &combined,
            aad: &aad.data,
        };

        cipher
            .decrypt(nonce_ga, payload)
            .map_err(|_| VaultError::new(VaultErrorKind::AuthenticationFailed))
    }

    fn wrap_dek(
        &self,
        kek: &KeyKEK,
        dek: &KeyKEK,
        aad: &AadContext,
    ) -> Result<[u8; NONCE_LEN + KEY_LEN + TAG_LEN], VaultError> {
        let nonce = NonceFactory::generate()?;
        let consumed = ConsumedNonce::new(nonce);

        let (ct, tag) = self.encrypt_object(kek, dek.as_bytes(), aad, consumed)?;

        let mut output = [0u8; NONCE_LEN + KEY_LEN + TAG_LEN];
        output[..NONCE_LEN].copy_from_slice(nonce.as_bytes());
        output[NONCE_LEN..NONCE_LEN + KEY_LEN].copy_from_slice(&ct);
        output[NONCE_LEN + KEY_LEN..].copy_from_slice(&tag);

        Ok(output)
    }

    fn unwrap_dek(
        &self,
        kek: &KeyKEK,
        wrapped: &[u8; NONCE_LEN + KEY_LEN + TAG_LEN],
        aad: &AadContext,
    ) -> Result<KeyKEK, VaultError> {
        let nonce_bytes: [u8; NONCE_LEN] = wrapped[..NONCE_LEN]
            .try_into()
            .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;
        let nonce = Nonce::new(nonce_bytes);

        let ct = &wrapped[NONCE_LEN..NONCE_LEN + KEY_LEN];
        let tag = &wrapped[NONCE_LEN + KEY_LEN..];

        let pt = self.decrypt_object(
            kek,
            nonce,
            ct,
            tag.try_into()
                .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?,
            aad,
        )?;

        if pt.len() != KEY_LEN {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }

        Ok(KeyKEK::new(pt.try_into().map_err(|_| {
            VaultError::new(VaultErrorKind::IntegrityError)
        })?))
    }

    fn compute_header_mac(
        &self,
        mk: &KeyMK,
        header_data: &[u8],
    ) -> Result<[u8; MAC_LEN], VaultError> {
        let mut mac = <HmacSha3_256 as Mac>::new_from_slice(mk.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        mac.update(header_data);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_header_mac(
        &self,
        mk: &KeyMK,
        header_data: &[u8],
        mac: &[u8; MAC_LEN],
    ) -> Result<bool, VaultError> {
        let computed = self.compute_header_mac(mk, header_data)?;
        Ok(scb_vka_common::util::ct_eq(&computed, mac))
    }

    fn generate_dek(&self) -> Result<KeyKEK, VaultError> {
        let mut key = [0u8; KEY_LEN];
        getrandom::getrandom(&mut key)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        Ok(KeyKEK::new(key))
    }

    fn csprng(&self, len: usize) -> Result<Vec<u8>, VaultError> {
        if len == 0 || len > CSPRNG_MAX_LEN {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        let mut buf = vec![0u8; len];
        getrandom::getrandom(&mut buf)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        Ok(buf)
    }

    fn encrypt_stream(
        &self,
        dek: &KeyKEK,
        reader: &mut dyn std::io::Read,
        writer: &mut dyn std::io::Write,
        aad: &AadContext,
        base_nonce: ConsumedNonce,
    ) -> Result<u64, VaultError> {
        // Use SecureBuffer for mlock protection and auto-zeroize on drop
        let mut buffer = SecureBuffer::new(scb_vka_common::config::STREAM_CHUNK_SIZE)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        let mut total_written = 0u64;
        let mut chunk_index = 0u64;
        let base_nonce_bytes = base_nonce.0.as_bytes(); // base_nonce is consumed here conceptually

        let mut mac = <HmacSha3_256 as hmac::Mac>::new_from_slice(dek.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        loop {
            let n = reader
                .read(buffer.as_mut_slice())
                .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
            if n == 0 {
                break;
            }

            // Deterministic Nonce: Base + ChunkIndex (Little Endian increment on last 8 bytes)
            let mut nonce_bytes = *base_nonce_bytes;
            let mut ctr = u64::from_le_bytes(
                nonce_bytes[16..24]
                    .try_into()
                    .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?,
            );
            ctr = ctr
                .checked_add(chunk_index)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
            nonce_bytes[16..24].copy_from_slice(&ctr.to_le_bytes());

            let nonce = Nonce::new(nonce_bytes);
            // We need a fresh ConsumedNonce for internal call, but we are managing the contract here manually
            // to allow the loop. We verified linearity by consuming base_nonce at function entry.
            // Safe because we increment nonce per chunk.
            let consumed = ConsumedNonce(nonce);

            let (ct, tag) = self.encrypt_object(dek, &buffer.as_mut_slice()[..n], aad, consumed)?;
            writer
                .write_all(&ct)
                .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
            writer
                .write_all(&tag)
                .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
            total_written += ct.len() as u64 + tag.len() as u64;

            mac.update(&ct);
            mac.update(&tag);

            chunk_index = chunk_index
                .checked_add(1)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        }
        let mac_result = mac.finalize().into_bytes();
        writer
            .write_all(&mac_result)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        total_written += mac_result.len() as u64;

        Ok(total_written)
    }

    fn decrypt_stream(
        &self,
        dek: &KeyKEK,
        reader: &mut dyn std::io::Read,
        writer: &mut dyn std::io::Write,
        aad: &AadContext,
        base_nonce: Nonce,
        expected_data_len: u64,
    ) -> Result<u64, VaultError> {
        let chunk_size = scb_vka_common::config::STREAM_CHUNK_SIZE;
        let encrypted_chunk_size = chunk_size + TAG_LEN;
        // Use SecureBuffer for mlock protection and auto-zeroize on drop
        let mut buffer = SecureBuffer::new(encrypted_chunk_size)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        let mut total_written = 0u64;
        let mut chunk_index = 0u64;
        let base_nonce_bytes = base_nonce.as_bytes();

        let mut mac = <HmacSha3_256 as hmac::Mac>::new_from_slice(dek.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        loop {
            if total_written == expected_data_len {
                let mut mac_bytes = [0u8; scb_vka_common::config::MAC_LEN];
                reader
                    .read_exact(&mut mac_bytes)
                    .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
                mac.verify_slice(&mac_bytes)
                    .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;
                break;
            }

            let remaining_pt = expected_data_len - total_written;
            let current_chunk_pt = usize::try_from(remaining_pt.min(chunk_size as u64))
                .map_err(|_| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
            let expected_read = current_chunk_pt + TAG_LEN;

            let mut read_count = 0;
            while read_count < expected_read {
                let n = reader
                    .read(&mut buffer.as_mut_slice()[read_count..expected_read])
                    .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
                if n == 0 {
                    break;
                }
                read_count += n;
            }

            if read_count != expected_read {
                return Err(VaultError::new(VaultErrorKind::IntegrityError));
            }

            let mut ct_clone = vec![0u8; expected_read - TAG_LEN];
            ct_clone.copy_from_slice(&buffer.as_mut_slice()[..expected_read - TAG_LEN]);

            let mut tag_clone = vec![0u8; TAG_LEN];
            tag_clone
                .copy_from_slice(&buffer.as_mut_slice()[expected_read - TAG_LEN..expected_read]);

            mac.update(&ct_clone);
            mac.update(&tag_clone);

            // Calculate Nonce
            let mut nonce_bytes = *base_nonce_bytes;
            let mut ctr = u64::from_le_bytes(
                nonce_bytes[16..24]
                    .try_into()
                    .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?,
            );
            ctr = ctr
                .checked_add(chunk_index)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
            nonce_bytes[16..24].copy_from_slice(&ctr.to_le_bytes());
            let nonce = Nonce::new(nonce_bytes);

            let tag_start = read_count - TAG_LEN;
            let slice = buffer.as_mut_slice();
            let (ct, tag) = slice[..read_count].split_at(tag_start);
            let tag_arr: [u8; TAG_LEN] = tag
                .try_into()
                .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;

            let pt = self.decrypt_object(dek, nonce, ct, &tag_arr, aad)?;
            writer
                .write_all(&pt)
                .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
            total_written += pt.len() as u64;

            chunk_index = chunk_index
                .checked_add(1)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        }
        Ok(total_written)
    }
}
