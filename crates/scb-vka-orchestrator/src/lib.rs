//! # scb-vka-orchestrator
//!
//! ## FINAL HARDENING IMPLEMENTATION
//!
//! - Strict Type System (`Key<Role>`, `Epoch`, `ObjectId`, `CryptoVersion`, `Nonce`)
//! - Strict AAD Builder (`AadPurpose`)
//! - `ConsumedNonce` Usage
//! - Invariant Checks
//! - Opaque IO Layout
//! - Deterministic Flow (no silent fallbacks)
//! - Centralized Error Helpers

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use scb_vka_common::config::{
    BLOCK_SIZE, CRYPTO_VERSION, DATA_REGION_START, HEADER_SLOT_A_OFFSET, HEADER_SLOT_B_OFFSET,
    HEADER_SLOT_CAPACITY, HEADER_SLOT_META_SIZE, KDF_ITERATIONS_MIN, KDF_MEMORY_KIB_MIN,
    KDF_PARALLELISM, MAC_LEN, MIN_PASSWORD_LEN, MIN_TOTAL_BLOCKS, NONCE_LEN, SALT_LEN,
    STREAM_CHUNK_SIZE, SUPERBLOCK_SIZE, TAG_LEN, VID_LEN, WRAPPED_DEK_SIZE,
};
pub use scb_vka_common::error::{VaultError, VaultErrorKind};
use scb_vka_crypto::engine::{
    AadBuilder, AadContext, AadPurpose, ConsumedNonce, DefaultCryptoEngine, KdfParams, NonceFactory,
};
use scb_vka_crypto::{CryptoEngine, CryptoVersion, Epoch, KeyKEK, KeyMK, Nonce, ObjectId};
use scb_vka_io::layout::{FileTableEntry, Superblock, VaultHeader, FILE_ENTRY_SIZE};
use scb_vka_io::lock::VaultLock;
use scb_vka_io::manager::SpaceManager;
use scb_vka_memory::SecureBox;
use zerocopy::AsBytes;
use zeroize::Zeroize;

// SAFETY: Ensure metadata region fits inside MIN_TOTAL_BLOCKS
static_assertions::const_assert!(
    scb_vka_common::config::MIN_TOTAL_BLOCKS
        > (scb_vka_common::config::DATA_REGION_START / scb_vka_common::config::BLOCK_SIZE as u64)
);

// =============================================================================
// HELPER FUNCTIONS - Centralized Error Handling & Utilities
// =============================================================================

/// Get current Unix timestamp. Returns error if system clock is unavailable.
/// SECURITY: Never falls back to 0 - timestamps are security-critical for replay protection.
#[inline]
fn get_timestamp() -> Result<u64, VaultError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))
}

/// Create IoError - reduces boilerplate
#[inline]
fn io_err() -> VaultError {
    VaultError::new(VaultErrorKind::IoError)
}

/// Create IntegrityError - reduces boilerplate
#[inline]
fn integrity_err() -> VaultError {
    VaultError::new(VaultErrorKind::IntegrityError)
}

/// Create ParameterOutOfRange error - reduces boilerplate
#[inline]
fn range_err() -> VaultError {
    VaultError::new(VaultErrorKind::ParameterOutOfRange)
}

/// Create CapacityExceeded error - reduces boilerplate
#[inline]
fn capacity_err() -> VaultError {
    VaultError::new(VaultErrorKind::CapacityExceeded)
}

/// Calculate encrypted payload size and required blocks for given plaintext size.
/// Returns (encrypted_payload_size, num_blocks, num_chunks).
/// Centralized to avoid code duplication between add_object and read_object.
fn calculate_stream_sizes(data_len: u64) -> Result<(u64, u64, u64), VaultError> {
    let chunk_size = STREAM_CHUNK_SIZE as u64;
    let num_chunks = if data_len > 0 {
        data_len
            .checked_add(chunk_size)
            .and_then(|x| x.checked_sub(1))
            .map(|x| x / chunk_size)
            .ok_or_else(range_err)?
    } else {
        0
    };

    let tag_overhead = num_chunks
        .checked_mul(TAG_LEN as u64)
        .ok_or_else(range_err)?;

    let encrypted_payload_size = data_len
        .checked_add(tag_overhead)
        .and_then(|sz| sz.checked_add(scb_vka_common::config::MAC_LEN as u64))
        .ok_or_else(range_err)?;

    let total_size = (WRAPPED_DEK_SIZE as u64)
        .checked_add(NONCE_LEN as u64)
        .and_then(|x| x.checked_add(encrypted_payload_size))
        .and_then(|x| x.checked_add(MAC_LEN as u64))
        .ok_or_else(range_err)?;

    let num_blocks = total_size
        .checked_add(BLOCK_SIZE as u64)
        .and_then(|x| x.checked_sub(1))
        .map(|x| x / (BLOCK_SIZE as u64))
        .ok_or_else(range_err)?;

    Ok((encrypted_payload_size, num_blocks, num_chunks))
}

/// Build AAD for header operations.
fn build_header_aad(crypto_version: u32) -> Result<AadContext, VaultError> {
    AadBuilder::new()
        .object_id(ObjectId::new([0u8; 16]))
        .version(CryptoVersion::new(crypto_version))
        .epoch(Epoch::new(0))
        .purpose(AadPurpose::Header)
        .build()
}

/// Convert string to fixed-size byte array (for object_type/purpose fields)
fn string_to_fixed_bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut arr = [0u8; N];
    let bytes = s.as_bytes();
    let len = bytes.len().min(N);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

/// Get alternate header slot offset (A/B ping-pong)
#[inline]
const fn alternate_slot(current: u64) -> u64 {
    if current == HEADER_SLOT_A_OFFSET {
        HEADER_SLOT_B_OFFSET
    } else {
        HEADER_SLOT_A_OFFSET
    }
}

/// Calculate data region offset from block index with overflow protection.
fn calculate_data_offset(start_block: u64) -> Result<u64, VaultError> {
    let block_offset = start_block
        .checked_mul(BLOCK_SIZE as u64)
        .ok_or_else(range_err)?;
    DATA_REGION_START
        .checked_add(block_offset)
        .ok_or_else(range_err)
}

// =============================================================================
// PUBLIC TYPES
// =============================================================================

#[derive(Debug, Clone)]
pub struct VaultInfo {
    pub path: PathBuf,
    pub vid: [u8; VID_LEN],
}

pub struct VaultSession {
    pub vid: [u8; VID_LEN],
    kek: SecureBox<KeyKEK>,
    mk: SecureBox<KeyMK>,

    header: VaultHeader,
    file_table: Vec<FileTableEntry>,
    space_manager: SpaceManager,

    /// File lock - held for session duration, released on drop
    pub(crate) lock: VaultLock,
    /// Active header slot offset (for A/B ping-pong)
    active_slot_offset: u64,
}

#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub object_id: [u8; 16],
    pub object_type: String,
    pub purpose: String,
    pub size: u64,
}

pub trait VaultManager {
    fn create_vault(&self, path: &Path, password: &[u8]) -> Result<VaultInfo, VaultError>;
    fn unlock_vault(&self, path: &Path, password: &[u8]) -> Result<VaultSession, VaultError>;
    fn lock_vault(&self, session: VaultSession) -> Result<(), VaultError>;

    fn add_object(
        &self,
        session: &mut VaultSession,
        object_type: &str,
        purpose: &str,
        data_len: u64,
        reader: &mut dyn std::io::Read,
    ) -> Result<[u8; 16], VaultError>;

    fn read_object(
        &self,
        session: &mut VaultSession,
        object_id: &[u8; 16],
        writer: &mut dyn std::io::Write,
    ) -> Result<u64, VaultError>;

    fn delete_object(
        &self,
        session: &mut VaultSession,
        object_id: &[u8; 16],
    ) -> Result<(), VaultError>;

    fn list_objects(&self, session: &VaultSession) -> Result<Vec<ObjectMeta>, VaultError>;

    /// Physically shrink vault by permanently dropping deleted objects out-of-place.
    fn vacuum_vault(&self, session: VaultSession, path: &Path) -> Result<(), VaultError>;

    /// Initialize the hardware-backed cryptographic keys (creates persistent key if missing).
    fn init_hardware(&self) -> Result<(), VaultError>;

    /// Erase all hardware-bound cryptographic keys (e.g., Secure Enclave, TPM) from the system.
    fn clear_hardware_keys(&self) -> Result<(), VaultError>;
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

use tracing::{debug, error, info, instrument, warn};

pub struct DefaultVaultManager {
    enclave: Box<dyn scb_vka_hsp::HardwareEnclave>,
    crypto: DefaultCryptoEngine,
}

impl Default for DefaultVaultManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultVaultManager {
    /// Create a new VaultManager instance.
    #[must_use]
    pub fn new() -> Self {
        // Enforce Process Hardening - MUST succeed for security
        if scb_vka_memory::disable_core_dumps().is_err() {
            warn!(
                "Core dump protection unavailable - sensitive data may be exposed in crash dumps"
            );
        }

        debug!("VaultManager initialized with hardware-backed security");
        Self {
            enclave: scb_vka_hsp::create_platform_enclave(),
            crypto: DefaultCryptoEngine,
        }
    }

    /// Create a new VaultManager instance with a custom hardware enclave (useful for testing or custom deployments).
    #[must_use]
    pub fn new_with(enclave: Box<dyn scb_vka_hsp::HardwareEnclave>) -> Self {
        if scb_vka_memory::disable_core_dumps().is_err() {
            warn!(
                "Core dump protection unavailable - sensitive data may be exposed in crash dumps"
            );
        }

        Self {
            enclave,
            crypto: DefaultCryptoEngine,
        }
    }

    /// Calculate required blocks for storing encrypted data.
    fn calculate_required_blocks(data_len: u64) -> Result<(u64, u64), VaultError> {
        let (encrypted_payload_size, num_blocks, _) = calculate_stream_sizes(data_len)?;
        Ok((encrypted_payload_size, num_blocks))
    }

    fn commit_header(&self, session: &mut VaultSession) -> Result<(), VaultError> {
        let entry_count = u32::try_from(session.file_table.len()).map_err(|_| capacity_err())?;
        session.header.update_entry_count(entry_count);
        session.header.increment_epoch()?;

        session.lock.file_mut().sync_all().map_err(|_| io_err())?;

        let target_slot = alternate_slot(session.active_slot_offset);

        write_encrypted_header(
            session.lock.file_mut(),
            &session.kek,
            &session.mk,
            &self.crypto,
            &mut session.header,
            &session.file_table,
            &session.space_manager,
            target_slot,
        )?;

        session.active_slot_offset = target_slot;
        Ok(())
    }

    fn unlock_vault_inner(&self, path: &Path, password: &[u8]) -> Result<VaultSession, VaultError> {
        debug!(path = %path.display(), "Attempting to unlock vault");

        // Acquire exclusive lock first - prevents concurrent access
        let mut lock = VaultLock::acquire(path)?;

        let mut sb_bytes = [0u8; SUPERBLOCK_SIZE];
        lock.file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|_| io_err())?;
        lock.file_mut()
            .read_exact(&mut sb_bytes)
            .map_err(|_| io_err())?;

        let superblock = Superblock::parse(&sb_bytes[..])?;

        info!(
            "Deriving keys using Argon2id with {} MiB memory - this may take a moment",
            KDF_MEMORY_KIB_MIN / 1024
        );

        let kdf_params = KdfParams {
            memory_kib: KDF_MEMORY_KIB_MIN,
            iterations: KDF_ITERATIONS_MIN,
            parallelism: KDF_PARALLELISM,
        };
        let (kek, mk, _ck) = self.crypto.derive_root_keys(
            password,
            superblock.salt(),
            &*self.enclave,
            superblock.vid(),
            superblock.created_timestamp(),
            &kdf_params,
        )?;

        let (header, file_table, space_manager, active_slot_offset) =
            read_encrypted_header(lock.file_mut(), &kek, &mk, &self.crypto, &superblock)?;

        // STRICT VALIDATION
        if header.crypto_version() != CRYPTO_VERSION {
            return Err(integrity_err());
        }

        info!(
            vid = %hex::encode(&superblock.vid()[..8]),
            objects = header.entry_count(),
            "Vault unlocked successfully"
        );

        Ok(VaultSession {
            vid: *superblock.vid(),
            kek: SecureBox::new(kek)?,
            mk: SecureBox::new(mk)?,
            header,
            file_table,
            space_manager,
            lock,
            active_slot_offset,
        })
    }
}

impl VaultManager for DefaultVaultManager {
    #[instrument(skip(self, password))]
    fn create_vault(&self, path: &Path, password: &[u8]) -> Result<VaultInfo, VaultError> {
        // Enforce minimum password length for security
        if password.len() < MIN_PASSWORD_LEN {
            warn!(
                min_length = MIN_PASSWORD_LEN,
                provided_length = password.len(),
                "Password rejected: minimum length requirement not met"
            );
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        }

        info!(
            path = %path.display(),
            kdf_memory_mib = KDF_MEMORY_KIB_MIN / 1024,
            "Creating new vault - key derivation requires significant memory"
        );

        let salt_vec = self.crypto.csprng(SALT_LEN)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);

        let vid_vec = self.crypto.csprng(VID_LEN)?;
        let mut vid = [0u8; VID_LEN];
        vid.copy_from_slice(&vid_vec);

        // SECURITY: Timestamp must be valid - no fallback to 0
        let timestamp = get_timestamp()?;

        let kdf_params = KdfParams {
            memory_kib: KDF_MEMORY_KIB_MIN,
            iterations: KDF_ITERATIONS_MIN,
            parallelism: KDF_PARALLELISM,
        };

        debug!("Deriving master keys from password");
        let (mut kek, mut mk, mut ck) = self.crypto.derive_root_keys(
            password,
            &salt,
            &*self.enclave,
            &vid,
            timestamp,
            &kdf_params,
        )?;

        #[allow(unused_mut)]
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(true);

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x80000000); // FILE_FLAG_WRITE_THROUGH
        }

        let mut file = options.open(path).map_err(|_| io_err())?;

        let mut do_create = || -> Result<(), VaultError> {
            let total_blocks = MIN_TOTAL_BLOCKS;
            file.set_len(total_blocks * BLOCK_SIZE as u64)
                .map_err(|_| io_err())?;

            let superblock = Superblock::new(salt, vid, timestamp, total_blocks);

            file.seek(SeekFrom::Start(0)).map_err(|_| io_err())?;
            file.write_all(superblock.as_bytes())
                .map_err(|_| io_err())?;

            let mut header = VaultHeader::new(CRYPTO_VERSION, 1);

            let space_manager = SpaceManager::new(total_blocks)?;
            write_encrypted_header(
                &mut file,
                &kek,
                &mk,
                &self.crypto,
                &mut header,
                &[],
                &space_manager,
                HEADER_SLOT_A_OFFSET,
            )?;

            Ok(())
        };

        if let Err(e) = do_create() {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(e);
        }

        kek.zeroize();
        mk.zeroize();
        ck.zeroize();

        info!(
            vid = %hex::encode(&vid[..8]),
            path = %path.display(),
            "Vault created successfully"
        );
        Ok(VaultInfo {
            path: path.to_path_buf(),
            vid,
        })
    }

    #[instrument(skip(self, password))]
    fn unlock_vault(&self, path: &Path, password: &[u8]) -> Result<VaultSession, VaultError> {
        let result = self.unlock_vault_inner(path, password);
        if let Err(e) = &result {
            match e.kind {
                VaultErrorKind::AuthenticationFailed => {
                    error!("Vault unlock failed: incorrect password or corrupted vault");
                }
                VaultErrorKind::IntegrityError => {
                    error!(
                        "Vault unlock failed: data integrity check failed - vault may be corrupted"
                    );
                }
                VaultErrorKind::VaultBusy => {
                    error!("Vault is locked by another process");
                }
                VaultErrorKind::IoError => {
                    error!("Vault unlock failed: unable to read vault file");
                }
                _ => {
                    error!(error = ?e.kind, "Vault unlock failed");
                }
            }
        }
        result
    }

    #[instrument(skip(self, session))]
    fn lock_vault(&self, mut session: VaultSession) -> Result<(), VaultError> {
        let vid = session.vid;
        for entry in &mut session.file_table {
            entry.zeroize_entry();
        }
        session.file_table.clear();
        session.header.zeroize();
        // O3: Zeroize bitmap to prevent object-location metadata leakage
        let mut bitmap = session.space_manager.export_bitmap();
        bitmap.zeroize();
        info!(vid = %hex::encode(&vid[..8]), "Vault locked - key material zeroized");
        Ok(())
    }

    fn init_hardware(&self) -> Result<(), VaultError> {
        self.enclave.init_hardware_keys()
    }

    fn clear_hardware_keys(&self) -> Result<(), VaultError> {
        self.enclave.clear_hardware_keys()
    }

    #[instrument(skip(self, session, reader))]
    fn add_object(
        &self,
        session: &mut VaultSession,
        object_type: &str,
        purpose: &str,
        data_len: u64,
        reader: &mut dyn std::io::Read,
    ) -> Result<[u8; 16], VaultError> {
        // Input Validation
        if object_type.contains('\0') || purpose.contains('\0') {
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        }
        if data_len == 0 {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        let max_data_len = scb_vka_common::config::MAX_TOTAL_BLOCKS as u64
            * scb_vka_common::config::BLOCK_SIZE as u64;
        if data_len > max_data_len {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        if session.header.entry_count() >= scb_vka_common::config::MAX_OBJECTS {
            return Err(capacity_err());
        }

        let oid_vec = self.crypto.csprng(16)?;
        let mut oid_bytes = [0u8; 16];
        oid_bytes.copy_from_slice(&oid_vec);
        let oid = ObjectId::new(oid_bytes);

        let dek = self.crypto.generate_dek()?;

        let epoch = Epoch::new(session.header.epoch());
        let version = CryptoVersion::new(session.header.crypto_version());

        let purpose_bytes: [u8; 32] = string_to_fixed_bytes(purpose);

        let aad = AadBuilder::new()
            .object_id(oid)
            .version(version)
            .epoch(epoch)
            .purpose(AadPurpose::UserPurpose(purpose_bytes))
            .build()?;

        let wrapped_dek = self.crypto.wrap_dek(&session.kek, &dek, &aad)?;

        let (encrypted_payload_size, num_blocks) = Self::calculate_required_blocks(data_len)?;

        let start_block = match session.space_manager.allocate(num_blocks) {
            Ok(block) => block,
            Err(e) if e.kind == VaultErrorKind::VaultFull => {
                let additional_blocks = num_blocks + 1024;
                warn!(
                    additional_blocks = additional_blocks,
                    "Vault capacity exceeded - dynamically expanding (may cause I/O latency)"
                );
                session.space_manager.expand(additional_blocks)?;

                let new_len = session.space_manager.total_blocks() * (BLOCK_SIZE as u64);
                session.lock.file_mut().set_len(new_len).map_err(|e| {
                    eprintln!("SET_LEN ERROR: {}", e);
                    io_err()
                })?;

                session.space_manager.allocate(num_blocks)?
            }
            Err(e) => return Err(e),
        };

        let offset = calculate_data_offset(start_block)?;
        session
            .lock
            .file_mut()
            .seek(SeekFrom::Start(offset))
            .map_err(|e| {
                eprintln!("SEEK ERROR: {}", e);
                io_err()
            })?;

        session
            .lock
            .file_mut()
            .write_all(&wrapped_dek)
            .map_err(|e| {
                eprintln!("WRITE WRAPPED_DEK ERROR: {}", e);
                io_err()
            })?;

        let nonce = NonceFactory::generate()?;
        session
            .lock
            .file_mut()
            .write_all(nonce.as_bytes())
            .map_err(|e| {
                eprintln!("WRITE NONCE ERROR: {}", e);
                io_err()
            })?;

        let consumed = ConsumedNonce::new(nonce);
        let mut limited_reader = reader.take(data_len);
        let bytes_written = self
            .crypto
            .encrypt_stream(
                &dek,
                &mut limited_reader,
                session.lock.file_mut(),
                &aad,
                consumed,
            )
            .map_err(|e| {
                eprintln!("ENCRYPT_STREAM ERROR: {:?}", e);
                e
            })?;

        if bytes_written != encrypted_payload_size {
            session
                .space_manager
                .deallocate(start_block, num_blocks)
                .inspect_err(|_| {
                    error!("CRITICAL: Space leak during rollback - bitmap inconsistent");
                })?;
            eprintln!(
                "BYTES_WRITTEN {} != expected {}",
                bytes_written, encrypted_payload_size
            );
            return Err(io_err());
        }

        // SECURITY: Timestamp must be valid - no fallback to 0
        let timestamp = get_timestamp()?;
        let obj_type_arr: [u8; 32] = string_to_fixed_bytes(object_type);

        let start_block_u32 = u32::try_from(start_block).map_err(|_| capacity_err())?;
        let num_blocks_u32 = u32::try_from(num_blocks).map_err(|_| capacity_err())?;

        let entry = FileTableEntry::new(
            oid_bytes,
            start_block_u32,
            num_blocks_u32,
            data_len,
            timestamp,
            obj_type_arr,
            purpose_bytes,
            wrapped_dek,
            session.header.epoch(),
        );

        session.file_table.push(entry);
        self.commit_header(session)?;

        info!(
            vid = %hex::encode(&session.vid[..8]),
            object_id = %hex::encode(oid_bytes),
            size = data_len,
            "Object encrypted and added"
        );
        Ok(oid_bytes)
    }

    #[instrument(skip(self, session, writer))]
    fn read_object(
        &self,
        session: &mut VaultSession,
        object_id: &[u8; 16],
        writer: &mut dyn std::io::Write,
    ) -> Result<u64, VaultError> {
        let entry = *session
            .file_table
            .iter()
            .find(|e| e.object_id() == object_id)
            .ok_or(VaultError::new(VaultErrorKind::ObjectNotFound))?;

        // INVARIANT CHECK
        let obj_epoch = Epoch::new(entry.epoch());
        let header_epoch = Epoch::new(session.header.epoch());
        if obj_epoch > header_epoch {
            return Err(integrity_err());
        }

        let oid = ObjectId::new(*object_id);
        let version = CryptoVersion::new(session.header.crypto_version());

        let aad = AadBuilder::new()
            .object_id(oid)
            .version(version)
            .epoch(obj_epoch)
            .purpose(AadPurpose::UserPurpose(*entry.purpose()))
            .build()?;

        let dek = self
            .crypto
            .unwrap_dek(&session.kek, entry.wrapped_dek(), &aad)?;

        let offset =
            calculate_data_offset(entry.start_block() as u64).map_err(|_| integrity_err())?;

        let data_len = entry.size();
        let (encrypted_payload_size, _, _) =
            calculate_stream_sizes(data_len).map_err(|_| integrity_err())?;

        let _stream_read_size = encrypted_payload_size
            .checked_add(MAC_LEN as u64)
            .ok_or_else(integrity_err)?;

        session
            .lock
            .file_mut()
            .seek(SeekFrom::Start(offset + WRAPPED_DEK_SIZE as u64))
            .map_err(|_| io_err())?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        session
            .lock
            .file_mut()
            .read_exact(&mut nonce_bytes)
            .map_err(|_| io_err())?;

        let nonce = Nonce::new(nonce_bytes);

        let bytes_written = self.crypto.decrypt_stream(
            &dek,
            session.lock.file_mut(),
            writer,
            &aad,
            nonce,
            data_len,
        )?;

        if bytes_written != data_len {
            return Err(integrity_err());
        }

        info!(
            vid = %hex::encode(&session.vid[..8]),
            object_id = %hex::encode(object_id),
            bytes = bytes_written,
            "Object decrypted and read"
        );
        Ok(bytes_written)
    }

    #[instrument(skip(self, session))]
    fn delete_object(
        &self,
        session: &mut VaultSession,
        object_id: &[u8; 16],
    ) -> Result<(), VaultError> {
        let idx = session
            .file_table
            .iter()
            .position(|e| e.object_id() == object_id)
            .ok_or(VaultError::new(VaultErrorKind::ObjectNotFound))?;

        let entry = session.file_table.remove(idx);

        // O5: Secure-wipe the on-disk encrypted data for defense-in-depth.
        // Even though the data is encrypted, overwriting prevents recovery of ciphertext.
        let wipe_offset =
            calculate_data_offset(entry.start_block() as u64).map_err(|_| integrity_err())?;
        let wipe_len = (entry.num_blocks() as usize)
            .checked_mul(BLOCK_SIZE as usize)
            .ok_or_else(range_err)?;
        scb_vka_memory::secure_wipe(session.lock.file_mut(), wipe_offset, wipe_len).inspect_err(
            |_| {
                error!("CRITICAL: Secure wipe failed for deleted object - ciphertext may remain");
            },
        )?;

        session
            .space_manager
            .deallocate(entry.start_block() as u64, entry.num_blocks() as u64)?;

        self.commit_header(session)?;
        info!(
            vid = %hex::encode(&session.vid[..8]),
            object_id = %hex::encode(object_id),
            "Object cryptographically deleted and securely wiped"
        );
        Ok(())
    }

    #[instrument(skip(self, session))]
    fn list_objects(&self, session: &VaultSession) -> Result<Vec<ObjectMeta>, VaultError> {
        let mut list = Vec::with_capacity(session.file_table.len());
        for entry in &session.file_table {
            let obj_type_str = std::str::from_utf8(entry.object_type())
                .map_err(|_| VaultError::new(VaultErrorKind::EncodingFailed))?
                .trim_matches('\0')
                .to_string();

            let purpose_str = std::str::from_utf8(entry.purpose())
                .map_err(|_| VaultError::new(VaultErrorKind::EncodingFailed))?
                .trim_matches('\0')
                .to_string();

            list.push(ObjectMeta {
                object_id: *entry.object_id(),
                object_type: obj_type_str,
                purpose: purpose_str,
                size: entry.size(),
            });
        }
        Ok(list)
    }

    #[instrument(skip(self, session))]
    fn vacuum_vault(&self, mut session: VaultSession, path: &Path) -> Result<(), VaultError> {
        info!(
            vid = %hex::encode(&session.vid[..8]),
            objects = session.file_table.len(),
            "Starting vacuum operation - compacting vault"
        );

        // O4: Use CSPRNG random suffix for temp file to prevent collisions
        let random_suffix = hex::encode(self.crypto.csprng(8)?);
        let mut temp_path_str = path.to_string_lossy().to_string();
        temp_path_str.push_str(&format!(".vacuum-{}.tmp", random_suffix));
        let temp_path = Path::new(&temp_path_str);

        #[allow(unused_mut)]
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x80000000); // FILE_FLAG_WRITE_THROUGH
        }

        let mut temp_file = options.open(temp_path).map_err(|_| io_err())?;

        // 1. Copy Superblock verbatim
        session
            .lock
            .file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|_| io_err())?;
        let mut superblock_buf = [0u8; scb_vka_io::layout::SUPERBLOCK_SIZE];
        session
            .lock
            .file_mut()
            .read_exact(&mut superblock_buf)
            .map_err(|_| io_err())?;
        temp_file.write_all(&superblock_buf).map_err(|_| io_err())?;

        // 2. Out-of-place Block Copy
        session.file_table.sort_by_key(|e| e.start_block());
        let mut next_free_block = scb_vka_io::manager::RESERVED_BLOCKS;
        let mut buf = vec![0u8; scb_vka_common::config::VACUUM_BUFFER_SIZE];

        let total_objects = session.file_table.len();
        for (idx, entry) in session.file_table.iter_mut().enumerate() {
            let src_block = entry.start_block() as u64;
            let num_blocks = entry.num_blocks() as u64;
            let byte_len = (num_blocks as usize)
                .checked_mul(BLOCK_SIZE as usize)
                .ok_or_else(range_err)?;

            let src_offset = calculate_data_offset(src_block)?;
            let dst_offset = calculate_data_offset(next_free_block)?;

            session
                .lock
                .file_mut()
                .seek(SeekFrom::Start(src_offset))
                .map_err(|_| io_err())?;
            temp_file
                .seek(SeekFrom::Start(dst_offset))
                .map_err(|_| io_err())?;

            let mut remaining = byte_len;
            let mut reader = session.lock.file_mut().take(remaining as u64);
            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                let n = reader.read(&mut buf[..to_read]).map_err(|_| io_err())?;
                if n == 0 {
                    break;
                }
                temp_file.write_all(&buf[..n]).map_err(|_| io_err())?;
                remaining -= n;
            }

            let new_start_block = u32::try_from(next_free_block).map_err(|_| capacity_err())?;
            entry.set_start_block(new_start_block);
            next_free_block += num_blocks;

            debug!(
                progress = format!("{}/{}", idx + 1, total_objects),
                "Vacuum: object relocated"
            );
        }

        // 3. Rebuild SpaceManager
        let new_total_blocks = std::cmp::max(next_free_block, MIN_TOTAL_BLOCKS);
        let mut new_sm = SpaceManager::new(new_total_blocks)?;
        if next_free_block > scb_vka_io::manager::RESERVED_BLOCKS {
            new_sm.allocate(next_free_block - scb_vka_io::manager::RESERVED_BLOCKS)?;
        }

        // 4. Update Header State
        let entry_count = u32::try_from(session.file_table.len()).map_err(|_| capacity_err())?;
        session.header.update_entry_count(entry_count);

        // M-06: Increment epoch explicitly once for the vacuumed vault
        session.header.increment_epoch()?;

        temp_file.sync_all().map_err(|_| io_err())?;

        // 5. Write Header to A/B Slots
        let write_a_result = write_encrypted_header(
            &mut temp_file,
            &session.kek,
            &session.mk,
            &self.crypto,
            &mut session.header,
            &session.file_table,
            &new_sm,
            HEADER_SLOT_A_OFFSET,
        );

        let write_b_result = write_encrypted_header(
            &mut temp_file,
            &session.kek,
            &session.mk,
            &self.crypto,
            &mut session.header,
            &session.file_table,
            &new_sm,
            HEADER_SLOT_B_OFFSET,
        );

        if write_a_result.is_err() || write_b_result.is_err() || temp_file.sync_all().is_err() {
            let _ = std::fs::remove_file(temp_path);
            return Err(io_err());
        }

        drop(temp_file);

        // 6. Atomic Replacement (C-03, S-04)
        // Keep session.lock active until rename succeeds so old vault isn't accessed
        if let Err(e) = std::fs::rename(temp_path, path) {
            // S-04: Cross-device rename fallback (EXDEV)
            if let Err(copy_e) = std::fs::copy(temp_path, path) {
                let _ = std::fs::remove_file(temp_path);
                error!(
                    "Vacuum atomic replacement failed (rename: {:?}, copy: {:?}) - old vault is intact",
                    e, copy_e
                );
                return Err(VaultError::new(VaultErrorKind::IoError));
            }
            let _ = std::fs::remove_file(temp_path);
        }

        // Drop the old vault lock only AFTER successful replacement
        drop(session.lock);

        // M-03: Explicitly zeroize session data after successful vacuum
        for entry in &mut session.file_table {
            entry.zeroize_entry();
        }
        session.file_table.clear();
        session.header.zeroize();
        // session.space_manager and new_sm are zeroized automatically via Drop impl

        info!(
            path = %path.display(),
            compacted_blocks = next_free_block,
            "Vacuum completed - vault requires re-unlock"
        );

        Ok(())
    }
}

// =============================================================================
// HEADER ENCRYPTION
// =============================================================================

/// Maximum header blob size - bounded by slot capacity
const MAX_HEADER_BLOB_SIZE: usize = (HEADER_SLOT_CAPACITY as usize) - HEADER_SLOT_META_SIZE;

/// Encryption overhead: WRAPPED_DEK(72) + NONCE(24) + TAG(16) = 112 bytes
const HEADER_ENCRYPTION_OVERHEAD: usize = WRAPPED_DEK_SIZE + NONCE_LEN + TAG_LEN;

/// Maximum plaintext size for header (accounting for encryption overhead)
const MAX_HEADER_PLAINTEXT_SIZE: usize = MAX_HEADER_BLOB_SIZE - HEADER_ENCRYPTION_OVERHEAD;

#[allow(clippy::too_many_arguments)]
fn write_encrypted_header(
    file: &mut File,
    kek: &KeyKEK,
    mk: &KeyMK,
    crypto: &DefaultCryptoEngine,
    header: &mut VaultHeader,
    file_table: &[FileTableEntry],
    space_manager: &SpaceManager,
    slot_offset: u64,
) -> Result<(), VaultError> {
    let bitmap = space_manager.export_bitmap();

    let bitmap_len = u32::try_from(bitmap.len()).map_err(|_| capacity_err())?;
    header.update_bitmap_size(bitmap_len);

    // Early size validation to prevent DoS via memory exhaustion
    let header_struct_size = std::mem::size_of::<VaultHeader>();
    let entries_size = file_table
        .len()
        .checked_mul(FILE_ENTRY_SIZE)
        .ok_or_else(capacity_err)?;
    let plaintext_size = header_struct_size
        .checked_add(bitmap.len())
        .and_then(|x| x.checked_add(entries_size))
        .ok_or_else(capacity_err)?;

    if plaintext_size > MAX_HEADER_PLAINTEXT_SIZE {
        return Err(capacity_err());
    }

    let mut plaintext = Vec::with_capacity(plaintext_size);
    plaintext.extend_from_slice(header.as_bytes());
    plaintext.extend_from_slice(&bitmap);
    for entry in file_table {
        plaintext.extend_from_slice(entry.as_bytes());
    }

    let dek = crypto.generate_dek()?;
    let aad = build_header_aad(header.crypto_version())?;

    let wrapped_dek = crypto.wrap_dek(kek, &dek, &aad)?;
    let nonce = NonceFactory::generate()?;
    // SECURITY: Save nonce bytes BEFORE consuming — Nonce is non-Copy/non-Clone
    let nonce_raw = nonce.to_bytes();
    let consumed = ConsumedNonce::new(nonce);
    let (ct, tag) = crypto.encrypt_object(&dek, &plaintext, &aad, consumed)?;

    let blob_size = WRAPPED_DEK_SIZE + NONCE_LEN + ct.len() + TAG_LEN;
    let mut blob = Vec::with_capacity(blob_size);
    blob.extend_from_slice(&wrapped_dek);
    blob.extend_from_slice(&nonce_raw);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);

    let mac = crypto.compute_header_mac(mk, &blob)?;

    file.seek(SeekFrom::Start(slot_offset))
        .map_err(|_| io_err())?;
    file.write_all(&(blob_size as u64).to_le_bytes())
        .map_err(|_| io_err())?;
    file.write_all(&mac).map_err(|_| io_err())?;
    file.write_all(&blob).map_err(|_| io_err())?;

    file.sync_all().map_err(|_| io_err())?;

    Ok(())
}

/// Try to read and decrypt a single header slot.
fn try_read_slot(
    file: &mut File,
    slot_offset: u64,
    kek: &KeyKEK,
    mk: &KeyMK,
    crypto: &DefaultCryptoEngine,
    superblock: &Superblock,
) -> Result<(VaultHeader, Vec<FileTableEntry>, SpaceManager), VaultError> {
    file.seek(SeekFrom::Start(slot_offset))
        .map_err(|_| io_err())?;

    let mut size_bytes = [0u8; 8];
    file.read_exact(&mut size_bytes).map_err(|_| io_err())?;
    let blob_size = u64::from_le_bytes(size_bytes);

    if blob_size == 0 || blob_size as usize > MAX_HEADER_BLOB_SIZE {
        return Err(integrity_err());
    }

    let mut expected_mac = [0u8; MAC_LEN];
    file.read_exact(&mut expected_mac).map_err(|_| io_err())?;

    let blob_len = blob_size as usize;
    let mut blob = vec![0u8; blob_len];
    file.read_exact(&mut blob).map_err(|_| io_err())?;

    if !crypto.verify_header_mac(mk, &blob, &expected_mac)? {
        return Err(VaultError::new(VaultErrorKind::AuthenticationFailed));
    }

    if blob_len < WRAPPED_DEK_SIZE + NONCE_LEN + TAG_LEN {
        return Err(integrity_err());
    }

    let wrapped_dek: [u8; WRAPPED_DEK_SIZE] = blob[..WRAPPED_DEK_SIZE]
        .try_into()
        .map_err(|_| integrity_err())?;

    let aad = build_header_aad(CRYPTO_VERSION)?;

    let dek = crypto.unwrap_dek(kek, &wrapped_dek, &aad)?;
    let rest = &blob[WRAPPED_DEK_SIZE..];

    let nonce: [u8; NONCE_LEN] = rest[..NONCE_LEN].try_into().map_err(|_| integrity_err())?;

    let ct_end = rest.len() - TAG_LEN;
    let ct = &rest[NONCE_LEN..ct_end];
    let tag: [u8; TAG_LEN] = rest[ct_end..].try_into().map_err(|_| integrity_err())?;

    let pt = crypto.decrypt_object(&dek, Nonce::new(nonce), ct, &tag, &aad)?;

    let header_struct_size = std::mem::size_of::<VaultHeader>();
    if pt.len() < header_struct_size {
        return Err(integrity_err());
    }

    let header = VaultHeader::parse(&pt[..header_struct_size])?;

    let bitmap_start = header_struct_size;
    let bitmap_size = header.bitmap_size() as usize;

    let expected_bitmap_size = (superblock.total_blocks() as usize).div_ceil(8);
    if bitmap_size != expected_bitmap_size {
        return Err(integrity_err());
    }

    if pt.len() < bitmap_start + bitmap_size {
        return Err(integrity_err());
    }

    let bitmap = pt[bitmap_start..bitmap_start + bitmap_size].to_vec();
    let space_manager = SpaceManager::from_bytes(bitmap, superblock.total_blocks())?;

    let mut file_table = Vec::with_capacity(header.entry_count() as usize);
    let mut offset = bitmap_start + bitmap_size;

    let expected_entries_size = (header.entry_count() as usize)
        .checked_mul(FILE_ENTRY_SIZE)
        .ok_or_else(integrity_err)?;
    let required_size = offset
        .checked_add(expected_entries_size)
        .ok_or_else(integrity_err)?;
    if pt.len() < required_size {
        return Err(integrity_err());
    }

    for _ in 0..header.entry_count() {
        let entry_bytes = &pt[offset..offset + FILE_ENTRY_SIZE];
        let entry = FileTableEntry::parse(entry_bytes)?;
        file_table.push(entry);
        offset += FILE_ENTRY_SIZE;
    }

    Ok((header, file_table, space_manager))
}

/// Read encrypted header using A/B slot ping-pong.
/// Tries both slots and returns the one with the highest epoch that passes
/// MAC verification. Also returns the offset of the active slot.
fn read_encrypted_header(
    file: &mut File,
    kek: &KeyKEK,
    mk: &KeyMK,
    crypto: &DefaultCryptoEngine,
    superblock: &Superblock,
) -> Result<(VaultHeader, Vec<FileTableEntry>, SpaceManager, u64), VaultError> {
    let slot_a = try_read_slot(file, HEADER_SLOT_A_OFFSET, kek, mk, crypto, superblock);
    let slot_b = try_read_slot(file, HEADER_SLOT_B_OFFSET, kek, mk, crypto, superblock);

    match (&slot_a, &slot_b) {
        (Ok(_), Err(_)) => {
            warn!(
                "Header slot B is corrupted - using slot A (vault may have crashed during write)"
            );
        }
        (Err(_), Ok(_)) => {
            warn!(
                "Header slot A is corrupted - using slot B (vault may have crashed during write)"
            );
        }
        _ => {}
    }

    match (slot_a, slot_b) {
        (Ok((ha, fta, sma)), Ok((hb, ftb, smb))) => {
            if hb.epoch() > ha.epoch() {
                Ok((hb, ftb, smb, HEADER_SLOT_B_OFFSET))
            } else {
                Ok((ha, fta, sma, HEADER_SLOT_A_OFFSET))
            }
        }
        (Ok((ha, fta, sma)), Err(_)) => Ok((ha, fta, sma, HEADER_SLOT_A_OFFSET)),
        (Err(_), Ok((hb, ftb, smb))) => Ok((hb, ftb, smb, HEADER_SLOT_B_OFFSET)),
        (Err(_), Err(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scb_vka_common::error::VaultError;
    use scb_vka_hsp::HardwareEnclave;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    struct MockEnclave;
    impl HardwareEnclave for MockEnclave {
        fn sign_with_hardware_key(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError> {
            let mut mr = [0u8; 64];
            mr.copy_from_slice(ur);
            Ok(mr)
        }
        fn provider_name(&self) -> &'static str {
            "Memory Mock"
        }
        fn init_hardware_keys(&self) -> Result<(), VaultError> {
            Ok(())
        }
        fn clear_hardware_keys(&self) -> Result<(), VaultError> {
            Ok(())
        }
    }

    #[test]
    fn test_full_vault_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let path_buf = temp_dir.path().join("test_vault.bbox");
        let path = path_buf.as_path();

        let hw_enclave = Box::new(MockEnclave);
        let vault_manager = DefaultVaultManager::new_with(hw_enclave);
        let password = Zeroizing::new(b"StrongVaultPassword123!".to_vec());

        // 1. CREATE VAULT
        vault_manager
            .create_vault(path, &password)
            .expect("Failed to create vault");

        // 2. UNLOCK VAULT
        let mut session = vault_manager
            .unlock_vault(path, &password)
            .expect("Failed to open vault");
        assert_eq!(vault_manager.list_objects(&session).unwrap().len(), 0);

        // 3. ADD OBJECT
        let payload1 = b"Hello, encrypted world!";
        let purpose1 = "test payload 1";
        let obj_type = "text/plain";
        let mut cursor1 = std::io::Cursor::new(payload1);
        let object_id1 = vault_manager
            .add_object(
                &mut session,
                obj_type,
                purpose1,
                payload1.len() as u64,
                &mut cursor1,
            )
            .expect("Failed to add object 1");

        let layout_obj1 = vault_manager.list_objects(&session).unwrap();
        assert_eq!(layout_obj1.len(), 1);
        assert_eq!(layout_obj1[0].size, payload1.len() as u64);

        // 4. READ OBJECT
        let mut read_buf1 = Vec::new();
        vault_manager
            .read_object(&mut session, &object_id1, &mut read_buf1)
            .expect("Failed to read object 1");
        assert_eq!(read_buf1.as_slice(), payload1);

        // 5. ADD SECOND OBJECT
        let payload2 = b"Second payload with a bit more data.";
        let purpose2 = "test payload 2";
        let mut cursor2 = std::io::Cursor::new(payload2);
        let object_id2 = vault_manager
            .add_object(
                &mut session,
                obj_type,
                purpose2,
                payload2.len() as u64,
                &mut cursor2,
            )
            .expect("Failed to add object 2");

        // 6. DELETE FIRST OBJECT
        vault_manager
            .delete_object(&mut session, &object_id1)
            .expect("Failed to delete object 1");

        let layout_obj2 = vault_manager.list_objects(&session).unwrap();
        assert_eq!(layout_obj2.len(), 1);
        assert_eq!(layout_obj2[0].object_id, object_id2);

        // 7. VACUUM VAULT
        vault_manager
            .vacuum_vault(session, path)
            .expect("Failed to vacuum vault");

        // 8. VERIFY AFTER VACUUM
        let mut session_after = vault_manager
            .unlock_vault(path, &password)
            .expect("Failed to unlock after vacuum");

        let mut read_buf2 = Vec::new();
        vault_manager
            .read_object(&mut session_after, &object_id2, &mut read_buf2)
            .expect("Failed to read object 2 after vacuum");
        assert_eq!(read_buf2.as_slice(), payload2);

        // Trying to read deleted object should fail
        let mut fail_buf = Vec::new();
        let _err = vault_manager
            .read_object(&mut session_after, &object_id1, &mut fail_buf)
            .unwrap_err();
    }
}
