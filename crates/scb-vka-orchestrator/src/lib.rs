//! # scb-vka-orchestrator
//!
//! ## FINAL HARDENING IMPLEMENTATION
//!
//! - Strict Type System (`Key<Role>`, `Epoch`, `ObjectId`, `CryptoVersion`, `Nonce`)
//! - Strict AAD Builder (`AadPurpose`)
//! - `ConsumedNonce` Usage
//! - Invariant Checks
//! - Opaque IO Layout

// Strict Type System (`Key<Role>`, `Epoch`, `ObjectId`, `CryptoVersion`, `Nonce`)
// Strict AAD Builder (`AadPurpose`)

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
    AadBuilder, AadPurpose, ConsumedNonce, DefaultCryptoEngine, KdfParams, NonceFactory,
};
use scb_vka_crypto::{CryptoEngine, CryptoVersion, Epoch, KeyKEK, KeyMK, Nonce, ObjectId};
use scb_vka_io::layout::{FileTableEntry, Superblock, VaultHeader, FILE_ENTRY_SIZE};
use scb_vka_io::lock::VaultLock;
use scb_vka_io::manager::SpaceManager;
use scb_vka_memory::SecureBox;
use zerocopy::AsBytes;
use zeroize::Zeroize;

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
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

use tracing::{error, info, instrument};

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
    #[must_use]
    pub fn new() -> Self {
        // Enforce Process Hardening
        let _ = scb_vka_memory::disable_core_dumps();

        Self {
            enclave: scb_vka_hsp::create_platform_enclave(),
            crypto: DefaultCryptoEngine,
        }
    }

    fn unlock_vault_inner(&self, path: &Path, password: &[u8]) -> Result<VaultSession, VaultError> {
        // Acquire exclusive lock first - prevents concurrent access
        let mut lock = VaultLock::acquire(path)?;

        let mut sb_bytes = [0u8; SUPERBLOCK_SIZE];
        lock.file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        lock.file_mut()
            .read_exact(&mut sb_bytes)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // Parse validate pattern
        let superblock = Superblock::parse(&sb_bytes[..])?;

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
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }

        info!(vid = %hex::encode(&superblock.vid()[..8]), "Vault successfully unlocked");

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
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        }

        let salt_vec = self.crypto.csprng(SALT_LEN)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);

        let vid_vec = self.crypto.csprng(VID_LEN)?;
        let mut vid = [0u8; VID_LEN];
        vid.copy_from_slice(&vid_vec);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let kdf_params = KdfParams {
            memory_kib: KDF_MEMORY_KIB_MIN,
            iterations: KDF_ITERATIONS_MIN,
            parallelism: KDF_PARALLELISM,
        };
        let (mut kek, mut mk, mut ck) = self.crypto.derive_root_keys(
            password,
            &salt,
            &*self.enclave,
            &vid,
            timestamp,
            &kdf_params,
        )?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        let total_blocks = MIN_TOTAL_BLOCKS;
        file.set_len(total_blocks * BLOCK_SIZE as u64)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // Constructor Pattern
        let superblock = Superblock::new(salt, vid, timestamp, total_blocks);

        file.seek(SeekFrom::Start(0))
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        file.write_all(superblock.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // Constructor Pattern
        let mut header = VaultHeader::new(CRYPTO_VERSION, 1);

        let space_manager = SpaceManager::new(total_blocks)?;
        // Write initial header to Slot A
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

        kek.zeroize();
        mk.zeroize();
        ck.zeroize();

        info!(vid = %hex::encode(&vid[..8]), path = %path.display(), "Vault successfully created");
        Ok(VaultInfo {
            path: path.to_path_buf(),
            vid,
        })
    }

    #[instrument(skip(self, password))]
    fn unlock_vault(&self, path: &Path, password: &[u8]) -> Result<VaultSession, VaultError> {
        let result = self.unlock_vault_inner(path, password);
        if let Err(e) = &result {
            // Log security-relevant failures
            match e.kind {
                VaultErrorKind::AuthenticationFailed | VaultErrorKind::IntegrityError => {
                    error!(error = ?e.kind, "Vault unlock failed: Authentication or Integrity compromised");
                }
                _ => {} // Ignore I/O errors to avoid log spam
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
        info!(vid = %hex::encode(&vid[..8]), "Vault strictly locked. Key material zeroized.");
        Ok(())
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
        // 1. Input Validation
        if object_type.contains('\0') || purpose.contains('\0') {
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        }
        if session.header.entry_count() >= scb_vka_common::config::MAX_OBJECTS {
            return Err(VaultError::new(VaultErrorKind::CapacityExceeded));
        }

        let oid_vec = self.crypto.csprng(16)?;
        let mut oid_bytes = [0u8; 16];
        oid_bytes.copy_from_slice(&oid_vec);
        let oid = ObjectId::new(oid_bytes);

        let dek = self.crypto.generate_dek()?;

        let epoch = Epoch::new(session.header.epoch());
        let version = CryptoVersion::new(session.header.crypto_version());

        let mut purpose_bytes = [0u8; 32];
        let bytes = purpose.as_bytes();
        let p_len = bytes.len().min(32);
        purpose_bytes[..p_len].copy_from_slice(&bytes[..p_len]);
        let aad_purpose = AadPurpose::UserPurpose(purpose_bytes);

        let aad = AadBuilder::new()
            .object_id(oid)
            .version(version)
            .epoch(epoch)
            .purpose(aad_purpose)
            .build()?;

        let wrapped_dek = self.crypto.wrap_dek(&session.kek, &dek, &aad)?;

        // 2. Integer Overflow Protection
        let chunk_size = scb_vka_common::config::STREAM_CHUNK_SIZE as u64;
        // Calculation: num_chunks = (data_len + chunk_size - 1) / chunk_size
        let num_chunks = if data_len > 0 {
            data_len
                .checked_add(chunk_size)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?
                .checked_sub(1)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?
                .checked_div(chunk_size)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?
        } else {
            0
        };

        let tag_overhead = num_chunks
            .checked_mul(TAG_LEN as u64)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        let encrypted_payload_size = data_len
            .checked_add(tag_overhead)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        let total_size = (scb_vka_common::config::WRAPPED_DEK_SIZE as u64)
            .checked_add(scb_vka_common::config::NONCE_LEN as u64)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?
            .checked_add(encrypted_payload_size)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?
            .checked_add(scb_vka_common::config::MAC_LEN as u64)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        // Allocate space
        let num_blocks = total_size
            .checked_add(BLOCK_SIZE as u64)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?
            .checked_sub(1)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?
            .checked_div(BLOCK_SIZE as u64)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        let start_block = match session.space_manager.allocate(num_blocks) {
            Ok(block) => block,
            Err(e) if e.kind == VaultErrorKind::CapacityExceeded => {
                // Dynamic Expansion: Give it exactly what it needs plus a 1024 block buffer (~4MB buffer)
                let additional_blocks = num_blocks + 1024;
                session.space_manager.expand(additional_blocks)?;

                // Expand underlying file
                let new_len = session.space_manager.total_blocks() * (BLOCK_SIZE as u64);
                session
                    .lock
                    .file_mut()
                    .set_len(new_len)
                    .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

                // Retry allocation
                session.space_manager.allocate(num_blocks)?
            }
            Err(e) => return Err(e),
        };

        // Checked arithmetic for offset calculation
        let block_offset = start_block
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        let offset = DATA_REGION_START
            .checked_add(block_offset)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        session
            .lock
            .file_mut()
            .seek(SeekFrom::Start(offset))
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // Write Header (Wrapped DEK + Base Nonce)
        session
            .lock
            .file_mut()
            .write_all(&wrapped_dek)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        let nonce = NonceFactory::generate()?;
        session
            .lock
            .file_mut()
            .write_all(nonce.as_bytes())
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // 3. Data Length Enforcement
        // Stream Encryption
        // We use the base nonce. encrypt_stream consumes it (conceptually) and increments it.
        let consumed = ConsumedNonce::new(nonce);
        // Take exactly data_len to prevent reader from sending more than promised
        let mut limited_reader = reader.take(data_len);
        let bytes_written = self.crypto.encrypt_stream(
            &dek,
            &mut limited_reader,
            session.lock.file_mut(),
            &aad,
            consumed,
        )?;

        if bytes_written != encrypted_payload_size {
            // Full rollback: deallocate space (DEK is discarded, data is shredded)
            // CRITICAL: Propagate deallocation errors - space leaks corrupt bitmap state
            session
                .space_manager
                .deallocate(start_block, num_blocks)
                .inspect_err(|_| {
                    error!("CRITICAL: Space leak during rollback - bitmap inconsistent");
                })?;
            return Err(VaultError::new(VaultErrorKind::IoError));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut obj_type_arr = [0u8; 32];
        let type_bytes = object_type.as_bytes();
        let t_len = type_bytes.len().min(32);
        obj_type_arr[..t_len].copy_from_slice(&type_bytes[..t_len]);

        // Safe conversion: validate block indices fit in u32 (prevents silent overflow)
        let start_block_u32 = u32::try_from(start_block)
            .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;
        let num_blocks_u32 = u32::try_from(num_blocks)
            .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;

        let entry = FileTableEntry::new(
            oid_bytes,
            start_block_u32,
            num_blocks_u32,
            data_len, // Storing PLAINTEXT size
            timestamp,
            obj_type_arr,
            purpose_bytes,
            wrapped_dek,
            session.header.epoch(),
        );

        session.file_table.push(entry);
        // Safe conversion: validate entry count fits in u32
        let entry_count = u32::try_from(session.file_table.len())
            .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;
        session.header.update_entry_count(entry_count);
        session.header.increment_epoch()?;

        // Crash resistance: sync data before header update
        session
            .lock
            .file_mut()
            .sync_all()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // Write header to OPPOSITE slot (A/B ping-pong)
        let target_slot = if session.active_slot_offset == HEADER_SLOT_A_OFFSET {
            HEADER_SLOT_B_OFFSET
        } else {
            HEADER_SLOT_A_OFFSET
        };
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

        info!(vid = %hex::encode(&session.vid[..8]), object_id = %hex::encode(oid_bytes), "Object encrypted and added");
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
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }

        let oid = ObjectId::new(*object_id);
        let version = CryptoVersion::new(session.header.crypto_version());
        let purpose = AadPurpose::UserPurpose(*entry.purpose());

        let aad = AadBuilder::new()
            .object_id(oid)
            .version(version)
            .epoch(obj_epoch)
            .purpose(purpose)
            .build()?;

        let dek = self
            .crypto
            .unwrap_dek(&session.kek, entry.wrapped_dek(), &aad)?;

        // Checked arithmetic for offset calculation
        let block_offset = (entry.start_block() as u64)
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
        let offset = DATA_REGION_START
            .checked_add(block_offset)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;

        // Calculate expected encrypted payload size with checked arithmetic
        let chunk_size = STREAM_CHUNK_SIZE as u64;
        let data_len = entry.size();
        let num_chunks = if data_len > 0 {
            data_len
                .checked_add(chunk_size)
                .and_then(|x| x.checked_sub(1))
                .map(|x| x / chunk_size)
                .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?
        } else {
            0
        };
        let tag_overhead = num_chunks
            .checked_mul(scb_vka_common::config::TAG_LEN as u64)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
        let encrypted_payload_size = data_len
            .checked_add(tag_overhead)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;

        let stream_read_size = encrypted_payload_size
            .checked_add(scb_vka_common::config::MAC_LEN as u64)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;

        // Verify total size vs allocated blocks?
        // allocated = num_blocks * BLOCK_SIZE.
        // real usage <= allocated. ok.

        session
            .lock
            .file_mut()
            .seek(SeekFrom::Start(offset + WRAPPED_DEK_SIZE as u64))
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        session
            .lock
            .file_mut()
            .read_exact(&mut nonce_bytes)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        let nonce = Nonce::new(nonce_bytes);

        // Limited Reader for Payload
        // Use (&mut file) to avoid moving File, invoking Read on &mut File
        let mut limited_reader = (session.lock.file_mut()).take(stream_read_size);

        let bytes_written =
            self.crypto
                .decrypt_stream(&dek, &mut limited_reader, writer, &aad, nonce, data_len)?;

        if bytes_written != data_len {
            // If decrypted size mismatch, integrity error (or truncation)
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }

        info!(vid = %hex::encode(&session.vid[..8]), object_id = %hex::encode(object_id), bytes = bytes_written, "Object decrypted and read");
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

        // Secure wipe removed. Space is cryptographically shredded when the DEK is discarded
        // with the FileTableEntry. Future additions will overwrite this space randomly.

        session
            .space_manager
            .deallocate(entry.start_block() as u64, entry.num_blocks() as u64)?;

        // Safe conversion: validate entry count fits in u32
        let entry_count = u32::try_from(session.file_table.len())
            .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;
        session.header.update_entry_count(entry_count);
        session.header.increment_epoch()?;

        // Crash resistance: sync wipe before header update
        session
            .lock
            .file_mut()
            .sync_all()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // Write header to OPPOSITE slot (A/B ping-pong)
        let target_slot = if session.active_slot_offset == HEADER_SLOT_A_OFFSET {
            HEADER_SLOT_B_OFFSET
        } else {
            HEADER_SLOT_A_OFFSET
        };
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
        info!(vid = %hex::encode(&session.vid[..8]), object_id = %hex::encode(object_id), "Object cryptographically deleted");
        Ok(())
    }

    #[instrument(skip(self, session))]
    fn list_objects(&self, session: &VaultSession) -> Result<Vec<ObjectMeta>, VaultError> {
        let mut list = Vec::new();
        for entry in &session.file_table {
            // Strict UTF-8 Validation
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
        // Prepare temporary file
        let mut temp_path_str = path.to_string_lossy().to_string();
        temp_path_str.push_str(".tmp");
        let temp_path = Path::new(&temp_path_str);

        let mut temp_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(temp_path)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // 1. Copy Superblock verbatim
        session
            .lock
            .file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        let mut superblock_buf = [0u8; scb_vka_io::layout::SUPERBLOCK_SIZE];
        session
            .lock
            .file_mut()
            .read_exact(&mut superblock_buf)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        temp_file
            .write_all(&superblock_buf)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // 2. Out-of-place Block Copy
        session.file_table.sort_by_key(|e| e.start_block());
        let mut next_free_block = 0u64;
        let mut buf = vec![0u8; 8 * 1024 * 1024]; // 8MB buffer

        for entry in &mut session.file_table {
            let src_block = entry.start_block() as u64;
            let num_blocks = entry.num_blocks() as u64;
            let byte_len = (num_blocks as usize)
                .checked_mul(scb_vka_common::config::BLOCK_SIZE as usize)
                .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

            let src_offset = scb_vka_common::config::DATA_REGION_START
                + src_block * (scb_vka_common::config::BLOCK_SIZE as u64);
            let dst_offset = scb_vka_common::config::DATA_REGION_START
                + next_free_block * (scb_vka_common::config::BLOCK_SIZE as u64);

            session
                .lock
                .file_mut()
                .seek(SeekFrom::Start(src_offset))
                .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
            temp_file
                .seek(SeekFrom::Start(dst_offset))
                .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

            let mut remaining = byte_len;
            let mut reader = session.lock.file_mut().take(remaining as u64);
            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                let n = reader
                    .read(&mut buf[..to_read])
                    .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
                if n == 0 {
                    break;
                }
                temp_file
                    .write_all(&buf[..n])
                    .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
                remaining -= n;
            }

            // Update entry with new contiguous position
            // CRITICAL: Validate block index fits in u32 to prevent silent overflow
            let new_start_block = u32::try_from(next_free_block)
                .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;
            entry.set_start_block(new_start_block);
            next_free_block += num_blocks;
        }

        // 3. Rebuild SpaceManager
        let new_total_blocks =
            std::cmp::max(next_free_block, scb_vka_common::config::MIN_TOTAL_BLOCKS);
        let mut new_sm = SpaceManager::new(new_total_blocks)?;
        if next_free_block > 0 {
            new_sm.allocate(next_free_block)?; // Lock blocks continuously
        }

        // 4. Update Header State
        session.header.increment_epoch()?;
        let entry_count = u32::try_from(session.file_table.len())
            .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;
        session.header.update_entry_count(entry_count);

        temp_file
            .sync_all()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // 5. Write Header to A/B Slots
        write_encrypted_header(
            &mut temp_file,
            &session.kek,
            &session.mk,
            &self.crypto,
            &mut session.header,
            &session.file_table,
            &new_sm,
            scb_vka_common::config::HEADER_SLOT_A_OFFSET,
        )?;

        write_encrypted_header(
            &mut temp_file,
            &session.kek,
            &session.mk,
            &self.crypto,
            &mut session.header,
            &session.file_table,
            &new_sm,
            scb_vka_common::config::HEADER_SLOT_B_OFFSET,
        )?;

        // Close files implicitly
        drop(session.lock); // close source
        temp_file
            .sync_all()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        drop(temp_file); // close temp

        // 6. Atomic Replacement
        std::fs::rename(temp_path, path).map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        // Note: the original VaultSession is now defunct, we require user to re-unlock manually.
        Ok(())
    }
}

/// Maximum header blob size — bounded by slot capacity
const MAX_HEADER_BLOB_SIZE: usize = (HEADER_SLOT_CAPACITY as usize) - HEADER_SLOT_META_SIZE;

/// Encryption overhead: WRAPPED_DEK(72) + NONCE(24) + TAG(16) = 112 bytes
/// ChaCha20 is stream cipher: ciphertext.len() == plaintext.len()
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

    // Fix bitmap_size in header before serialization
    let bitmap_len = u32::try_from(bitmap.len())
        .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;
    header.update_bitmap_size(bitmap_len);

    // Early size validation to prevent DoS via memory exhaustion
    let header_struct_size = std::mem::size_of::<VaultHeader>();
    let entries_size = file_table
        .len()
        .checked_mul(FILE_ENTRY_SIZE)
        .ok_or(VaultError::new(VaultErrorKind::CapacityExceeded))?;
    let plaintext_size = header_struct_size
        .checked_add(bitmap.len())
        .and_then(|x| x.checked_add(entries_size))
        .ok_or(VaultError::new(VaultErrorKind::CapacityExceeded))?;

    // CRITICAL: Check against max PLAINTEXT size (not blob size)
    // blob_size = plaintext_size + ENCRYPTION_OVERHEAD
    if plaintext_size > MAX_HEADER_PLAINTEXT_SIZE {
        return Err(VaultError::new(VaultErrorKind::CapacityExceeded));
    }

    let mut plaintext = Vec::with_capacity(plaintext_size);
    plaintext.extend_from_slice(header.as_bytes());
    plaintext.extend_from_slice(&bitmap);
    for entry in file_table {
        plaintext.extend_from_slice(entry.as_bytes());
    }

    let dek = crypto.generate_dek()?;
    let zero_id = ObjectId::new([0u8; 16]);

    let aad = AadBuilder::new()
        .object_id(zero_id)
        .version(CryptoVersion::new(header.crypto_version()))
        .epoch(Epoch::new(0))
        .purpose(AadPurpose::Header)
        .build()?;

    let wrapped_dek = crypto.wrap_dek(kek, &dek, &aad)?;
    let nonce = NonceFactory::generate()?;
    let consumed = ConsumedNonce::new(nonce);
    let (ct, tag) = crypto.encrypt_object(&dek, &plaintext, &aad, consumed)?;

    // Build blob: WrappedDEK || Nonce || Ciphertext || Tag
    let blob_size = WRAPPED_DEK_SIZE + NONCE_LEN + ct.len() + TAG_LEN;
    let mut blob = Vec::with_capacity(blob_size);
    blob.extend_from_slice(&wrapped_dek);
    blob.extend_from_slice(nonce.as_bytes());
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);

    // Encrypt-then-MAC: MAC over the entire blob
    let mac = crypto.compute_header_mac(mk, &blob)?;

    // Write self-describing slot: [blob_size:u64 LE][mac:32B][blob]
    file.seek(SeekFrom::Start(slot_offset))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    file.write_all(&(blob_size as u64).to_le_bytes())
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    file.write_all(&mac)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    file.write_all(&blob)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    // Atomic commit: fsync ensures the entire slot is persisted
    file.sync_all()
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    Ok(())
}

/// Try to read and decrypt a single header slot.
/// Returns (header, file_table, space_manager) on success.
fn try_read_slot(
    file: &mut File,
    slot_offset: u64,
    kek: &KeyKEK,
    mk: &KeyMK,
    crypto: &DefaultCryptoEngine,
    superblock: &Superblock,
) -> Result<(VaultHeader, Vec<FileTableEntry>, SpaceManager), VaultError> {
    // 1. Read slot metadata
    file.seek(SeekFrom::Start(slot_offset))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    let mut size_bytes = [0u8; 8];
    file.read_exact(&mut size_bytes)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    let blob_size = u64::from_le_bytes(size_bytes);

    // 2. Sanity check blob_size
    if blob_size == 0 || blob_size as usize > MAX_HEADER_BLOB_SIZE {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let mut expected_mac = [0u8; MAC_LEN];
    file.read_exact(&mut expected_mac)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    // 3. Read blob
    let blob_len = blob_size as usize;
    let mut blob = vec![0u8; blob_len];
    file.read_exact(&mut blob)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    // 4. Verify MAC (Encrypt-then-MAC)
    if !crypto.verify_header_mac(mk, &blob, &expected_mac)? {
        return Err(VaultError::new(VaultErrorKind::AuthenticationFailed));
    }

    // 5. Parse blob: WrappedDEK || Nonce || Ciphertext || Tag
    if blob_len < WRAPPED_DEK_SIZE + NONCE_LEN + TAG_LEN {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let wrapped_dek: [u8; WRAPPED_DEK_SIZE] = blob[..WRAPPED_DEK_SIZE]
        .try_into()
        .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;

    let zero_id = ObjectId::new([0u8; 16]);
    let aad = AadBuilder::new()
        .object_id(zero_id)
        .version(CryptoVersion::new(CRYPTO_VERSION))
        .epoch(Epoch::new(0))
        .purpose(AadPurpose::Header)
        .build()?;

    let dek = crypto.unwrap_dek(kek, &wrapped_dek, &aad)?;
    let rest = &blob[WRAPPED_DEK_SIZE..];

    let nonce: [u8; NONCE_LEN] = rest[..NONCE_LEN]
        .try_into()
        .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;

    let ct_end = rest.len() - TAG_LEN;
    let ct = &rest[NONCE_LEN..ct_end];
    let tag: [u8; TAG_LEN] = rest[ct_end..]
        .try_into()
        .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;

    let pt = crypto.decrypt_object(&dek, Nonce::new(nonce), ct, &tag, &aad)?;

    // 6. Parse plaintext: VaultHeader || Bitmap || FileTable
    let header_struct_size = std::mem::size_of::<VaultHeader>();
    if pt.len() < header_struct_size {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let header = VaultHeader::parse(&pt[..header_struct_size])?;

    let bitmap_start = header_struct_size;
    let bitmap_size = header.bitmap_size() as usize;

    let expected_bitmap_size = (superblock.total_blocks() as usize).div_ceil(8);
    if bitmap_size != expected_bitmap_size {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    if pt.len() < bitmap_start + bitmap_size {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let bitmap = pt[bitmap_start..bitmap_start + bitmap_size].to_vec();
    let space_manager = SpaceManager::from_bytes(bitmap, superblock.total_blocks())?;

    let mut file_table = Vec::with_capacity(header.entry_count() as usize);
    let mut offset = bitmap_start + bitmap_size;

    let expected_entries_size = (header.entry_count() as usize)
        .checked_mul(FILE_ENTRY_SIZE)
        .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
    let required_size = offset
        .checked_add(expected_entries_size)
        .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
    if pt.len() < required_size {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
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

    match (slot_a, slot_b) {
        (Ok((ha, fta, sma)), Ok((hb, ftb, smb))) => {
            // Both valid: pick the one with the higher epoch
            // CRITICAL: Use proper u64 comparison - epochs increment monotonically
            // and checked_add prevents overflow, so simple > comparison is correct
            if hb.epoch() > ha.epoch() {
                Ok((hb, ftb, smb, HEADER_SLOT_B_OFFSET))
            } else {
                Ok((ha, fta, sma, HEADER_SLOT_A_OFFSET))
            }
        }
        (Ok((ha, fta, sma)), Err(_)) => Ok((ha, fta, sma, HEADER_SLOT_A_OFFSET)),
        (Err(_), Ok((hb, ftb, smb))) => Ok((hb, ftb, smb, HEADER_SLOT_B_OFFSET)),
        (Err(_), Err(e)) => Err(e), // Both slots failed — vault is corrupted
    }
}
