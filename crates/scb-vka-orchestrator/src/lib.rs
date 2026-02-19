//! # scb-vka-orchestrator
//!
//! ## FINAL HARDENING IMPLEMENTATION
//!
//! - Strict Type System (`Key<Role>`, `Epoch`, `ObjectId`, `CryptoVersion`, `Nonce`)
//! - Strict AAD Builder (`AadPurpose`)
//! - `ConsumedNonce` Usage
//! - Invariant Checks
//! - Opaque IO Layout

#[cfg(not(feature = "mock-hsp"))]
compile_error!("CRITICAL: Production builds MUST NOT use MockHSP. Provide a real HSP implementation or enable 'mock-hsp' for dev.");

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use scb_vka_common::config::{
    BLOCK_SIZE, CRYPTO_VERSION, DATA_REGION_START, KDF_ITERATIONS_MIN, KDF_MEMORY_KIB_MIN,
    KDF_PARALLELISM, MIN_TOTAL_BLOCKS, NONCE_LEN, SALT_LEN, STREAM_CHUNK_SIZE, SUPERBLOCK_SIZE,
    TAG_LEN, VID_LEN, WRAPPED_DEK_SIZE,
};
pub use scb_vka_common::error::{VaultError, VaultErrorKind};
pub use scb_vka_common::log::{LogLevel, NullLogger, VaultEvent, VaultLogger};
use scb_vka_crypto::engine::{
    AadBuilder, AadPurpose, ConsumedNonce, DefaultCryptoEngine, KdfParams, NonceFactory,
};
use scb_vka_crypto::{CryptoEngine, CryptoVersion, Epoch, KeyKEK, KeyMK, Nonce, ObjectId};
use scb_vka_io::hsp::{HardwareSecurityProvider, MockHSP};
use scb_vka_io::layout::{
    FileTableEntry, Superblock, VaultHeader, FILE_ENTRY_SIZE, VAULT_HEADER_OFFSET,
};
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
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

pub struct DefaultVaultManager<L> {
    hsp: MockHSP,
    logger: L,
    crypto: DefaultCryptoEngine,
}

impl<L> DefaultVaultManager<L>
where
    L: VaultLogger,
{
    pub fn new(logger: L) -> Self {
        // Enforce Process Hardening
        let _ = scb_vka_memory::disable_core_dumps();

        Self {
            hsp: MockHSP::new(),
            logger,
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
        let machine_secret = self.hsp.get_machine_secret()?;

        let (kek, mk, _ck) = self.crypto.derive_root_keys(
            password,
            superblock.salt(),
            &machine_secret,
            superblock.vid(),
            superblock.created_timestamp(),
            &kdf_params,
        )?;

        let (header, file_table, space_manager) =
            read_encrypted_header(lock.file_mut(), &kek, &mk, &self.crypto, &superblock)?;

        // STRICT VALIDATION
        if header.crypto_version() != CRYPTO_VERSION {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }

        self.logger.log(&VaultEvent::VaultUnlocked {
            vid: *superblock.vid(),
        });

        Ok(VaultSession {
            vid: *superblock.vid(),
            kek: SecureBox::new(kek)?,
            mk: SecureBox::new(mk)?,
            header,
            file_table,
            space_manager,
            lock,
        })
    }
}

impl<L> VaultManager for DefaultVaultManager<L>
where
    L: VaultLogger,
{
    fn create_vault(&self, path: &Path, password: &[u8]) -> Result<VaultInfo, VaultError> {
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
        let machine_secret = self.hsp.get_machine_secret()?;

        let (mut kek, mut mk, mut ck) = self.crypto.derive_root_keys(
            password,
            &salt,
            &machine_secret,
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
        let header = VaultHeader::new(CRYPTO_VERSION, 1);

        let space_manager = SpaceManager::new(total_blocks)?;
        write_encrypted_header(
            &mut file,
            &kek,
            &mk,
            &self.crypto,
            &header,
            &[],
            &space_manager,
        )?;

        file.sync_all()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        kek.zeroize();
        mk.zeroize();
        ck.zeroize();

        self.logger.log(&VaultEvent::VaultCreated { vid });
        Ok(VaultInfo {
            path: path.to_path_buf(),
            vid,
        })
    }

    fn unlock_vault(&self, path: &Path, password: &[u8]) -> Result<VaultSession, VaultError> {
        let result = self.unlock_vault_inner(path, password);
        if let Err(e) = &result {
            // Log security-relevant failures
            match e.kind {
                VaultErrorKind::AuthenticationFailed | VaultErrorKind::IntegrityError => {
                    self.logger.log(&VaultEvent::Error {
                        message: format!(
                            "Unlock failed: Authentication or Integrity error ({:?})",
                            e.kind
                        ),
                    });
                }
                _ => {} // Ignore I/O errors to avoid log spam, or log as debug?
            }
        }
        result
    }

    fn lock_vault(&self, mut session: VaultSession) -> Result<(), VaultError> {
        let vid = session.vid;
        for entry in &mut session.file_table {
            entry.zeroize_entry();
        }
        session.file_table.clear();
        session.header.zeroize();
        self.logger.log(&VaultEvent::VaultLocked { vid });
        Ok(())
    }

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

        let start_block = session.space_manager.allocate(num_blocks)?;

        // Checked arithmetic for offset calculation
        let block_offset = (start_block as u64)
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
            // Full rollback: securely wipe partially written data, then deallocate
            let wipe_len = (num_blocks as usize)
                .checked_mul(BLOCK_SIZE as usize)
                .unwrap_or(0);
            if wipe_len > 0 {
                // Best-effort secure wipe - ignore errors during rollback
                let _ = scb_vka_memory::secure_wipe(session.lock.file_mut(), offset, wipe_len);
            }
            if session
                .space_manager
                .deallocate(start_block, num_blocks)
                .is_err()
            {
                self.logger.log(&VaultEvent::Error {
                    message: "Space leak during rollback: failed to deallocate blocks".to_string(),
                });
            }
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

        let entry = FileTableEntry::new(
            oid_bytes,
            start_block as u32,
            num_blocks as u32,
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

        write_encrypted_header(
            session.lock.file_mut(),
            &session.kek,
            &session.mk,
            &self.crypto,
            &session.header,
            &session.file_table,
            &session.space_manager,
        )?;
        session
            .lock
            .file_mut()
            .sync_all()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        self.logger.log(&VaultEvent::ObjectAdded {
            vid: session.vid,
            object_id: oid_bytes,
        });
        Ok(oid_bytes)
    }

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

        self.logger.log(&VaultEvent::ObjectRead {
            vid: session.vid,
            object_id: *object_id,
        });
        Ok(bytes_written)
    }

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

        // Checked arithmetic for offset calculation
        let block_offset = (entry.start_block() as u64)
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
        let offset = DATA_REGION_START
            .checked_add(block_offset)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
        let len = (entry.num_blocks() as usize)
            .checked_mul(BLOCK_SIZE as usize)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;

        // Secure wipe: overwrite with CSPRNG random data before deallocation
        scb_vka_memory::secure_wipe(session.lock.file_mut(), offset, len)?;

        session
            .space_manager
            .deallocate(entry.start_block() as u64, entry.num_blocks() as u64)?;

        // Safe conversion: validate entry count fits in u32
        let entry_count = u32::try_from(session.file_table.len())
            .map_err(|_| VaultError::new(VaultErrorKind::CapacityExceeded))?;
        session.header.update_entry_count(entry_count);
        session.header.increment_epoch()?;

        write_encrypted_header(
            session.lock.file_mut(),
            &session.kek,
            &session.mk,
            &self.crypto,
            &session.header,
            &session.file_table,
            &session.space_manager,
        )?;
        session
            .lock
            .file_mut()
            .sync_all()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        self.logger.log(&VaultEvent::ObjectDeleted {
            vid: session.vid,
            object_id: *object_id,
        });
        Ok(())
    }

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
}

/// Maximum header size (16 MB) to prevent DoS via memory exhaustion
const MAX_HEADER_SIZE: usize = 16 * 1024 * 1024;

fn write_encrypted_header(
    file: &mut File,
    kek: &KeyKEK,
    mk: &KeyMK,
    crypto: &DefaultCryptoEngine,
    header: &VaultHeader,
    file_table: &[FileTableEntry],
    space_manager: &SpaceManager,
) -> Result<(), VaultError> {
    let bitmap = space_manager.export_bitmap();

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

    if plaintext_size > MAX_HEADER_SIZE {
        return Err(VaultError::new(VaultErrorKind::CapacityExceeded));
    }

    let mut plaintext = Vec::with_capacity(plaintext_size);
    plaintext.extend_from_slice(header.as_bytes());
    plaintext.extend_from_slice(&bitmap);
    for entry in file_table {
        plaintext.extend_from_slice(entry.as_bytes());
    }

    let dek = crypto.generate_dek()?;
    let zero_id_bytes = [0u8; 16];
    let zero_id = ObjectId::new(zero_id_bytes);

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

    // Calculate Header Size (already validated plaintext_size above)
    let header_size = WRAPPED_DEK_SIZE + NONCE_LEN + ct.len() + TAG_LEN;

    file.seek(SeekFrom::Start(VAULT_HEADER_OFFSET))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    // Write in order
    file.write_all(&wrapped_dek)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    file.write_all(nonce.as_bytes())
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    file.write_all(&ct)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    file.write_all(&tag)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    // Encrypt-then-MAC: MAC over the entire encrypted blob on disk
    // Blob = WrappedDEK || Nonce || Ciphertext || Tag
    let mut mac_input = Vec::with_capacity(header_size);
    mac_input.extend_from_slice(&wrapped_dek);
    mac_input.extend_from_slice(nonce.as_bytes());
    mac_input.extend_from_slice(&ct);
    mac_input.extend_from_slice(&tag);

    let mac = crypto.compute_header_mac(mk, &mac_input)?;

    file.seek(SeekFrom::Start(0))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    let mut sb_bytes = [0u8; SUPERBLOCK_SIZE];
    file.read_exact(&mut sb_bytes)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    let mut superblock = Superblock::parse(&sb_bytes[..])?;

    // Update using setter (Authenticated)
    superblock.update_header_info(header_size as u64, *nonce.as_bytes(), mac);

    file.seek(SeekFrom::Start(0))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    file.write_all(superblock.as_bytes())
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    Ok(())
}

fn read_encrypted_header(
    file: &mut File,
    kek: &KeyKEK,
    mk: &KeyMK,
    crypto: &DefaultCryptoEngine,
    superblock: &Superblock,
) -> Result<(VaultHeader, Vec<FileTableEntry>, SpaceManager), VaultError> {
    if superblock.header_size() == 0 {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }
    // Size Sanity Check using the same constant as write
    if superblock.header_size() as usize > MAX_HEADER_SIZE {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    file.seek(SeekFrom::Start(superblock.header_offset()))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
    let mut encrypted = vec![0u8; superblock.header_size() as usize];
    file.read_exact(&mut encrypted)
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    if encrypted.len() < WRAPPED_DEK_SIZE + NONCE_LEN + TAG_LEN {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    // MAC Verification (Encrypt-then-MAC)
    // Verify over the whole read blob
    if !crypto.verify_header_mac(mk, &encrypted, superblock.header_mac())? {
        return Err(VaultError::new(VaultErrorKind::AuthenticationFailed));
    }

    let wrapped_dek: [u8; WRAPPED_DEK_SIZE] = encrypted[..WRAPPED_DEK_SIZE]
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
    let rest = &encrypted[WRAPPED_DEK_SIZE..];

    // Bounds check to prevent underflow: rest must contain at least nonce + tag
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let nonce: [u8; NONCE_LEN] = rest[..NONCE_LEN]
        .try_into()
        .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;

    // Safe: we've verified rest.len() >= NONCE_LEN + TAG_LEN
    let ct_end = rest.len() - TAG_LEN;
    let ct = &rest[NONCE_LEN..ct_end];
    let tag: [u8; TAG_LEN] = rest[ct_end..]
        .try_into()
        .map_err(|_| VaultError::new(VaultErrorKind::IntegrityError))?;

    let pt = crypto.decrypt_object(&dek, Nonce::new(nonce), ct, &tag, &aad)?;

    let header_size = std::mem::size_of::<VaultHeader>();
    if pt.len() < header_size {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let header = VaultHeader::parse(&pt[..header_size])?;

    let bitmap_start = header_size;
    let bitmap_size = header.bitmap_size() as usize;

    // Bitmap Size Validation
    // size must match total_blocks (1 bit per block -> total_blocks / 8 bytes)
    // SpaceManager handles the math, but we should sanity check vs superblock.
    let expected_bitmap_size = (superblock.total_blocks() as usize + 7) / 8;
    if bitmap_size != expected_bitmap_size {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    // Bounds Check
    if pt.len() < bitmap_start + bitmap_size {
        return Err(VaultError::new(VaultErrorKind::IntegrityError));
    }

    let bitmap = pt[bitmap_start..bitmap_start + bitmap_size].to_vec();
    let space_manager = SpaceManager::from_bytes(bitmap, superblock.total_blocks())?;

    let mut file_table = Vec::with_capacity(header.entry_count() as usize);
    let mut offset = bitmap_start + bitmap_size;

    // Bounds Check for Entries
    // Each entry is FILE_ENTRY_SIZE. Use checked arithmetic to prevent overflow.
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
