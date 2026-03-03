//! # scb-vka-io/layout
//!
//! ## SECURITY CONTRACT
//!
//! 1.  **Opaque Types**: Struct fields are private. Direct modification is impossible.
//! 2.  **Parse-Validate**: Construction from bytes ALWAYS validates.
//! 3.  **Construct**: Creation of new instances requires valid inputs.
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! Disk layout struct'ları. Zerocopy ile binary serialize/deserialize,
//! fakat dış dünyaya kapalı (encapsulated).

pub use scb_vka_common::config::{
    BLOCK_SIZE, DATA_REGION_START, FILE_ENTRY_SIZE, HEADER_SLOT_A_OFFSET, HEADER_SLOT_B_OFFSET,
    HEADER_SLOT_CAPACITY, HEADER_SLOT_META_SIZE, KEY_LEN, MAGIC_FILE_TABLE, MAGIC_SUPERBLOCK,
    NONCE_LEN, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE, TAG_LEN,
};

use scb_vka_common::error::{VaultError, VaultErrorKind};
use static_assertions::const_assert;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use zeroize::Zeroize;

/// Wrapped DEK size: nonce(24) + encrypted_key(32) + tag(16) = 72 bytes
pub const WRAPPED_DEK_SIZE: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

// =============================================================================
// SUPERBLOCK
// =============================================================================

/// Vault Superblock (Opaque)
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, Zeroize)]
pub struct Superblock {
    magic: [u8; 8],
    pub(crate) salt: [u8; 32], // Exposed to crate for KDF
    pub(crate) version: u32,
    pub(crate) crypto_version: u32,
    pub(crate) total_blocks: u64,
    pub(crate) block_size: u32,
    _pad2: u32,
    pub(crate) created_timestamp: u64,
    pub(crate) hw_key_handle: [u8; 64],
    pub(crate) vid: [u8; 16],
    pub(crate) enc_hw_secret: [u8; 128],
    #[zeroize(skip)]
    reserved: [u8; 7912],
}
const_assert!(std::mem::size_of::<Superblock>() == SUPERBLOCK_SIZE);

impl Superblock {
    /// Create new Superblock (Constructor)
    #[allow(clippy::too_many_arguments)]
    pub fn new(salt: [u8; 32], vid: [u8; 16], timestamp: u64, total_blocks: u64) -> Self {
        Self {
            magic: MAGIC_SUPERBLOCK,
            salt,
            version: scb_vka_common::config::VERSION,
            crypto_version: scb_vka_common::config::CRYPTO_VERSION,
            total_blocks,
            block_size: BLOCK_SIZE,
            _pad2: 0,
            created_timestamp: timestamp,
            hw_key_handle: [0u8; 64],
            vid,
            enc_hw_secret: [0u8; 128],
            reserved: [0u8; 7912],
        }
    }

    /// Parse and Validate from bytes
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        let sb =
            Superblock::read_from(bytes).ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
        sb.validate()?;
        Ok(sb)
    }

    /// Validate fields
    pub fn validate(&self) -> Result<(), VaultError> {
        if self.magic != MAGIC_SUPERBLOCK {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        if self.block_size != BLOCK_SIZE {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        if self.total_blocks < scb_vka_common::config::MIN_TOTAL_BLOCKS {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        if self.total_blocks > scb_vka_common::config::MAX_TOTAL_BLOCKS {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        if self.version != scb_vka_common::config::VERSION {
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        }
        if self.crypto_version != scb_vka_common::config::CRYPTO_VERSION {
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        }
        Ok(())
    }

    // Getters for Orchestrator
    /// Get Salt
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }
    /// Get VID
    pub fn vid(&self) -> &[u8; 16] {
        &self.vid
    }
    /// Get Timestamp
    pub fn created_timestamp(&self) -> u64 {
        self.created_timestamp
    }
    /// Get Total Blocks
    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Get Crypto Version
    pub fn crypto_version(&self) -> u32 {
        self.crypto_version
    }
}

// =============================================================================
// VAULT HEADER
// =============================================================================

/// Encrypted Vault Header (Opaque)
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, Zeroize)]
pub struct VaultHeader {
    magic: [u8; 4],
    pub(crate) entry_count: u32,
    pub(crate) data_region_start: u64,
    pub(crate) bitmap_size: u32,
    _pad: u32,
    pub(crate) crypto_version: u32,
    _pad2: u32,
    pub(crate) epoch: u64,
    #[zeroize(skip)]
    reserved: [u8; 16],
}
const_assert!(std::mem::size_of::<VaultHeader>() == 56);

impl VaultHeader {
    /// Create new header
    pub fn new(crypto_version: u32, epoch: u64) -> Self {
        Self {
            magic: MAGIC_FILE_TABLE,
            entry_count: 0,
            data_region_start: DATA_REGION_START,
            bitmap_size: 0,
            _pad: 0,
            crypto_version,
            _pad2: 0,
            epoch,
            reserved: [0u8; 16],
        }
    }

    /// Parse and Validate
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        let h =
            VaultHeader::read_from(bytes).ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
        h.validate()?;
        Ok(h)
    }

    fn validate(&self) -> Result<(), VaultError> {
        if self.magic != MAGIC_FILE_TABLE {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        if self.entry_count > scb_vka_common::config::MAX_OBJECTS {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        Ok(())
    }

    /// Increment Epoch (Managed State)
    pub fn increment_epoch(&mut self) -> Result<(), VaultError> {
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or(VaultError::new(VaultErrorKind::OperationFailed))?;
        Ok(())
    }

    /// Update stats
    pub fn update_entry_count(&mut self, count: u32) {
        self.entry_count = count;
    }

    // Getters
    /// Get Crypto Version
    pub fn crypto_version(&self) -> u32 {
        self.crypto_version
    }
    /// Get Epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Get Entry Count
    pub fn entry_count(&self) -> u32 {
        self.entry_count
    }
    /// Get Bitmap Size
    pub fn bitmap_size(&self) -> u32 {
        self.bitmap_size
    }
    /// Set Bitmap Size (must be called before serialization)
    pub fn update_bitmap_size(&mut self, size: u32) {
        self.bitmap_size = size;
    }
}

// =============================================================================
// FILE TABLE ENTRY
// =============================================================================

/// Encrypted File Entry (Opaque)
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, Zeroize)]
pub struct FileTableEntry {
    pub(crate) object_id: [u8; 16],
    pub(crate) start_block: u32,
    pub(crate) num_blocks: u32,
    pub(crate) size: u64,
    pub(crate) flags: u32,
    _pad: u32,
    pub(crate) created: u64,
    pub(crate) modified: u64,
    pub(crate) object_type: [u8; 32],
    pub(crate) purpose: [u8; 32],
    pub(crate) wrapped_dek: [u8; WRAPPED_DEK_SIZE],
    pub(crate) epoch: u64,
    #[zeroize(skip)]
    reserved: [u8; 56],
}
const_assert!(std::mem::size_of::<FileTableEntry>() == FILE_ENTRY_SIZE);

impl FileTableEntry {
    /// Create new entry
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        object_id: [u8; 16],
        start_block: u32,
        num_blocks: u32,
        size: u64,
        created: u64,
        object_type: [u8; 32],
        purpose: [u8; 32],
        wrapped_dek: [u8; WRAPPED_DEK_SIZE],
        epoch: u64,
    ) -> Self {
        Self {
            object_id,
            start_block,
            num_blocks,
            size,
            flags: 1, // Active
            _pad: 0,
            created,
            modified: created,
            object_type,
            purpose,
            wrapped_dek,
            epoch,
            reserved: [0u8; 56],
        }
    }

    /// Parse and Validate
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        let entry = FileTableEntry::read_from(bytes)
            .ok_or(VaultError::new(VaultErrorKind::IntegrityError))?;
        entry.validate()?;
        Ok(entry)
    }

    /// Validate entry fields
    fn validate(&self) -> Result<(), VaultError> {
        // flags == 0 means deleted (should not appear in active file table)
        // flags == 1 means active
        if self.flags != 1 {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        Ok(())
    }

    // Getters
    /// Get Object ID
    pub fn object_id(&self) -> &[u8; 16] {
        &self.object_id
    }
    /// Get Purpose
    pub fn purpose(&self) -> &[u8; 32] {
        &self.purpose
    }
    /// Get Epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Get Wrapped DEK
    pub fn wrapped_dek(&self) -> &[u8; WRAPPED_DEK_SIZE] {
        &self.wrapped_dek
    }
    /// Get Start Block
    pub fn start_block(&self) -> u32 {
        self.start_block
    }
    /// Set Start Block (Used by Vacuum for compaction)
    pub fn set_start_block(&mut self, start_block: u32) {
        self.start_block = start_block;
    }
    /// Get Num Blocks
    pub fn num_blocks(&self) -> u32 {
        self.num_blocks
    }
    /// Get Size
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Get Type
    pub fn object_type(&self) -> &[u8; 32] {
        &self.object_type
    }

    /// Zeroize (Method wrapper)
    pub fn zeroize_entry(&mut self) {
        self.zeroize();
    }

    /// Validate Epoch
    pub fn validate_epoch(&self, header_epoch: u64) -> Result<(), VaultError> {
        if self.epoch > header_epoch {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        Ok(())
    }
}
