//! # scb-vka-io/manager
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! Block allocation manager. Bitmap tabanlı.
//!
//! - bit = 0: Free
//! - bit = 1: Allocated
//!
//! ## RESERVED BLOCKS
//!
//! İlk 256 block metadata için ayrılmış (superblock + header region).

use scb_vka_common::error::{VaultError, VaultErrorKind};

/// Reserved blocks for metadata (DATA_REGION_START / BLOCK_SIZE)
pub const RESERVED_BLOCKS: u64 = 256;

pub struct SpaceManager {
    bitmap: Vec<u8>,
    total_blocks: u64,
}

impl SpaceManager {
    /// Create new manager with reserved blocks marked as allocated
    pub fn new(total_blocks: u64) -> Result<Self, VaultError> {
        // Validate total_blocks to prevent overflow
        let bitmap_size = total_blocks.div_ceil(8);
        let bitmap_size_usize = usize::try_from(bitmap_size)
            .map_err(|_| VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        let mut bitmap = vec![0u8; bitmap_size_usize];

        // Mark reserved blocks as allocated
        let reserved = RESERVED_BLOCKS.min(total_blocks);
        for block_idx in 0..reserved {
            let byte_idx = (block_idx / 8) as usize;
            let bit_idx = (block_idx % 8) as usize;
            // Safety: byte_idx < bitmap_size guaranteed by block_idx < total_blocks
            bitmap[byte_idx] |= 1 << bit_idx;
        }

        Ok(Self {
            bitmap,
            total_blocks,
        })
    }

    pub fn from_bytes(bytes: Vec<u8>, total_blocks: u64) -> Result<Self, VaultError> {
        // Validate bitmap size matches total_blocks
        let expected_size = total_blocks.div_ceil(8) as usize;
        if bytes.len() != expected_size {
            return Err(VaultError::new(VaultErrorKind::IntegrityError));
        }
        Ok(Self {
            bitmap: bytes,
            total_blocks,
        })
    }

    pub fn bitmap_size(&self) -> u64 {
        self.bitmap.len() as u64
    }

    pub fn export_bitmap(&self) -> Vec<u8> {
        self.bitmap.clone()
    }

    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Dynamically expand the number of manageable blocks.
    pub fn expand(&mut self, additional_blocks: u64) -> Result<(), VaultError> {
        if additional_blocks == 0 {
            return Ok(());
        }

        let new_total = self
            .total_blocks
            .checked_add(additional_blocks)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;

        let current_bytes = self.bitmap.len();
        let new_bytes = (new_total as usize).div_ceil(8);

        let bytes_to_add = new_bytes.saturating_sub(current_bytes);
        self.bitmap.extend(std::iter::repeat_n(0, bytes_to_add));

        self.total_blocks = new_total;
        Ok(())
    }

    /// Allocate contiguous blocks. Returns starting block index.
    pub fn allocate(&mut self, count: u64) -> Result<u64, VaultError> {
        if count == 0 {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }

        let mut consecutive = 0u64;
        let mut start_candidate = 0u64;

        for block_idx in 0..self.total_blocks {
            let byte_idx = (block_idx / 8) as usize;
            let bit_idx = (block_idx % 8) as usize;

            // Bounds check before indexing
            if byte_idx >= self.bitmap.len() {
                return Err(VaultError::new(VaultErrorKind::IntegrityError));
            }

            let is_allocated = (self.bitmap[byte_idx] >> bit_idx) & 1 == 1;

            if !is_allocated {
                if consecutive == 0 {
                    start_candidate = block_idx;
                }
                consecutive += 1;
                if consecutive == count {
                    self.mark_range(start_candidate, count, true)?;
                    return Ok(start_candidate);
                }
            } else {
                consecutive = 0;
            }
        }

        Err(VaultError::new(VaultErrorKind::VaultFull))
    }

    /// Deallocate blocks
    pub fn deallocate(&mut self, start: u64, count: u64) -> Result<(), VaultError> {
        // mark_range already does bounds checking
        self.mark_range(start, count, false)
    }

    fn mark_range(&mut self, start: u64, count: u64, value: bool) -> Result<(), VaultError> {
        // Bounds check: ensure all blocks are within bitmap
        let end = start
            .checked_add(count)
            .ok_or(VaultError::new(VaultErrorKind::ParameterOutOfRange))?;
        if end > self.total_blocks {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }

        for i in 0..count {
            let block_idx = start + i;
            let byte_idx = (block_idx / 8) as usize;
            let bit_idx = (block_idx % 8) as usize;

            // Safety: bounds checked above
            if byte_idx >= self.bitmap.len() {
                return Err(VaultError::new(VaultErrorKind::IntegrityError));
            }

            if value {
                self.bitmap[byte_idx] |= 1 << bit_idx;
            } else {
                self.bitmap[byte_idx] &= !(1 << bit_idx);
            }
        }
        Ok(())
    }
}
