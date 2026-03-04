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

use scb_vka_common::config::MAX_TOTAL_BLOCKS;
use scb_vka_common::error::{VaultError, VaultErrorKind};
use zeroize::Zeroize;

/// Reserved blocks for metadata (DATA_REGION_START / BLOCK_SIZE)
pub const RESERVED_BLOCKS: u64 = 256;

pub struct SpaceManager {
    bitmap: Vec<u8>,
    total_blocks: u64,
    /// Hint for the first potentially free block index.
    /// Allocation scans from here instead of block 0.  The hint is conservative
    /// (may point to an allocated block) but never past a free block.
    first_free_hint: u64,
}

/// SECURITY: Zeroize bitmap on drop to prevent object-location metadata leaks.
impl Drop for SpaceManager {
    fn drop(&mut self) {
        self.bitmap.zeroize();
        self.total_blocks = 0;
        self.first_free_hint = 0;
    }
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
            first_free_hint: reserved,
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
            first_free_hint: RESERVED_BLOCKS,
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

        // CRITICAL: Enforce vault size limit to prevent unbounded growth
        if new_total > MAX_TOTAL_BLOCKS {
            return Err(VaultError::new(VaultErrorKind::CapacityExceeded));
        }

        let current_bytes = self.bitmap.len();
        let new_bytes = (new_total as usize).div_ceil(8);

        let bytes_to_add = new_bytes.saturating_sub(current_bytes);
        self.bitmap.extend(std::iter::repeat_n(0, bytes_to_add));

        self.total_blocks = new_total;
        Ok(())
    }

    /// Allocate contiguous blocks. Returns starting block index.
    ///
    /// Scans from `first_free_hint` for O(1) amortised best-case allocation.
    pub fn allocate(&mut self, count: u64) -> Result<u64, VaultError> {
        if count == 0 {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }

        let mut consecutive = 0u64;
        let mut start_candidate = 0u64;

        let mut scan_count = 0u64;
        let scan_limit = self.total_blocks - RESERVED_BLOCKS;
        let mut block_idx = self.first_free_hint;

        while scan_count < scan_limit {
            let byte_idx = (block_idx / 8) as usize;
            let bit_idx = (block_idx % 8) as usize;

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
                    self.first_free_hint = start_candidate + count;
                    return Ok(start_candidate);
                }
            } else {
                consecutive = 0;
            }

            block_idx += 1;
            if block_idx >= self.total_blocks {
                block_idx = RESERVED_BLOCKS;
                consecutive = 0; // cannot wrap around contiguous allocation
            }
            scan_count += 1;
        }

        Err(VaultError::new(VaultErrorKind::VaultFull))
    }

    /// Deallocate blocks
    pub fn deallocate(&mut self, start: u64, count: u64) -> Result<(), VaultError> {
        self.mark_range(start, count, false)?;
        // Move hint back so freed space can be found
        if start < self.first_free_hint {
            self.first_free_hint = start;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_space_manager_allocation() {
        // Create a SpaceManager with 512 blocks. First 256 are reserved.
        let mut sm = SpaceManager::new(512).unwrap();
        assert_eq!(sm.total_blocks(), 512);

        // Allocate 10 blocks (should start exactly after reserved)
        let block_idx = sm.allocate(10).unwrap();
        assert_eq!(block_idx, 256);

        // Allocate 5 more
        let block_idx2 = sm.allocate(5).unwrap();
        assert_eq!(block_idx2, 266);

        // Deallocate the first 10
        assert!(sm.deallocate(256, 10).is_ok());

        // Allocate 8 blocks (should reuse the freed space at 256)
        let block_idx3 = sm.allocate(8).unwrap();
        assert_eq!(block_idx3, 256);

        // Allocating past capacity should fail
        assert!(sm.allocate(1000).is_err());

        // Out-of-bounds deallocation should fail
        assert!(sm.deallocate(1000, 10).is_err());
    }

    #[test]
    fn test_space_manager_expansion() {
        let mut sm = SpaceManager::new(300).unwrap();
        // Expand by 100 blocks
        assert!(sm.expand(100).is_ok());
        assert_eq!(sm.total_blocks(), 400);

        // Ensure we can allocate in the newly expanded space
        let block_idx = sm.allocate(100).unwrap();
        assert_eq!(block_idx, 256); // 256-355

        let block_idx2 = sm.allocate(44).unwrap();
        assert_eq!(block_idx2, 356); // 356-399
    }
}
