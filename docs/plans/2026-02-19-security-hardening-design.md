# Security Hardening Design

**Date:** 2026-02-19
**Status:** Approved
**Author:** Claude (with user approval)

## Overview

This document describes three security hardening improvements for BlackBox:

1. **File Locking** - RAII-based exclusive lock to prevent concurrent access
2. **Secure Wipe** - CSPRNG-based block overwrite on object deletion
3. **Streaming Buffer Hardening** - mlock-protected buffers for chunk processing

## 1. File Locking (VaultLock)

### Problem

Currently, multiple processes can open the same vault file simultaneously, leading to potential corruption.

### Solution

Implement RAII-based file locking using POSIX `flock()`.

### Design

**New file:** `crates/scb-vka-io/src/lock.rs`

```rust
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use scb_vka_common::error::{VaultError, VaultErrorKind};

/// RAII guard for exclusive vault file lock.
/// Lock is released automatically on drop.
pub struct VaultLock {
    file: File,
}

impl VaultLock {
    /// Acquire exclusive lock on vault file.
    /// Returns error if file is already locked (non-blocking).
    pub fn acquire(path: &Path) -> Result<Self, VaultError> {
        let file = File::open(path)
            .map_err(|_| VaultError::new(VaultErrorKind::StorageUnavailable))?;

        let fd = file.as_raw_fd();
        let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

        if result != 0 {
            return Err(VaultError::new(VaultErrorKind::VaultBusy));
        }

        Ok(Self { file })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let fd = self.file.as_raw_fd();
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
}
```

### Integration

`VaultSession` will hold a `VaultLock` field to maintain the lock for the session duration.

### Dependencies

- `libc` (already in dependencies)

---

## 2. Secure Wipe

### Problem

Current `delete_object` writes zeros to freed blocks. This is not cryptographically secure.

### Solution

Overwrite with CSPRNG-generated random bytes before deallocation.

### Design

**Location:** `crates/scb-vka-memory/src/lib.rs` (new function)

```rust
use std::io::{Write, Seek, SeekFrom};
use scb_vka_common::error::{VaultError, VaultErrorKind};
use zeroize::Zeroize;

/// Chunk size for secure wipe operations (1 MiB)
const WIPE_CHUNK_SIZE: usize = 1024 * 1024;

/// Securely wipe a region of a file with CSPRNG random data.
///
/// # Security Properties
/// - Uses getrandom for cryptographically secure randomness
/// - Processes in chunks to bound memory usage
/// - Flushes after each chunk to ensure disk write
/// - Zeroizes the buffer after use
pub fn secure_wipe<W: Write + Seek>(
    writer: &mut W,
    offset: u64,
    len: usize,
) -> Result<(), VaultError> {
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    let chunk_size = WIPE_CHUNK_SIZE.min(len);
    let mut chunk = vec![0u8; chunk_size];
    let mut remaining = len;

    while remaining > 0 {
        let to_write = chunk_size.min(remaining);
        getrandom::getrandom(&mut chunk[..to_write])
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        writer
            .write_all(&chunk[..to_write])
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        writer
            .flush()
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

        remaining -= to_write;
    }

    chunk.zeroize();
    Ok(())
}
```

### Integration

Replace in `orchestrator/src/lib.rs` `delete_object`:

```rust
// Before:
let zeros = vec![0u8; len];
session.file.write_all(&zeros)?;

// After:
scb_vka_memory::secure_wipe(&mut session.file, offset, len)?;
```

### Dependencies

- `getrandom` (add to scb-vka-memory)
- `zeroize` (already in dependencies)

---

## 3. Streaming Buffer Hardening

### Problem

Current streaming encryption/decryption uses plain `Vec<u8>` buffers. These are not:
- Protected from swap (no mlock)
- Automatically zeroized on drop

### Solution

Use `SecureBuffer` from `scb-vka-memory` for chunk processing.

### Design

**Location:** `crates/scb-vka-crypto/src/engine.rs`

**Changes in `encrypt_stream`:**
```rust
// Before:
let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];

// After:
let mut buffer = SecureBuffer::new(STREAM_CHUNK_SIZE)?;
```

**Changes in `decrypt_stream`:**
```rust
// Before:
let mut buffer = vec![0u8; encrypted_chunk_size];

// After:
let mut buffer = SecureBuffer::new(encrypted_chunk_size)?;
```

### SecureBuffer Requirements

The existing `SecureBuffer` in `scb-vka-memory` needs:
- `as_mut_slice()` method for Read trait compatibility
- `len()` method
- Implements `Drop` with zeroize (already done)

### Dependencies

- Add `scb-vka-memory` to `scb-vka-crypto` Cargo.toml

---

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `crates/scb-vka-io/src/lock.rs` | Create | VaultLock RAII guard |
| `crates/scb-vka-io/src/lib.rs` | Modify | Export lock module |
| `crates/scb-vka-io/Cargo.toml` | Modify | (no change, libc exists) |
| `crates/scb-vka-memory/src/lib.rs` | Modify | Add secure_wipe function |
| `crates/scb-vka-memory/Cargo.toml` | Modify | Add getrandom dependency |
| `crates/scb-vka-crypto/src/engine.rs` | Modify | Use SecureBuffer |
| `crates/scb-vka-crypto/Cargo.toml` | Modify | Add scb-vka-memory dependency |
| `crates/scb-vka-orchestrator/src/lib.rs` | Modify | Use VaultLock, secure_wipe |

---

## Security Considerations

### File Locking
- Non-blocking lock prevents deadlocks
- RAII ensures lock release even on panic
- Does not protect against malicious processes with root access

### Secure Wipe
- CSPRNG provides unpredictable overwrite pattern
- Single pass is sufficient per NIST SP 800-88
- Combined with DEK destruction for defense-in-depth
- SSD wear leveling may retain old data in spare blocks, but encrypted data without DEK is unrecoverable

### Streaming Buffers
- mlock prevents swap to disk
- Automatic zeroization prevents memory reuse attacks
- Bounded chunk size prevents memory exhaustion

---

## Constraints

- **No test code** - Only compile, no execution
- **Use existing crates** - No reimplementing crypto primitives
- **Minimal changes** - Pure, small, reliable code
