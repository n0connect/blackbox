# Security Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement file locking, secure wipe, and streaming buffer hardening for BlackBox vault.

**Architecture:** Three independent components that integrate into existing crates without changing public APIs. Each component is self-contained and follows the project's strict type-safety patterns.

**Tech Stack:** Rust, libc (flock), getrandom (CSPRNG), zeroize

**Constraints:** Compile only - no test execution, no running the binary.

---

## Task 1: Add getrandom Dependency to scb-vka-memory

**Files:**
- Modify: `crates/scb-vka-memory/Cargo.toml`

**Step 1: Add getrandom dependency**

Add `getrandom = "0.2"` to dependencies for CSPRNG-based secure wipe.

```toml
[dependencies]
zeroize = { version = "1.8", features = ["derive"] }
scb-vka-common = { path = "../scb-vka-common" }
libc = "0.2.180"
getrandom = "0.2"
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-memory
```

**Step 3: Commit**

```bash
git add crates/scb-vka-memory/Cargo.toml
git commit -m "chore(memory): add getrandom dependency for secure wipe"
```

---

## Task 2: Implement secure_wipe Function

**Files:**
- Modify: `crates/scb-vka-memory/src/lib.rs`

**Step 1: Add imports and constant**

After the existing imports (line ~21), add:

```rust
use std::io::{Seek, SeekFrom, Write};
```

After the `// PROCESS HARDENING` section, add new section:

```rust
// =============================================================================
// SECURE WIPE
// =============================================================================

/// Chunk size for secure wipe operations (64 KiB - within mlock limits)
const WIPE_CHUNK_SIZE: usize = 65_536;

/// Securely wipe a region of a file with CSPRNG random data.
///
/// # Security Properties
/// - Uses getrandom for cryptographically secure randomness
/// - Processes in chunks to bound memory usage
/// - Flushes after each chunk to ensure disk write
/// - Zeroizes the buffer after use
///
/// # Arguments
/// - `writer`: File or writer to wipe
/// - `offset`: Starting byte offset
/// - `len`: Number of bytes to overwrite
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

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-memory
```

**Step 3: Commit**

```bash
git add crates/scb-vka-memory/src/lib.rs
git commit -m "feat(memory): add secure_wipe function with CSPRNG overwrite"
```

---

## Task 3: Create VaultLock Module

**Files:**
- Create: `crates/scb-vka-io/src/lock.rs`

**Step 1: Create lock.rs file**

```rust
//! # scb-vka-io/lock
//!
//! RAII-based exclusive file locking using POSIX flock.
//!
//! ## Security Contract
//!
//! 1. Lock is acquired exclusively (LOCK_EX)
//! 2. Non-blocking to prevent deadlocks (LOCK_NB)
//! 3. Automatic release on drop (RAII)

use std::fs::File;
use std::path::Path;

use scb_vka_common::error::{VaultError, VaultErrorKind};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// RAII guard for exclusive vault file lock.
///
/// Lock is released automatically when the guard is dropped.
/// Only one process can hold the lock at a time.
pub struct VaultLock {
    #[allow(dead_code)]
    file: File,
}

impl VaultLock {
    /// Acquire exclusive lock on vault file.
    ///
    /// # Errors
    /// - `StorageUnavailable`: File cannot be opened
    /// - `VaultBusy`: File is already locked by another process
    ///
    /// # Platform Support
    /// - Unix: Uses flock(LOCK_EX | LOCK_NB)
    /// - Non-Unix: No-op (always succeeds)
    pub fn acquire(path: &Path) -> Result<Self, VaultError> {
        let file = File::open(path)
            .map_err(|_| VaultError::new(VaultErrorKind::StorageUnavailable))?;

        #[cfg(unix)]
        {
            let fd = file.as_raw_fd();
            // LOCK_EX: Exclusive lock
            // LOCK_NB: Non-blocking (return error instead of waiting)
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

            if result != 0 {
                return Err(VaultError::new(VaultErrorKind::VaultBusy));
            }
        }

        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for VaultLock {
    fn drop(&mut self) {
        let fd = self.file.as_raw_fd();
        // LOCK_UN: Unlock - ignore errors on drop
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
}
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-io
```

**Step 3: Commit**

```bash
git add crates/scb-vka-io/src/lock.rs
git commit -m "feat(io): add VaultLock RAII guard with flock"
```

---

## Task 4: Export lock Module from scb-vka-io

**Files:**
- Modify: `crates/scb-vka-io/src/lib.rs`

**Step 1: Add lock module export**

Add after line 42 (`pub mod manager;`):

```rust
pub mod lock;
```

Add after line 47 (`pub use manager::*;`):

```rust
pub use lock::*;
```

The file should look like:

```rust
//! ... (existing docs)

#[cfg(feature = "mock-hsp")]
pub mod hsp;
#[cfg(not(feature = "mock-hsp"))]
/// HSP module — provide a real `HardwareSecurityProvider` implementation here.
pub mod hsp {}

pub mod layout;
pub mod manager;
pub mod lock;

pub use hsp::*;
pub use layout::*;
pub use manager::*;
pub use lock::*;
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-io
```

**Step 3: Commit**

```bash
git add crates/scb-vka-io/src/lib.rs
git commit -m "feat(io): export lock module"
```

---

## Task 5: Add libc Dependency to scb-vka-io

**Files:**
- Modify: `crates/scb-vka-io/Cargo.toml`

**Step 1: Add libc dependency**

libc is needed for flock. Add after `getrandom = "0.2"`:

```toml
libc = "0.2"
```

Full dependencies section:

```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
zerocopy = { version = "0.7", features = ["derive"] }
zeroize = { version = "1.7", features = ["derive"] }
thiserror = "1.0"
scb-vka-common = { path = "../scb-vka-common" }
scb-vka-crypto = { path = "../scb-vka-crypto" }
scb-vka-memory = { path = "../scb-vka-memory" }
static_assertions = "1.1"
hex = "0.4"
rand = "0.8"
getrandom = "0.2"
libc = "0.2"
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-io
```

**Step 3: Commit**

```bash
git add crates/scb-vka-io/Cargo.toml
git commit -m "chore(io): add libc dependency for flock"
```

---

## Task 6: Increase SecureBuffer Limit for Streaming

**Files:**
- Modify: `crates/scb-vka-memory/src/lib.rs`

**Context:** Current SecureBuffer has 65KB limit but streaming uses 1 MiB chunks. We need to increase the limit or make it configurable.

**Step 1: Update SecureBuffer::new limit**

Change line 98-100 from:

```rust
    pub fn new(size: usize) -> Result<Self, VaultError> {
        if size > 65_536 {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
```

To:

```rust
    /// Maximum buffer size: 2 MiB (allows for 1 MiB chunk + overhead)
    pub const MAX_SIZE: usize = 2 * 1024 * 1024;

    /// Create a new secure buffer of specified size.
    ///
    /// # Errors
    /// - `ParameterOutOfRange`: Size exceeds MAX_SIZE (2 MiB)
    /// - `OperationFailed`: mlock failed (insufficient privileges or limits)
    pub fn new(size: usize) -> Result<Self, VaultError> {
        if size > Self::MAX_SIZE {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-memory
```

**Step 3: Commit**

```bash
git add crates/scb-vka-memory/src/lib.rs
git commit -m "feat(memory): increase SecureBuffer limit to 2 MiB for streaming"
```

---

## Task 7: Add scb-vka-memory Dependency to scb-vka-crypto

**Files:**
- Modify: `crates/scb-vka-crypto/Cargo.toml`

**Step 1: Add memory crate dependency**

Add after `scb-vka-common`:

```toml
scb-vka-memory = { path = "../scb-vka-memory" }
```

Full dependencies:

```toml
[dependencies]
aead = "0.5"
argon2 = "0.5"
chacha20poly1305 = "0.10"
getrandom = "0.2"
hmac = "0.12"
hkdf = "0.12"
sha3 = "0.10"
subtle = "2.5"
zeroize = { version = "1.8", features = ["derive"] }
scb-vka-common = { path = "../scb-vka-common" }
scb-vka-memory = { path = "../scb-vka-memory" }
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-crypto
```

**Step 3: Commit**

```bash
git add crates/scb-vka-crypto/Cargo.toml
git commit -m "chore(crypto): add scb-vka-memory dependency for SecureBuffer"
```

---

## Task 8: Harden encrypt_stream with SecureBuffer

**Files:**
- Modify: `crates/scb-vka-crypto/src/engine.rs`

**Step 1: Add import**

After line 26 (`use crate::{...};`), add:

```rust
use scb_vka_memory::SecureBuffer;
```

**Step 2: Update encrypt_stream buffer**

In `encrypt_stream` function (around line 544), change:

```rust
        let mut buffer = vec![0u8; scb_vka_common::config::STREAM_CHUNK_SIZE];
```

To:

```rust
        let mut buffer = SecureBuffer::new(scb_vka_common::config::STREAM_CHUNK_SIZE)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
```

Also update the read call (around line 552) from:

```rust
            let n = reader
                .read(&mut buffer)
```

To:

```rust
            let n = reader
                .read(buffer.as_mut_slice())
```

And update the encrypt call (around line 575) from:

```rust
            let (ct, tag) = self.encrypt_object(dek, &buffer[..n], aad, consumed)?;
```

To:

```rust
            let (ct, tag) = self.encrypt_object(dek, &buffer.as_mut_slice()[..n], aad, consumed)?;
```

**Step 3: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-crypto
```

**Step 4: Commit**

```bash
git add crates/scb-vka-crypto/src/engine.rs
git commit -m "feat(crypto): use SecureBuffer in encrypt_stream for mlock protection"
```

---

## Task 9: Harden decrypt_stream with SecureBuffer

**Files:**
- Modify: `crates/scb-vka-crypto/src/engine.rs`

**Step 1: Update decrypt_stream buffer**

In `decrypt_stream` function (around line 599), change:

```rust
        let mut buffer = vec![0u8; encrypted_chunk_size];
```

To:

```rust
        let mut buffer = SecureBuffer::new(encrypted_chunk_size)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
```

Also update the read loop (around line 617) from:

```rust
                let n = reader
                    .read(&mut buffer[read_count..])
```

To:

```rust
                let n = reader
                    .read(&mut buffer.as_mut_slice()[read_count..])
```

And update the slice operations (around line 640-642) from:

```rust
            let ct = &buffer[..tag_start];
            let tag = &buffer[tag_start..read_count];
```

To:

```rust
            let ct = &buffer.as_mut_slice()[..tag_start];
            let tag = &buffer.as_mut_slice()[tag_start..read_count];
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-crypto
```

**Step 3: Commit**

```bash
git add crates/scb-vka-crypto/src/engine.rs
git commit -m "feat(crypto): use SecureBuffer in decrypt_stream for mlock protection"
```

---

## Task 10: Integrate VaultLock into VaultSession

**Files:**
- Modify: `crates/scb-vka-orchestrator/src/lib.rs`

**Step 1: Add VaultLock import**

Update the import from scb-vka-io (around line 30-33) to include VaultLock:

```rust
use scb_vka_io::layout::{
    FileTableEntry, Superblock, VaultHeader, FILE_ENTRY_SIZE, VAULT_HEADER_OFFSET,
};
use scb_vka_io::manager::SpaceManager;
use scb_vka_io::lock::VaultLock;
```

**Step 2: Add lock field to VaultSession**

Update VaultSession struct (around line 48-57) to include the lock:

```rust
pub struct VaultSession {
    file: File,
    pub vid: [u8; VID_LEN],
    kek: SecureBox<KeyKEK>,
    mk: SecureBox<KeyMK>,

    header: VaultHeader,
    file_table: Vec<FileTableEntry>,
    space_manager: SpaceManager,

    /// File lock - held for session duration, released on drop
    _lock: VaultLock,
}
```

**Step 3: Acquire lock in unlock_vault**

In `unlock_vault` function (around line 205-210), acquire lock before opening file:

```rust
    fn unlock_vault(&self, path: &Path, password: &[u8]) -> Result<VaultSession, VaultError> {
        // Acquire exclusive lock first
        let lock = VaultLock::acquire(path)?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
```

**Step 4: Include lock in VaultSession construction**

Update the VaultSession construction (around line 247-255):

```rust
        Ok(VaultSession {
            file,
            vid: *superblock.vid(),
            kek: SecureBox::new(kek)?,
            mk: SecureBox::new(mk)?,
            header,
            file_table,
            space_manager,
            _lock: lock,
        })
```

**Step 5: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-orchestrator
```

**Step 6: Commit**

```bash
git add crates/scb-vka-orchestrator/src/lib.rs
git commit -m "feat(orchestrator): integrate VaultLock into VaultSession"
```

---

## Task 11: Integrate secure_wipe into delete_object

**Files:**
- Modify: `crates/scb-vka-orchestrator/src/lib.rs`

**Step 1: Update delete_object to use secure_wipe**

In `delete_object` function (around line 502-527), replace the zero-fill with secure_wipe:

Change from:

```rust
        let entry = session.file_table.remove(idx);
        let offset = DATA_REGION_START + (entry.start_block() as u64 * BLOCK_SIZE as u64);
        let len = entry.num_blocks() as usize * BLOCK_SIZE as usize;
        let zeros = vec![0u8; len];

        session
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
        session
            .file
            .write_all(&zeros)
            .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;
```

To:

```rust
        let entry = session.file_table.remove(idx);
        let offset = DATA_REGION_START + (entry.start_block() as u64 * BLOCK_SIZE as u64);
        let len = entry.num_blocks() as usize * BLOCK_SIZE as usize;

        // Secure wipe: overwrite with CSPRNG random data
        scb_vka_memory::secure_wipe(&mut session.file, offset, len)?;
```

**Step 2: Verify compilation**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo check -p scb-vka-orchestrator
```

**Step 3: Commit**

```bash
git add crates/scb-vka-orchestrator/src/lib.rs
git commit -m "feat(orchestrator): use secure_wipe for CSPRNG block overwrite on delete"
```

---

## Task 12: Final Full Build Verification

**Files:** None (verification only)

**Step 1: Clean build**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo clean
```

**Step 2: Full workspace build**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo build --all-features
```

**Step 3: Check for warnings**

```bash
cd /Users/n0n0/Desktop/coding/BlackBox && cargo clippy --all-features -- -D warnings
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: security hardening complete - file locking, secure wipe, streaming buffers"
```

---

## Summary

| Task | Component | File | Change Type |
|------|-----------|------|-------------|
| 1 | secure_wipe | memory/Cargo.toml | Add dependency |
| 2 | secure_wipe | memory/src/lib.rs | New function |
| 3 | VaultLock | io/src/lock.rs | New file |
| 4 | VaultLock | io/src/lib.rs | Export module |
| 5 | VaultLock | io/Cargo.toml | Add dependency |
| 6 | SecureBuffer | memory/src/lib.rs | Increase limit |
| 7 | Streaming | crypto/Cargo.toml | Add dependency |
| 8 | Streaming | crypto/src/engine.rs | SecureBuffer encrypt |
| 9 | Streaming | crypto/src/engine.rs | SecureBuffer decrypt |
| 10 | Integration | orchestrator/src/lib.rs | VaultLock |
| 11 | Integration | orchestrator/src/lib.rs | secure_wipe |
| 12 | Verification | - | Full build |

---

## Rollback Plan

If any task fails, revert with:

```bash
git reset --hard HEAD~N  # where N is number of commits to undo
```

Or revert specific commit:

```bash
git revert <commit-hash>
```
