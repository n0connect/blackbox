//! # scb-vka-io/lock
//!
//! RAII-based exclusive file locking.
//!
//! ## Security Contract
//!
//! 1. Lock is acquired exclusively
//! 2. Non-blocking to prevent deadlocks
//! 3. Automatic release on drop (RAII)
//!
//! ## Platform Support
//! - Unix (Linux/macOS): POSIX flock
//! - Windows: LockFileEx/UnlockFileEx

use std::fs::File;
use std::path::Path;

use scb_vka_common::error::{VaultError, VaultErrorKind};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

/// RAII guard for exclusive vault file lock.
///
/// Lock is released automatically when the guard is dropped.
/// Only one process can hold the lock at a time.
pub struct VaultLock {
    #[allow(dead_code)]
    file: File,
}

// =============================================================================
// UNIX IMPLEMENTATION (Linux, macOS)
// =============================================================================

#[cfg(unix)]
impl VaultLock {
    /// Acquire exclusive lock on vault file.
    ///
    /// # Errors
    /// - `StorageUnavailable`: File cannot be opened
    /// - `VaultBusy`: File is already locked by another process
    pub fn acquire(path: &Path) -> Result<Self, VaultError> {
        let file =
            File::open(path).map_err(|_| VaultError::new(VaultErrorKind::StorageUnavailable))?;

        let fd = file.as_raw_fd();
        // LOCK_EX: Exclusive lock
        // LOCK_NB: Non-blocking (return error instead of waiting)
        let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

        if result != 0 {
            return Err(VaultError::new(VaultErrorKind::VaultBusy));
        }

        Ok(Self { file })
    }

    /// Access the locked file (mutable).
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Access the locked file (immutable).
    pub fn file(&self) -> &File {
        &self.file
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

// =============================================================================
// WINDOWS IMPLEMENTATION
// =============================================================================

#[cfg(windows)]
impl VaultLock {
    /// Acquire exclusive lock on vault file.
    ///
    /// # Errors
    /// - `StorageUnavailable`: File cannot be opened
    /// - `VaultBusy`: File is already locked by another process
    pub fn acquire(path: &Path) -> Result<Self, VaultError> {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;

        let file =
            File::open(path).map_err(|_| VaultError::new(VaultErrorKind::StorageUnavailable))?;

        let handle = file.as_raw_handle() as HANDLE;

        // OVERLAPPED structure for LockFileEx (required even for synchronous ops)
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };

        let result = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,          // reserved
                u32::MAX,   // lock entire file (low)
                u32::MAX,   // lock entire file (high)
                &mut overlapped,
            )
        };

        if result == 0 {
            return Err(VaultError::new(VaultErrorKind::VaultBusy));
        }

        Ok(Self { file })
    }

    /// Access the locked file (mutable).
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Access the locked file (immutable).
    pub fn file(&self) -> &File {
        &self.file
    }
}

#[cfg(windows)]
impl Drop for VaultLock {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
        use windows_sys::Win32::System::IO::OVERLAPPED;

        let handle = self.file.as_raw_handle() as HANDLE;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };

        unsafe {
            // Ignore errors on drop - best effort unlock
            let _ = UnlockFileEx(handle, 0, u32::MAX, u32::MAX, &mut overlapped);
        }
    }
}

// =============================================================================
// FALLBACK (unsupported platforms)
// =============================================================================

#[cfg(not(any(unix, windows)))]
impl VaultLock {
    pub fn acquire(path: &Path) -> Result<Self, VaultError> {
        let file =
            File::open(path).map_err(|_| VaultError::new(VaultErrorKind::StorageUnavailable))?;
        Ok(Self { file })
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn file(&self) -> &File {
        &self.file
    }
}
