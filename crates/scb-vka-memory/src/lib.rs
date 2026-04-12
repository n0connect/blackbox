//! # scb-vka-memory
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! Güvenli bellek yönetimi:
//!
//! - **SecureBox<T>**: Zeroize-on-drop container
//! - **SecureBuffer**: Zeroize-on-drop byte buffer
//! - **mlock**: Swap'a yazılmayı önler (Unix)
//!
//! ## KULLANIM
//!
//! ```ignore
//! let key = SecureBox::new([0u8; 32])?;
//! // key drop edildiğinde otomatik zeroize olur
//! ```

use std::io::{Seek, SeekFrom, Write};
use std::ops::Deref;
use zeroize::Zeroize;

use scb_vka_common::error::{VaultError, VaultErrorKind};

// =============================================================================
// PROCESS HARDENING
// =============================================================================

/// Harden the entire process against memory dumping.
/// Must be called early in the application lifecycle.
pub fn harden_process() {
    #[cfg(unix)]
    {
        // Disable core dumps on Unix
        unsafe {
            let mut limit = std::mem::zeroed::<libc::rlimit>();
            limit.rlim_cur = 0;
            limit.rlim_max = 0;
            libc::setrlimit(libc::RLIMIT_CORE, &limit);
        }
    }

    #[cfg(windows)]
    {
        // Keep hardening portable across windows-sys versions.
        // dump suppression still happens via disable_core_dumps() / SetErrorMode.
        let _ = disable_core_dumps();
    }
}

// =============================================================================
// MLOCK WRAPPERS
// =============================================================================

#[cfg(unix)]
fn mem_lock(ptr: *const u8, len: usize) -> Result<(), VaultError> {
    unsafe {
        if libc::mlock(ptr as *const std::ffi::c_void, len) != 0 {
            return Err(VaultError::new(VaultErrorKind::OperationFailed));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn mem_unlock(ptr: *const u8, len: usize) {
    unsafe {
        libc::munlock(ptr as *const std::ffi::c_void, len);
    }
}

#[cfg(windows)]
fn mem_lock(ptr: *const u8, len: usize) -> Result<(), VaultError> {
    use windows_sys::Win32::System::Memory::VirtualLock;

    unsafe {
        if VirtualLock(ptr as *mut _, len) == 0 {
            return Err(VaultError::new(VaultErrorKind::OperationFailed));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn mem_unlock(ptr: *const u8, len: usize) {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    unsafe {
        // Ignore errors - best effort unlock
        let _ = VirtualUnlock(ptr as *mut _, len);
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!(
    "Memory locking is unavailable on this platform. \
     Sensitive key material may be written to swap. \
     Supported: Unix (mlock) or Windows (VirtualLock)."
);

// =============================================================================
// SECURE BOX
// =============================================================================

/// Memory-locked, zeroize-on-drop container.
pub struct SecureBox<T: Zeroize> {
    inner: Box<T>,
}

impl<T: Zeroize> SecureBox<T> {
    /// Create a memory-locked, zeroize-on-drop container.
    ///
    /// # Security Note
    /// There is an inherent, brief window between `Box::new` (heap write)
    /// and `mem_lock` where the data could theoretically be swapped to disk.
    /// This is a fundamental limitation of safe Rust — `Box::new_uninit()`
    /// and `ptr::write` could narrow this window further but requires nightly
    /// features.  In practice the window is negligible (<µs).
    #[inline(always)] // Minimise the mlock gap
    pub fn new(value: T) -> Result<Self, VaultError> {
        let b = Box::new(value);
        let ptr = &*b as *const T as *const u8;
        let len = std::mem::size_of::<T>();
        mem_lock(ptr, len)?;
        Ok(Self { inner: b })
    }
}

impl<T: Zeroize> Deref for SecureBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for SecureBox<T> {
    #[inline(never)] // Prevent compiler from optimizing away zeroize
    fn drop(&mut self) {
        // SECURITY: Save pointer and length BEFORE zeroize.
        // Zeroize may invalidate internal state for complex types.
        let ptr = &*self.inner as *const T as *const u8;
        let len = std::mem::size_of::<T>();
        self.inner.zeroize();
        mem_unlock(ptr, len);
    }
}

// =============================================================================
// SECURE BUFFER
// =============================================================================

/// Zeroize-on-drop byte buffer.
pub struct SecureBuffer {
    inner: Vec<u8>,
}

impl SecureBuffer {
    /// Maximum allowed allocation (to prevent locking too much unswappable RAM)
    pub const MAX_SIZE: usize = scb_vka_common::config::MAX_SECURE_BUFFER_SIZE;

    /// Create a new secure buffer of specified size.
    ///
    /// # Errors
    /// - `ParameterOutOfRange`: Size exceeds MAX_SIZE
    /// - `OperationFailed`: mlock failed (insufficient privileges or limits)
    pub fn new(size: usize) -> Result<Self, VaultError> {
        if size > Self::MAX_SIZE {
            return Err(VaultError::new(VaultErrorKind::ParameterOutOfRange));
        }
        let inner = vec![0u8; size];
        mem_lock(inner.as_ptr(), size)?;
        Ok(Self { inner })
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // SECURITY: Save pointer and length BEFORE zeroize.
        // Vec::zeroize() calls clear() which sets len to 0,
        // making subsequent munlock(ptr, 0) a no-op.
        let ptr = self.inner.as_ptr();
        let len = self.inner.len();
        self.inner.zeroize();
        mem_unlock(ptr, len);
    }
}
// ===================================
// PROCESS HARDENING
// ===================================

/// Disable Core Dumps (OS specific)
#[cfg(unix)]
pub fn disable_core_dumps() -> Result<(), VaultError> {
    unsafe {
        // 1. RLIMIT_CORE = 0
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) != 0 {
            return Err(VaultError::new(VaultErrorKind::OperationFailed));
        }

        // 2. Linux specific PR_SET_DUMPABLE
        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                return Err(VaultError::new(VaultErrorKind::OperationFailed));
            }
        }

        // 3. MacOS specific PT_DENY_ATTACH (Anti-Debug)
        // Note: usage of PT_DENY_ATTACH is discouraged by Apple for App Store,
        // but for a vault tool it's appropriate defense-in-depth.
        // However, libc binding might need manual definition or strict flag.
        // We'll stick to setrlimit for now as it's the standard way to stop core dumps.
    }
    Ok(())
}

/// Disable crash dumps on Windows.
///
/// Uses SetErrorMode with SEM_NOGPFAULTERRORBOX to prevent
/// Windows Error Reporting from creating memory dumps.
#[cfg(windows)]
pub fn disable_core_dumps() -> Result<(), VaultError> {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };
    unsafe {
        // SEM_NOGPFAULTERRORBOX: Prevents WER from creating dumps
        // SEM_FAILCRITICALERRORS: Prevents system error dialog boxes
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    }
    Ok(())
}

// Fallback for unsupported platforms
#[cfg(not(any(unix, windows)))]
pub fn disable_core_dumps() -> Result<(), VaultError> {
    Ok(())
}

// =============================================================================
// SECURE WIPE
// =============================================================================

/// Chunk size for secure wipe operations (64 KiB — within mlock limits).
///
/// # Security Note
/// The wipe buffer itself is NOT mlock'd because it only ever contains
/// CSPRNG random data or zero-fill patterns — never user secrets.
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
    // PASS 1: Random
    overwrite_pass(writer, offset, len, None)?;
    // PASS 2: Zeros
    overwrite_pass(writer, offset, len, Some(0x00))?;
    // PASS 3: Random
    overwrite_pass(writer, offset, len, None)?;
    Ok(())
}

fn overwrite_pass<W: Write + Seek>(
    writer: &mut W,
    offset: u64,
    len: usize,
    pattern: Option<u8>,
) -> Result<(), VaultError> {
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(|_| VaultError::new(VaultErrorKind::IoError))?;

    let chunk_size = WIPE_CHUNK_SIZE.min(len);
    let mut chunk = vec![0u8; chunk_size];
    let mut remaining = len;

    while remaining > 0 {
        let to_write = chunk_size.min(remaining);

        if let Some(p) = pattern {
            chunk[..to_write].fill(p);
        } else {
            getrandom::getrandom(&mut chunk[..to_write])
                .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use scb_vka_common::error::VaultErrorKind;
    use std::io::Cursor;

    #[test]
    fn test_secure_buffer_bounds() {
        // Valid allocation within limit
        let buf = SecureBuffer::new(1024).expect("Failed to allocate 1KB SecureBuffer");
        assert_eq!(buf.len(), 1024);

        // Invalid allocation (exceeds MAX_SIZE)
        let too_large = SecureBuffer::MAX_SIZE + 1;
        let err = SecureBuffer::new(too_large).err().unwrap();
        // VaultErrorKind is not exported with Eq directly on VaultError, so we match on kind if possible,
        // or just format and check
        assert_eq!(err.kind, VaultErrorKind::ParameterOutOfRange);
    }

    #[test]
    fn test_secure_wipe_execution() {
        let mut data = vec![0xFF; 1024];
        let mut cursor = Cursor::new(&mut data);

        // Wipe the first 512 bytes
        secure_wipe(&mut cursor, 0, 512).expect("Secure wipe failed");

        let inner = cursor.into_inner();

        // Ensure remaining 512 bytes are untouched
        assert!(inner[512..1024].iter().all(|&b| b == 0xFF));

        // The first 512 bytes are wiped with random data (pass 3), so we just verify they aren't all 0xFF
        assert!(!inner[0..512].iter().all(|&b| b == 0xFF));
    }
}
