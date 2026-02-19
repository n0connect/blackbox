//! # scb-vka-common/error
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! - **Opak hata tipi**: Display her zaman aynı mesajı gösterir (bilgi sızıntısı yok)
//! - **Kind public**: İç lojik için kind kullanılabilir ama kullanıcıya gösterilmez
//! - **No source chain**: Inner error yok, wrap yok

use crate::config;

const DISPLAY_MSG: &str = config::ERROR_DISPLAY_MSG;

/// Opaque vault error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultError {
    /// Internal error kind (not exposed to users via Display).
    pub kind: VaultErrorKind,
}

/// Opaque error kind for internal dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultErrorKind {
    /// AEAD tag mismatch
    AuthenticationFailed,
    /// Storage backend unavailable
    StorageUnavailable,
    /// HSP unavailable
    HardwareUnavailable,
    /// Concurrent access
    VaultBusy,
    /// Structural corruption
    VaultCorrupted,
    /// Serialization failure
    EncodingFailed,
    /// Value outside allowed range
    ParameterOutOfRange,
    /// Generic operation failure
    OperationFailed,
    /// Object not found in file table
    ObjectNotFound,
    /// No free blocks
    VaultFull,
    /// Exceeded capacity limit
    CapacityExceeded,
    /// Disk I/O error
    IoError,
    /// MAC / hash mismatch
    IntegrityError,
    /// Vault not unlocked
    VaultLocked,
    /// Missing or malformed input
    InvalidInput,
}

impl VaultError {
    /// Create a new error from a kind.
    #[must_use]
    pub fn new(kind: VaultErrorKind) -> Self {
        Self { kind }
    }
}

impl From<VaultErrorKind> for VaultError {
    fn from(kind: VaultErrorKind) -> Self {
        Self::new(kind)
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{DISPLAY_MSG}")
    }
}

impl std::error::Error for VaultError {}

/// Bounds check utility.
///
/// # Errors
///
/// Returns `VaultError` with `ParameterOutOfRange` if the value is out of bounds.
pub fn check_bounds_usize(
    value: usize,
    min_inclusive: usize,
    max_inclusive: usize,
) -> Result<(), VaultError> {
    if value >= min_inclusive && value <= max_inclusive {
        Ok(())
    } else {
        Err(VaultError::new(VaultErrorKind::ParameterOutOfRange))
    }
}
