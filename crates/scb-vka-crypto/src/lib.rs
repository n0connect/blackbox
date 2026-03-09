#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

//! # scb-vka-crypto
//!
//! ## FINAL HARDENING (Extreme Type-Safety)
//!
//! - `Key<Role>`: Newtypes.
//! - `ObjectId`, `Version`, `Nonce`: Strict newtypes.
//! - `ConsumedNonce`: Linear type for nonce usage.
//! - `Epoch`: Strict comparison.
//! - `AadPurpose`: Enum restriction.

pub mod engine;

pub use engine::{AadBuilder, AadPurpose, ConsumedNonce, CryptoEngine, NonceFactory};
pub use scb_vka_common::error::{VaultError, VaultErrorKind};

use zeroize::Zeroize;

/// Marker traits for Key Roles
pub trait KeyRole: Send + Sync + 'static {}
/// KEK Role
pub struct RoleKEK;
impl KeyRole for RoleKEK {}
/// MK Role
pub struct RoleMK;
impl KeyRole for RoleMK {}
/// CK Role
pub struct RoleCK;
impl KeyRole for RoleCK {}
/// UR Role
pub struct RoleUR;
impl KeyRole for RoleUR {}
/// RR Role
pub struct RoleRR;
impl KeyRole for RoleRR {}
/// MR Role
pub struct RoleMR;
impl KeyRole for RoleMR {}
/// CR Role
pub struct RoleCR;
impl KeyRole for RoleCR {}

// NEWTYPES

/// Strict Object ID (16 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
#[must_use]
pub struct ObjectId([u8; 16]);

impl ObjectId {
    /// Create new `ObjectId`
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    /// Get as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
// Redacted Debug
impl std::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectId(***)")
    }
}

/// Strict Crypto Version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[must_use]
pub struct CryptoVersion(u32);

impl CryptoVersion {
    /// Create new Version
    pub const fn new(val: u32) -> Self {
        Self(val)
    }
    /// Get value
    #[must_use]
    pub fn value(&self) -> u32 {
        self.0
    }
}

/// Strict Nonce (24 bytes)
///
/// SECURITY: Intentionally does NOT implement Clone or Copy.
/// Once a nonce is consumed via `ConsumedNonce`, it cannot be reused.
/// To save nonce bytes before consumption, use `to_bytes()` which returns
/// an owned copy of the raw bytes (not a Nonce).
#[derive(PartialEq, Eq)]
#[repr(transparent)]
#[must_use]
pub struct Nonce([u8; 24]);

impl Nonce {
    /// Create new Nonce
    pub fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }
    /// Get reference to nonce bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
    /// Extract a raw byte copy for serialization BEFORE consuming.
    /// Returns owned bytes, not a Nonce — cannot be used for encryption.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 24] {
        self.0
    }
}
impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce(***)")
    }
}

/// Type-Safe Key Wrapper
#[repr(transparent)]
#[must_use]
pub struct Key<R: KeyRole, const N: usize>([u8; N], std::marker::PhantomData<R>);

impl<R: KeyRole, const N: usize> Key<R, N> {
    /// Create new Key
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes, std::marker::PhantomData)
    }

    /// Get Key bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<R: KeyRole, const N: usize> Zeroize for Key<R, N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<R: KeyRole, const N: usize> Drop for Key<R, N> {
    #[inline(never)] // Hardening: Prevent optimization of Drop
    fn drop(&mut self) {
        self.zeroize();
    }
}
// Redacted Debug for Keys
impl<R: KeyRole, const N: usize> std::fmt::Debug for Key<R, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key<Role>(***)")
    }
}

impl<R: KeyRole, const N: usize> Clone for Key<R, N> {
    fn clone(&self) -> Self {
        Self(self.0, std::marker::PhantomData)
    }
}

// Concrete Key Types
/// Key Encryption Key
pub type KeyKEK = Key<RoleKEK, 32>;
/// MAC Key
pub type KeyMK = Key<RoleMK, 32>;
/// Context Key
pub type KeyCK = Key<RoleCK, 32>;

/// User Root
pub type KeyUR = Key<RoleUR, 64>;
/// Recovery Root
pub type KeyRR = Key<RoleRR, 64>;
/// Master Root
pub type KeyMR = Key<RoleMR, 64>;
/// Context Root
pub type KeyCR = Key<RoleCR, 64>;

/// Strict Epoch Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
#[must_use]
pub struct Epoch(u64);

impl Epoch {
    /// Create new Epoch
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Get value
    #[must_use]
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Advance epoch (Checked Add)
    ///
    /// # Errors
    /// Returns `VaultError` on overflow.
    pub fn advance(&mut self) -> Result<(), VaultError> {
        self.0 = self
            .0
            .checked_add(1)
            .ok_or(VaultError::new(VaultErrorKind::CapacityExceeded))?;
        Ok(())
    }
}

// Re-export specific constants
pub use scb_vka_common::config::{
    ARGON2_OUTPUT_LEN, KEY_LEN, MAC_LEN, NONCE_LEN, SALT_LEN, TAG_LEN,
};
