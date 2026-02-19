//! # scb-vka-hsp
//!
//! Real Hardware Security Provider implementations.
//!
//! Platform support:
//! - macOS: Hardware UUID + Keychain
//! - Linux: TPM 2.0 (requires tpm-linux feature) or Machine ID
//! - Windows: TPM 2.0 (requires tpm-windows feature) or Machine GUID
//!
//! ## Usage
//!
//! This module is NOT integrated into the main project.
//! It serves as a reference implementation for production deployments.
//!
//! ## Security Model
//!
//! The HSP provides a 32-byte machine-bound secret that:
//! - Is derived from hardware identifiers unique to this machine
//! - Is stored securely in OS credential storage
//! - Is consistent across reboots
//! - Cannot be easily transferred to another machine

#![deny(clippy::all)]

use scb_vka_common::error::VaultError;
use sha2::{Sha256, Digest};
use zeroize::Zeroizing;

/// Hardware Security Provider trait
pub trait HardwareSecurityProvider: Send + Sync {
    /// Retrieve the machine-bound secret (32 bytes).
    ///
    /// This secret is derived from hardware-protected keys and is:
    /// - Unique to this machine
    /// - Protected by secure storage
    /// - Consistent across reboots
    fn get_machine_secret(&self) -> Result<[u8; 32], VaultError>;

    /// Check if hardware security is available on this platform.
    fn is_available(&self) -> bool;

    /// Get provider name for diagnostics.
    fn provider_name(&self) -> &'static str;
}

// Platform-specific implementations
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOSHSP;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxHSP;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::WindowsHSP;

/// Select the best available HSP for the current platform.
pub fn create_platform_hsp() -> Box<dyn HardwareSecurityProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSHSP::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxHSP::new())
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsHSP::new())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        compile_error!("Unsupported platform for HSP")
    }
}

/// Derive a deterministic secret from hardware identity.
/// Used internally by HSP implementations.
pub(crate) fn derive_secret(hardware_id: &[u8], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"BLACKBOX_HSP_V1:");
    hasher.update(hardware_id);
    hasher.update(b":");
    hasher.update(context);

    let result = hasher.finalize();
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&result);
    secret
}

/// Combine multiple identifiers into a single hardware fingerprint.
pub(crate) fn combine_identifiers(ids: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"BLACKBOX_HWID_V1:");
    for (i, id) in ids.iter().enumerate() {
        hasher.update(&[i as u8]);
        hasher.update(id);
    }
    let result = hasher.finalize();
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(&result);
    output
}
