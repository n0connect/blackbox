//! # scb-vka-hsp
//!
//! Hardware Security Provider - Native hardware enclave integrations.
//!
//! ## Platform Support
//!
//! | Platform | Hardware | Implementation |
//! |----------|----------|----------------|
//! | macOS    | Secure Enclave (T2/M1/M2/M3) | P-256 ECDH key agreement |
//! | Linux    | TPM 2.0 | HMAC-SHA256 |
//! | Windows  | TPM 2.0 (TBS) | HMAC-SHA256 |
//!
//! ## Security Model
//!
//! The enclave acts as a physical gatekeeper in the key derivation chain:
//!
//! ```text
//! Password + Salt → Argon2id → UR (User Root)
//!                               ↓
//!                    ╔═══════════════════════╗
//!                    ║   HARDWARE ENCLAVE    ║
//!                    ║  UR + HW_KEY → MR     ║  ← Single visit
//!                    ║  (key never exported) ║
//!                    ╚═══════════════════════╝
//!                               ↓
//!                 MR + Context → CR → KEK/MK/CK
//! ```
//!
//! - The User Root (UR) derived from Argon2id is sent to the enclave
//! - The enclave combines UR with its non-exportable hardware key
//! - The resulting Master Root (MR) is returned
//! - The hardware key NEVER leaves the physical chip
//! - The chip is visited exactly ONCE per unlock operation
//!
//! ## Compile-Time Platform Enforcement
//!
//! This crate requires physical hardware security:
//! - macOS: Secure Enclave (T2 chip or Apple Silicon)
//! - Linux/Windows: TPM 2.0 module
//!
//! Compilation will fail on unsupported platforms.

#![deny(clippy::all)]
#![deny(unsafe_op_in_unsafe_fn)]

use scb_vka_common::error::VaultError;

/// Hardware Security Enclave trait
///
/// Implementations provide hardware-bound cryptographic operations
/// where the key material never leaves the physical security chip.
pub trait HardwareEnclave: Send + Sync {
    /// Sign (or HMAC) the User Root using the non-exportable hardware key.
    ///
    /// # Arguments
    /// * `ur` - The 64-byte User Root derived via Argon2id from password and salt
    ///
    /// # Returns
    /// The 64-byte Master Root (MR), which is the UR transformed by the hardware key.
    ///
    /// # Security Guarantees
    /// - The hardware key NEVER leaves the chip
    /// - The operation is performed entirely within the secure enclave
    /// - Only the result (MR) is returned to software
    fn sign_with_hardware_key(&self, ur: &[u8; 64]) -> Result<[u8; 64], VaultError>;

    /// Get the enclave provider name for diagnostics.
    fn provider_name(&self) -> &'static str;

    /// Explicitly initialize the hardware keys on platforms that require it.
    /// Returns Ok if already initialized or successful.
    fn init_hardware_keys(&self) -> Result<(), VaultError>;

    /// Check whether a hardware key already exists without creating one.
    fn has_hardware_key(&self) -> bool;

    /// Permanently delete the hardware-bound keys generated for this enclave.
    /// This is an irreversible operation and will make all vaults relying on
    /// this key unrecoverable.
    fn clear_hardware_keys(&self) -> Result<(), VaultError>;
}

// =============================================================================
// PLATFORM-SPECIFIC IMPLEMENTATIONS
// =============================================================================

// macOS: Apple Secure Enclave (T2/M1/M2/M3)
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOSEnclave;

// Linux & Windows: TPM 2.0
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod tpm;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use tpm::TpmEnclave;

// =============================================================================
// COMPILE-TIME PLATFORM ENFORCEMENT
// =============================================================================

// Fail compilation on unsupported platforms
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
compile_error!(
    "scb-vka-hsp requires hardware security support. \
    Supported platforms: macOS (Secure Enclave), Linux (TPM 2.0), Windows (TPM 2.0). \
    Your platform is not supported."
);

// =============================================================================
// FACTORY FUNCTION
// =============================================================================

/// Create the appropriate hardware enclave for the current platform.
///
/// # Platform Selection
/// - macOS: Apple Secure Enclave (SEP)
/// - Linux: TPM 2.0 via /dev/tpmrm0
/// - Windows: TPM 2.0 via TBS
///
/// # Panics
/// This function cannot fail at compile time on supported platforms.
/// Runtime errors (e.g., TPM not present) are returned when using the enclave.
pub fn create_platform_enclave() -> Box<dyn HardwareEnclave> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSEnclave::new())
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        Box::new(TpmEnclave::new())
    }
}

/// Check if hardware security is available on this system.
///
/// # Returns
/// - `Ok(provider_name)` if hardware security is available
/// - `Err(VaultError)` if hardware security is not available
///
/// This performs a lightweight probe without creating persistent keys.
pub fn probe_hardware_security() -> Result<&'static str, VaultError> {
    let enclave = create_platform_enclave();
    // Hardware availability will be intrinsically verified during vault creation/unlock.
    // Probing should remain purely informative to avoid persistent dummy keys.
    Ok(enclave.provider_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_creation() {
        // This should compile and create the appropriate enclave
        let enclave = create_platform_enclave();
        let name = enclave.provider_name();
        assert!(!name.is_empty());
    }

    #[test]
    #[ignore = "Requires physical hardware (TPM 2.0 or Secure Enclave)"]
    fn test_hardware_probe() {
        let result = probe_hardware_security();
        assert!(result.is_ok(), "Hardware security should be available");
        println!("Provider: {}", result.unwrap());
    }
}
