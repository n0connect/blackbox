//! # scb-vka-io/hsp
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! Strict Mock Implementation.
//! Returns static Machine Secret (32 bytes).
//!

use scb_vka_common::error::VaultError;

/// Static Machine Secret (MOCK)
/// In a real system, this would be retrieved from the Secure Enclave.
pub const MOCK_MACHINE_SECRET: [u8; 32] = [0xCA; 32];

pub trait HardwareSecurityProvider {
    /// Get the machine-specific secret (32 bytes)
    /// This secret is then fed into HKDF to produce RR (512-bit).
    fn get_machine_secret(&self) -> Result<[u8; 32], VaultError>;
}

/// Mock HSP Provider
#[derive(Debug, Clone, Copy, Default)]
pub struct MockHSP;

impl MockHSP {
    pub fn new() -> Self {
        Self
    }
}

impl HardwareSecurityProvider for MockHSP {
    fn get_machine_secret(&self) -> Result<[u8; 32], VaultError> {
        Ok(MOCK_MACHINE_SECRET)
    }
}
