//! macOS HSP implementation.
//!
//! Uses macOS Hardware UUID as machine identifier.
//! The Hardware UUID is:
//! - Unique per Mac
//! - Persistent across OS reinstalls
//! - Only changes with logic board replacement
//!
//! Additionally stores a random salt in Keychain for added entropy.

use scb_vka_common::error::{VaultError, VaultErrorKind};
use security_framework::passwords::{get_generic_password, set_generic_password};
use std::process::Command;

use crate::{combine_identifiers, derive_secret, HardwareSecurityProvider};

const KEYCHAIN_SERVICE: &str = "com.blackbox.vault";
const KEYCHAIN_ACCOUNT: &str = "machine-salt";

/// macOS HSP using Hardware UUID + Keychain salt.
pub struct MacOSHSP {
    hardware_uuid: Option<Vec<u8>>,
}

impl MacOSHSP {
    pub fn new() -> Self {
        let hardware_uuid = Self::get_hardware_uuid();
        Self { hardware_uuid }
    }

    /// Get Hardware UUID via ioreg command.
    fn get_hardware_uuid() -> Option<Vec<u8>> {
        let output = Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(start) = line.find('"') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find('"') {
                        let uuid = &rest[..end];
                        // Skip the label, get actual UUID
                        if uuid.len() == 36 && uuid.contains('-') {
                            return Some(uuid.as_bytes().to_vec());
                        }
                    }
                }
            }
        }
        None
    }

    /// Get or create random salt stored in Keychain.
    fn get_or_create_salt(&self) -> Result<Vec<u8>, VaultError> {
        // Try to get existing salt
        if let Ok(salt) = get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
            if salt.len() == 32 {
                return Ok(salt.to_vec());
            }
        }

        // Generate new salt
        let mut salt = vec![0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        // Store in Keychain
        set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, &salt)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        Ok(salt)
    }
}

impl Default for MacOSHSP {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareSecurityProvider for MacOSHSP {
    fn get_machine_secret(&self) -> Result<[u8; 32], VaultError> {
        let hardware_uuid = self
            .hardware_uuid
            .as_ref()
            .ok_or_else(|| VaultError::new(VaultErrorKind::OperationFailed))?;

        let salt = self.get_or_create_salt()?;

        // Combine hardware UUID and salt
        let combined = combine_identifiers(&[hardware_uuid.as_slice(), salt.as_slice()]);

        // Derive final secret
        let secret = derive_secret(&*combined, b"macos-hsp-v1");
        Ok(*secret)
    }

    fn is_available(&self) -> bool {
        self.hardware_uuid.is_some()
    }

    fn provider_name(&self) -> &'static str {
        "macOS Hardware UUID + Keychain"
    }
}
