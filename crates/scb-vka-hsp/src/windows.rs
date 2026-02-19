//! Windows HSP implementation.
//!
//! Uses Windows machine identifiers:
//! - MachineGuid from registry (unique per Windows installation)
//! - SMBIOS UUID via WMI
//!
//! Combines identifiers with a stored random salt in user data.

use scb_vka_common::error::{VaultError, VaultErrorKind};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::{combine_identifiers, derive_secret, HardwareSecurityProvider};

/// Windows HSP using machine identifiers.
pub struct WindowsHSP {
    identifiers: Vec<Vec<u8>>,
}

impl WindowsHSP {
    pub fn new() -> Self {
        let mut identifiers = Vec::new();

        // Get MachineGuid from registry
        if let Some(guid) = Self::get_machine_guid() {
            identifiers.push(guid);
        }

        // Get SMBIOS UUID via WMIC
        if let Some(uuid) = Self::get_smbios_uuid() {
            identifiers.push(uuid);
        }

        // Get processor ID as additional identifier
        if let Some(cpu_id) = Self::get_processor_id() {
            identifiers.push(cpu_id);
        }

        Self { identifiers }
    }

    /// Get MachineGuid from Windows registry.
    fn get_machine_guid() -> Option<Vec<u8>> {
        let output = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "MachineGuid    REG_SZ    XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        for line in stdout.lines() {
            if line.contains("MachineGuid") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let guid = parts.last()?;
                    if guid.len() == 36 && guid.contains('-') {
                        return Some(guid.as_bytes().to_vec());
                    }
                }
            }
        }
        None
    }

    /// Get SMBIOS UUID via WMIC.
    fn get_smbios_uuid() -> Option<Vec<u8>> {
        let output = Command::new("wmic")
            .args(["csproduct", "get", "uuid"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let uuid = line.trim();
            if uuid.len() == 36 && uuid.contains('-') {
                return Some(uuid.as_bytes().to_vec());
            }
        }
        None
    }

    /// Get processor ID via WMIC.
    fn get_processor_id() -> Option<Vec<u8>> {
        let output = Command::new("wmic")
            .args(["cpu", "get", "processorid"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let id = line.trim();
            if !id.is_empty() {
                return Some(id.as_bytes().to_vec());
            }
        }
        None
    }

    /// Get salt storage path in AppData.
    fn get_salt_path() -> PathBuf {
        if let Some(appdata) = std::env::var_os("LOCALAPPDATA") {
            let path = PathBuf::from(appdata).join("BlackBox");
            let _ = fs::create_dir_all(&path);
            return path.join("machine-salt");
        }

        PathBuf::from("machine-salt")
    }

    /// Get or create random salt.
    fn get_or_create_salt(&self) -> Result<Vec<u8>, VaultError> {
        let salt_path = Self::get_salt_path();

        // Try to read existing salt
        if salt_path.exists() {
            if let Ok(salt) = fs::read(&salt_path) {
                if salt.len() == 32 {
                    return Ok(salt);
                }
            }
        }

        // Generate new salt
        let mut salt = vec![0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| VaultError::new(VaultErrorKind::OperationFailed))?;

        // Store salt
        let _ = fs::write(&salt_path, &salt);

        Ok(salt)
    }
}

impl Default for WindowsHSP {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareSecurityProvider for WindowsHSP {
    fn get_machine_secret(&self) -> Result<[u8; 32], VaultError> {
        if self.identifiers.is_empty() {
            return Err(VaultError::new(VaultErrorKind::OperationFailed));
        }

        let salt = self.get_or_create_salt()?;

        // Combine all identifiers
        let mut all_ids: Vec<&[u8]> = self.identifiers.iter().map(|v| v.as_slice()).collect();
        all_ids.push(salt.as_slice());

        let combined = combine_identifiers(&all_ids);

        // Derive final secret
        let secret = derive_secret(&*combined, b"windows-hsp-v1");
        Ok(*secret)
    }

    fn is_available(&self) -> bool {
        !self.identifiers.is_empty()
    }

    fn provider_name(&self) -> &'static str {
        "Windows Machine GUID"
    }
}
