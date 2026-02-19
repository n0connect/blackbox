//! Linux HSP implementation.
//!
//! Uses multiple machine identifiers:
//! - /etc/machine-id (systemd machine ID)
//! - /sys/class/dmi/id/product_uuid (SMBIOS UUID, requires root)
//! - /sys/class/dmi/id/board_serial (motherboard serial)
//!
//! Combines available identifiers with a stored random salt.

use scb_vka_common::error::{VaultError, VaultErrorKind};
use std::fs;
use std::path::Path;

use crate::{combine_identifiers, derive_secret, HardwareSecurityProvider};

const SALT_PATH: &str = "/var/lib/blackbox/.machine-salt";
const USER_SALT_PATH: &str = ".local/share/blackbox/machine-salt";

/// Linux HSP using machine identifiers.
pub struct LinuxHSP {
    identifiers: Vec<Vec<u8>>,
}

impl LinuxHSP {
    pub fn new() -> Self {
        let mut identifiers = Vec::new();

        // /etc/machine-id - always available on systemd systems
        if let Ok(id) = fs::read_to_string("/etc/machine-id") {
            let id = id.trim();
            if !id.is_empty() {
                identifiers.push(id.as_bytes().to_vec());
            }
        }

        // /sys/class/dmi/id/product_uuid - requires root
        if let Ok(uuid) = fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            let uuid = uuid.trim();
            if !uuid.is_empty() && uuid != "None" {
                identifiers.push(uuid.as_bytes().to_vec());
            }
        }

        // /sys/class/dmi/id/board_serial - motherboard serial
        if let Ok(serial) = fs::read_to_string("/sys/class/dmi/id/board_serial") {
            let serial = serial.trim();
            if !serial.is_empty() && serial != "None" {
                identifiers.push(serial.as_bytes().to_vec());
            }
        }

        // CPU info as fallback
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("Serial") || line.starts_with("model name") {
                    if let Some(value) = line.split(':').nth(1) {
                        let value = value.trim();
                        if !value.is_empty() {
                            identifiers.push(value.as_bytes().to_vec());
                            break;
                        }
                    }
                }
            }
        }

        Self { identifiers }
    }

    /// Get salt storage path (system-wide or user-specific).
    fn get_salt_path() -> std::path::PathBuf {
        // Try system-wide first
        if Path::new("/var/lib/blackbox").exists()
            || fs::create_dir_all("/var/lib/blackbox").is_ok()
        {
            return std::path::PathBuf::from(SALT_PATH);
        }

        // Fall back to user directory
        if let Some(home) = std::env::var_os("HOME") {
            let user_path = Path::new(&home).join(USER_SALT_PATH);
            if let Some(parent) = user_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            return user_path;
        }

        std::path::PathBuf::from(SALT_PATH)
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

        // Store salt with restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);

            if let Ok(mut file) = opts.open(&salt_path) {
                use std::io::Write;
                let _ = file.write_all(&salt);
            }
        }

        #[cfg(not(unix))]
        {
            let _ = fs::write(&salt_path, &salt);
        }

        Ok(salt)
    }
}

impl Default for LinuxHSP {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareSecurityProvider for LinuxHSP {
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
        let secret = derive_secret(&*combined, b"linux-hsp-v1");
        Ok(*secret)
    }

    fn is_available(&self) -> bool {
        !self.identifiers.is_empty()
    }

    fn provider_name(&self) -> &'static str {
        "Linux Machine ID"
    }
}
