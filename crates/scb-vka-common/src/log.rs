//! # scb-vka-common/log
//!
//! Structured logging for vault events.

use crate::config::VID_LEN;
use chrono::Local;
use colored::Colorize;
use std::io::{self, Write};

/// Vault event types for structured logging.
#[derive(Debug, Clone)]
pub enum VaultEvent {
    /// A new vault was created.
    VaultCreated {
        /// Vault ID
        vid: [u8; VID_LEN],
    },
    /// Vault was unlocked.
    VaultUnlocked {
        /// Vault ID
        vid: [u8; VID_LEN],
    },
    /// Vault was locked.
    VaultLocked {
        /// Vault ID
        vid: [u8; VID_LEN],
    },
    /// Object was added.
    ObjectAdded {
        /// Vault ID
        vid: [u8; VID_LEN],
        /// Object ID
        object_id: [u8; 16],
    },
    /// Object was read.
    ObjectRead {
        /// Vault ID
        vid: [u8; VID_LEN],
        /// Object ID
        object_id: [u8; 16],
    },
    /// Object was deleted.
    ObjectDeleted {
        /// Vault ID
        vid: [u8; VID_LEN],
        /// Object ID
        object_id: [u8; 16],
    },
    /// An error occurred.
    Error {
        /// Error message
        message: String,
    },
}

/// Log verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    /// No output
    #[default]
    Silent,
    /// Errors only
    Error,
    /// Informational
    Info,
    /// Verbose debug
    Debug,
}

/// Logger trait for vault operations.
pub trait VaultLogger: Send + Sync {
    /// Log a vault event.
    fn log(&self, event: &VaultEvent);
    /// Set log level.
    fn set_level(&mut self, level: LogLevel);
}

/// Simple stdout logger.
pub struct SimpleLogger {
    level: LogLevel,
}

impl SimpleLogger {
    /// Create a new logger with `Info` level.
    #[must_use]
    pub fn new() -> Self {
        Self {
            level: LogLevel::Info,
        }
    }
}

impl Default for SimpleLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultLogger for SimpleLogger {
    fn log(&self, event: &VaultEvent) {
        if self.level == LogLevel::Silent {
            return;
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let (level_str, msg_color) = match event {
            VaultEvent::Error { .. } => ("ERROR".red().bold(), true),
            _ => ("INFO".green().bold(), false),
        };

        let msg = match event {
            VaultEvent::VaultCreated { vid } => format!("Vault CREATED (VID={})", hex::encode(vid)),
            VaultEvent::VaultUnlocked { vid } => {
                format!("Vault UNLOCKED (VID={})", hex::encode(vid))
            }
            VaultEvent::VaultLocked { vid } => format!("Vault LOCKED (VID={})", hex::encode(vid)),
            VaultEvent::ObjectAdded { vid, object_id } => {
                format!(
                    "Object ADDED (VID={} OID={})",
                    hex::encode(vid),
                    hex::encode(object_id)
                )
            }
            VaultEvent::ObjectRead { vid, object_id } => {
                format!(
                    "Object READ (VID={} OID={})",
                    hex::encode(vid),
                    hex::encode(object_id)
                )
            }
            VaultEvent::ObjectDeleted { vid, object_id } => {
                format!(
                    "Object DELETED (VID={} OID={})",
                    hex::encode(vid),
                    hex::encode(object_id)
                )
            }
            VaultEvent::Error { message } => message.clone(),
        };

        let final_msg = if msg_color {
            msg.red().to_string()
        } else {
            msg
        };

        let _ = writeln!(io::stdout(), "[{timestamp}] [{level_str}] {final_msg}");
    }

    fn set_level(&mut self, level: LogLevel) {
        self.level = level;
    }
}

/// Null logger (no output).
pub struct NullLogger;

impl VaultLogger for NullLogger {
    fn log(&self, _event: &VaultEvent) {}
    fn set_level(&mut self, _level: LogLevel) {}
}
