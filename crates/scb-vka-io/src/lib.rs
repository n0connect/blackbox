//! # scb-vka-io
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! Disk I/O ve Hardware Security Provider yönetimi:
//!
//! - **layout**: Disk yapıları (Superblock, FileEntry)
//! - **manager**: Block allocation (bitmap)
//! - **hsp**: Hardware Security Provider trait
//! - **sep**: macOS Secure Enclave implementasyonu
//!
//! ## DİSK LAYOUT
//!
//! ```text
//! Offset      Size    Content
//! ────────────────────────────────────
//! 0x000000    8KB     Superblock
//! 0x002000    ~1MB    Header Region (encrypted)
//! 0x100000    ...     Data Region (encrypted objects)
//! ```
//!
//! ## HEADER REGION
//!
//! Header Region şunları içerir (encrypted):
//! - VaultHeader struct
//! - Space bitmap
//! - File table entries
//!
//! ## OBJECT STORAGE
//!
//! Her obje Data Region'da şu formatta:
//! ```text
//! [wrapped_dek: 72 bytes][nonce: 24][ciphertext: N][tag: 16]
//! ```

#[cfg(feature = "mock-hsp")]
pub mod hsp;
#[cfg(not(feature = "mock-hsp"))]
/// HSP module — provide a real `HardwareSecurityProvider` implementation here.
pub mod hsp {}

pub mod layout;
pub mod manager;
pub mod lock;

pub use hsp::*;
pub use layout::*;
pub use manager::*;
pub use lock::*;
