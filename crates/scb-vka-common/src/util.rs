//! # scb-vka-common/util
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! - **Constant-time operations**: Timing attack önleme
//! - **Minimal**: Sadece gerekli yardımcı fonksiyonlar

use subtle::ConstantTimeEq;

/// Constant-time equality check for byte slices.
///
/// # Timing Note
/// The length comparison is intentionally NOT constant-time.
/// When lengths differ the inputs are structurally invalid and the comparison
/// result (`false`) carries no secret information.  Only the byte-by-byte
/// content comparison needs to be constant-time to prevent oracle attacks.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Parse a hex-encoded string into a 16-byte object ID.
///
/// Accepts optional `0x` prefix. Returns `VaultError` on invalid input.
///
/// # Errors
/// - `InvalidInput`: Wrong length or non-hex characters.
pub fn parse_hex_object_id(s: &str) -> Result<[u8; 16], crate::error::VaultError> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 32 {
        return Err(crate::error::VaultError::new(
            crate::error::VaultErrorKind::InvalidInput,
        ));
    }
    let bytes = hex::decode(s)
        .map_err(|_| crate::error::VaultError::new(crate::error::VaultErrorKind::InvalidInput))?;
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes);
    Ok(buf)
}
