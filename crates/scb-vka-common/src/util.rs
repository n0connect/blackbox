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
    let mut res = a.len().ct_eq(&b.len());
    let max_len = if a.len() > b.len() { a.len() } else { b.len() };

    for i in 0..max_len {
        // Bitwise logic to get element or 0 if out of bounds, preventing branch prediction length leaks
        let a_valid = u8::from(i < a.len());
        let b_valid = u8::from(i < b.len());

        // Use conditional assignment without branching
        let a_byte = [0, a.get(i).copied().unwrap_or(0)][a_valid as usize];
        let b_byte = [0, b.get(i).copied().unwrap_or(0)][b_valid as usize];

        res &= a_byte.ct_eq(&b_byte);
    }

    bool::from(res)
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
