//! # scb-vka-common/util
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! - **Constant-time operations**: Timing attack önleme
//! - **Minimal**: Sadece gerekli yardımcı fonksiyonlar

use subtle::ConstantTimeEq;

/// Constant-time equality check for byte slices.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
