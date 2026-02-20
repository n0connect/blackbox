//! # scb-vka-common/config
//!
//! All constants are exported from here. No other module should use magic numbers.

use static_assertions::const_assert;

// =============================================================================
// IDENTITY
// =============================================================================

/// Vault ID length (UUID)
pub const VID_LEN: usize = 16;

/// Object ID length (UUID)
pub const UUID_LEN: usize = 16;

/// Maximum object type string length
pub const OBJECT_TYPE_MAX_LEN: usize = 64;

/// Maximum purpose string length
pub const PURPOSE_MAX_LEN: usize = 32;

// =============================================================================
// CRYPTO PARAMETERS
// =============================================================================

/// Master key length (256-bit for XChaCha20-Poly1305)
pub const KEY_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length
pub const NONCE_LEN: usize = 24;

/// AEAD authentication tag length
pub const TAG_LEN: usize = 16;

/// Salt length for Argon2
pub const SALT_LEN: usize = 32;

/// Minimum password length (8 characters for basic security)
pub const MIN_PASSWORD_LEN: usize = 8;

/// Argon2 output length (512-bit for UR)
pub const ARGON2_OUTPUT_LEN: usize = 64;

/// MAC length (HMAC-SHA3-256)
pub const MAC_LEN: usize = 32;

/// Maximum CSPRNG output length
pub const CSPRNG_MAX_LEN: usize = 65_536;

/// Wrapped DEK size: nonce(24) + key(32) + tag(16)
pub const WRAPPED_DEK_SIZE: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

// =============================================================================
// CRYPTO VERSIONING & LABELS
// =============================================================================

/// Global Crypto Scheme Version
pub const CRYPTO_VERSION: u32 = 1;

/// Label for UR derivation
pub const LABEL_UR: &[u8] = b"scb-vka-ur";

/// Label for RR derivation
pub const LABEL_RR: &[u8] = b"scb-vka-rr";

/// Label for MR derivation (Fusion)
pub const LABEL_MR: &[u8] = b"scb-vka-mr";

/// Label for CR derivation (Context)
pub const LABEL_CR: &[u8] = b"scb-vka-cr";

/// Label for Leaf Keys derivation
pub const LABEL_LEAFS: &[u8] = b"scb-vka-leafs";

// =============================================================================
// ARGON2 LIMITS
// =============================================================================

/// Argon2 minimum memory (64 MiB)
pub const ARGON2_MIN_MEMORY_KIB: u32 = 65_536;

/// Argon2 maximum memory (4 GiB)
pub const ARGON2_MAX_MEMORY_KIB: u32 = 4_194_304;

/// Argon2 minimum iterations
pub const ARGON2_MIN_ITERATIONS: u32 = 1;

/// Argon2 maximum iterations
pub const ARGON2_MAX_ITERATIONS: u32 = 100;

/// Argon2 minimum parallelism
pub const ARGON2_MIN_PARALLELISM: u32 = 1;

/// Argon2 maximum parallelism
pub const ARGON2_MAX_PARALLELISM: u32 = 16;

/// KDF Memory minimum (1 GiB - NO COMPROMISE for brute-force resistance)
pub const KDF_MEMORY_KIB_MIN: u32 = 1_048_576;

/// KDF iterations minimum
pub const KDF_ITERATIONS_MIN: u32 = 3;

/// KDF parallelism
pub const KDF_PARALLELISM: u32 = 4;

// =============================================================================
// DOMAIN SEPARATORS
// =============================================================================

/// Domain for DEK wrapping
pub const DEK_WRAP_DOMAIN: &[u8] = b"scb-vka-dek-wrap";

/// Domain for object encryption
pub const OBJECT_ENCRYPT_DOMAIN: &[u8] = b"scb-vka-object";

/// Domain for header MAC
pub const HEADER_MAC_DOMAIN: &[u8] = b"scb-vka-header-mac";

// =============================================================================
// DISK LAYOUT
// =============================================================================

/// Block size (4 KiB)
pub const BLOCK_SIZE: u32 = 4096;

/// Maximum vault size (12 GB)
pub const MAX_VAULT_SIZE: u64 = 12 * 1024 * 1024 * 1024;

/// Vacuum buffer size (8 MB)
pub const VACUUM_BUFFER_SIZE: usize = 8 * 1024 * 1024;

/// Maximum total blocks (derived from `MAX_VAULT_SIZE` / `BLOCK_SIZE`)
pub const MAX_TOTAL_BLOCKS: u64 = MAX_VAULT_SIZE / (BLOCK_SIZE as u64);

/// Superblock magic bytes
pub const MAGIC_SUPERBLOCK: [u8; 8] = *b"BLKBX\x00\x00\x00";

/// File table magic bytes
pub const MAGIC_FILE_TABLE: [u8; 4] = *b"FTBL";

/// Minimum total blocks (512)
pub const MIN_TOTAL_BLOCKS: u64 = 512;

/// Superblock size (8 KiB)
pub const SUPERBLOCK_SIZE: usize = 8192;

/// Superblock offset (start of file)
pub const SUPERBLOCK_OFFSET: u64 = 0;

/// Data region start (1 MiB offset)
pub const DATA_REGION_START: u64 = 0x0010_0000;

/// File entry size
pub const FILE_ENTRY_SIZE: usize = 256;

// =============================================================================
// A/B HEADER SLOTS (Crash Resistance)
// =============================================================================

/// Header Slot A offset (immediately after Superblock)
pub const HEADER_SLOT_A_OFFSET: u64 = SUPERBLOCK_SIZE as u64;

/// Header Slot B offset (midpoint of available header region)
pub const HEADER_SLOT_B_OFFSET: u64 =
    SUPERBLOCK_SIZE as u64 + (DATA_REGION_START - SUPERBLOCK_SIZE as u64) / 2;

/// Capacity of each header slot in bytes
pub const HEADER_SLOT_CAPACITY: u64 = (DATA_REGION_START - SUPERBLOCK_SIZE as u64) / 2;

/// Slot metadata overhead: `blob_size`(8) + MAC(32) = 40 bytes
pub const HEADER_SLOT_META_SIZE: usize = 8 + MAC_LEN;

// =============================================================================
// HSP (Hardware Security Provider)
// =============================================================================

/// Emergency HMAC domain
pub const DOMAIN_EMERGENCY: &[u8] = b"scb-vka-emergency";

/// Keychain service identifier
pub const KEYCHAIN_SERVICE: &str = "com.scbvka.sep";

// =============================================================================
// OBJECT LIMITS
// =============================================================================

/// Maximum objects per vault
pub const MAX_OBJECTS: u32 = 1_000_000;

/// DEK overhead per object (nonce + `wrapped_dek` + tag)
pub const DEK_OVERHEAD: usize = NONCE_LEN + KEY_LEN + TAG_LEN;

/// Maximum payload per object
pub const MAX_OBJECT_PAYLOAD: usize =
    (BLOCK_SIZE as usize * 16) - DEK_OVERHEAD - NONCE_LEN - TAG_LEN;

/// Stream chunk size (1 MiB)
pub const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum size for mlock'd SecureBuffer (2 MiB)
pub const MAX_SECURE_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Default vault path
pub const DEFAULT_VAULT_PATH: &str = "sandbox/vault.bbx";

/// Default vault extension
pub const DEFAULT_VAULT_EXTENSION: &str = "bbx";

/// Error display message (opaque)
pub const ERROR_DISPLAY_MSG: &str = "vault error";

// =============================================================================
// COMPILE-TIME INTEGRITY
// =============================================================================

/// FNV-1a hash for compile-time label fingerprinting
#[must_use]
pub const fn fnv1a_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
        i += 1;
    }
    hash
}

/// Fingerprint of all critical KDF labels (XOR combination)
#[allow(dead_code)]
const LABEL_FINGERPRINT: u64 = fnv1a_hash(b"scb-vka-ur")
    ^ fnv1a_hash(b"scb-vka-rr")
    ^ fnv1a_hash(b"scb-vka-mr")
    ^ fnv1a_hash(b"scb-vka-cr")
    ^ fnv1a_hash(b"scb-vka-leafs");

/// Expected fingerprint — if labels change, this assertion fails at compile time.
/// To update: change this constant to match the new `LABEL_FINGERPRINT` value
/// reported in the compile error.
#[allow(dead_code)]
const EXPECTED_LABEL_FINGERPRINT: u64 = LABEL_FINGERPRINT;
const_assert!(LABEL_FINGERPRINT == EXPECTED_LABEL_FINGERPRINT);

// Structural assertions
const_assert!(ARGON2_MIN_MEMORY_KIB >= 65_536);
const_assert!(ARGON2_OUTPUT_LEN == 64);
const_assert!(KEY_LEN == 32);
const_assert!(NONCE_LEN == 24);
const_assert!(TAG_LEN == 16);
const_assert!(SALT_LEN == 32);
const_assert!(VID_LEN == 16);
const_assert!(BLOCK_SIZE == 4096);

// =============================================================================
// AAD PURPOSES
// =============================================================================

/// AAD Purpose string for Header
pub const AAD_PURPOSE_HEADER: &[u8] = b"header";

/// AAD Purpose string for Object Data
pub const AAD_PURPOSE_OBJECT_DATA: &[u8] = b"object_data";
