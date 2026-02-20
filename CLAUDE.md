# BlackBox Codebase Guidelines

## Architecture
- 512-bit key derivation pipeline: Password → Argon2id → UR → Hardware Enclave → MR → CR → KEK/MK/CK
- Hardware binding: TPM 2.0 (Linux/Windows), Secure Enclave (macOS)
- No mock/fallback - unsupported platforms get compile_error!

## Crate Structure
- `scb-vka-hsp` - Hardware Security Provider (TPM/Secure Enclave)
- `scb-vka-crypto` - CryptoEngine, key derivation
- `scb-vka-memory` - SecureBox, mlock, zeroize
- `scb-vka-io` - Vault file layout, locking
- `scb-vka-orchestrator` - VaultManager coordination
- `scb-vka-common` - Shared types, errors, constants

## macOS Secure Enclave Gotchas
- ECDSA is NON-DETERMINISTIC (random nonce per signature) - DO NOT use for key derivation
- Use ECDH with hash-to-curve (RFC 9380 SSWU) for deterministic key derivation
- API name: `SecKeyCreateFromData` not `SecKeyCreateWithData`
- Use `kSecAttrApplicationLabel` not `kSecAttrApplicationTag` for key lookup
- Pin `core-foundation = "0.9"` to match security-framework compatibility

## Build Commands
- `cargo check -p scb-vka-hsp` - Check HSP compilation
- `cargo check --workspace` - Check full workspace
- `cargo clippy -p scb-vka-hsp` - Lint check
- `cargo build --release` - Production build

## Security Notes
- KDF always uses 1 GiB minimum memory (no test-kdf bypass)
- No mock HSP - real hardware required
- Mutex uses proper error handling (no unwrap panic)
- Minimum password length: 8 characters
- All u64→u32 casts use `try_from()` with error handling
- Header plaintext size validated against encryption overhead
- Vault size limited to MAX_TOTAL_BLOCKS

## Critical Invariants
- Epoch comparison: Use simple `>` (no wrapping arithmetic)
- Header blob size: plaintext + 112 bytes encryption overhead
- Block indices: Always checked before u32 cast
- Space manager: Enforces MAX_TOTAL_BLOCKS limit

## Permissions
- COMPILE ONLY - do not run tests or execute the binary
