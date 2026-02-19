# BlackBox: Secure Vault Architecture

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Shell](https://img.shields.io/badge/Shell-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue?style=for-the-badge)

BlackBox is a Zero-Trust, Layered Security vault system designed for extreme data protection. It employs a 512-bit Cryptographic Pipeline, Memory Hardening, and Streaming I/O to ensure data confidentiality and integrity without compromising system resources.

---

## Security Warnings

**Read before use. These limitations are inherent to the design.**

1. **Crash-Resistant Design (A/B Header)**: The vault uses a dual-slot header (A/B ping-pong) to prevent corruption during unexpected power loss. If interrupted, the vault safely reverts to its last healthy state upon next unlock. No WAL is used to strictly maintain the Zero-Trust attack surface.

2. **No Password Change**: Password cannot be changed after vault creation. To change password, create a new vault and migrate data manually.

3. **Single Session Only**: Concurrent access from multiple processes is not supported and will corrupt the vault.

4. **COW Filesystem Limitation**: On filesystems like ZFS or APFS, secure deletion tools cannot guarantee erasure of *decrypted* files due to snapshots or block copying. Note: Snapshots of the *encrypted vault file* itself pose no security risk.

5. **Memory Constraints**: SecureBox uses mlock to prevent swapping. Systems with limited memory or strict ulimits may fail to allocate secure memory.

---

## Key Features

- **Layered Defense Strategy**: Security enforced at Kernel, Memory, Application, and Crypto levels.
- **512-bit Native Pipeline**: All key derivations use SHA3-512 and Argon2id.
- **Zero-Trust Architecture**: Every component assumes hostile environment.
- **Streaming I/O**: 1 MiB chunked pipeline for constant memory usage with full-file integrity (HMAC-SHA3-256).
- **Authenticated Storage**: XChaCha20-Poly1305 encryption with HMAC-SHA3-256 authentication.
- **Process Hardening**: Core dumps disabled, mlock for sensitive keys, zeroize-on-drop for all key material.
- **Cross-Platform**: Native support for Linux, macOS, and Windows with platform-specific security primitives.

---

## Architecture Overview

The system follows a strict dependency hierarchy:

1. **Level 0: Kernel & Memory (scb-vka-memory)**
   - SecureBox / SecureBuffer: Protects keys in RAM (mlock, zeroize-on-drop).
   - Process Hardening: Disables core dumps and debugging.
   - Secure Wipe: Multi-pass CSPRNG overwrite for deleted data.

2. **Level 1: Core Logic (scb-vka-common)**
   - Centralized Constants (Crypto versions, layout parameters, object limits).
   - Opaque Error types (no internal state leakage).
   - Structured Logging (VaultEvent, VaultLogger trait).
   - Constant-time utilities (subtle crate).

3. **Level 2: IO & Hardware (scb-vka-io)**
   - Layout: Manages .bbx binary file structure (Superblock, VaultHeader, FileTableEntry).
   - HSP: Hardware Security Provider abstraction (MockHSP for development).
   - Lock: RAII-based exclusive file locking (flock / LockFileEx).
   - SpaceManager: Bitmap-based block allocation.

4. **Level 3: Cryptography (scb-vka-crypto)**
   - CryptoEngine trait: The 512-bit pipeline engine.
   - Type-safe keys: `Key<Role, N>` with role separation (KEK, MK, CK).
   - ConsumedNonce: Linear type enforcing single-use nonce semantics.
   - AAD Context Binding: Strict AadBuilder with ObjectId, Version, Epoch, Purpose.
   - Streaming: encrypt_stream / decrypt_stream with per-chunk AEAD and global MAC.

5. **Level 4: Orchestration (scb-vka-orchestrator)**
   - VaultManager: Coordinates Keys + IO + Crypto.
   - Enforces Epoch progression and Context Binding.
   - Integer overflow protection on all size calculations.
   - Rollback safety with logged deallocation failures.

6. **Level 5: Interface (scb-vka-cli / scb-vka-shell)**
   - CLI: Scriptable vault operations (create, add, read, list, delete).
   - Shell: Interactive REPL exploration (ls, cat, rm, help, exit).

---

## Security Model

### The 512-bit Pipeline

Keys are derived in a strict one-way chain:

1. **User Root (UR)**: Derived from Password + Salt via Argon2id (64-byte output, min 64 MiB memory).
2. **Recovery Root (RR)**: Derived from HSP Machine Secret via HKDF-SHA3-512.
3. **Master Root (MR)**: Fusion of UR + RR via HMAC-SHA3-512 with version binding.
4. **Context Root (CR)**: MR + VaultID + Timestamp via HMAC-SHA3-512 with version binding.
5. **Leaf Keys**: KEK (32B), MK (32B), CK (32B) derived from CR via HKDF-SHA3-512.

### Zero-Trust Storage Layout

- **Superblock (8 KiB)**: Magic bytes, Salt, VID, Timestamp, Header location, Header MAC.
- **Auth Header**: Encrypted Metadata (VaultHeader + Bitmap + FileTable) with Encrypt-then-MAC.
- **Data Region (1 MiB offset)**: Per-object Wrapped DEK + Nonce + Encrypted Chunks + Global MAC.
- **Space Management**: Bitmap-based block allocation (4 KiB blocks).

### Consumable Nonces

Nonces are never reused. The ConsumedNonce type enforces consumption semantics at the type system level, requiring a fresh random nonce for every operation. Streaming operations use a deterministic counter scheme: `[128-bit random | 64-bit LE counter]`.

### Full-File Integrity

Every encrypted stream is authenticated with a global HMAC-SHA3-256 computed over all ciphertext chunks and their per-chunk Poly1305 tags. This MAC is appended after the final chunk and verified before any plaintext is considered valid, preventing truncation and splicing attacks.

---

## Usage

All commands prompt for password interactively. Password is never passed via command line.

### Create a Vault

```bash
./blackbox create --vault my.bbx
# Password: [hidden input]
# Confirm password: [hidden input]
```

### Add an Object

```bash
# From a file
./blackbox add --vault my.bbx --file document.pdf --purpose "backup"

# From inline data
./blackbox add --vault my.bbx --data "secret text" --purpose "note"
```

### Read an Object

```bash
# To file
./blackbox read --vault my.bbx --id <OBJECT_ID> --output restored.pdf

# To stdout
./blackbox read --vault my.bbx --id <OBJECT_ID>
```

### List Objects

```bash
./blackbox list --vault my.bbx
```

### Delete an Object

```bash
./blackbox delete --vault my.bbx --id <OBJECT_ID>
```

### Interactive Shell

```bash
./blackbox shell --vault my.bbx
```

Shell commands: `ls`, `cat <id>`, `rm <id>`, `help`, `exit`

---

## Compilation

```bash
cargo build --release
```

For development builds with reduced KDF memory (256 MiB instead of 1 GiB):

```bash
cargo build --features test-kdf
```

---

## Platform Support

| Platform | Memory Locking | File Locking | Core Dump Prevention | HSP |
|----------|---------------|-------------|---------------------|-----|
| Linux    | mlock/munlock | POSIX flock | setrlimit + PR_SET_DUMPABLE | TPM 2.0 / Machine-ID |
| macOS    | mlock/munlock | POSIX flock | setrlimit | IOKit / Keychain |
| Windows  | VirtualLock/VirtualUnlock | LockFileEx/UnlockFileEx | SetErrorMode | TPM 2.0 / MachineGUID |
| Other    | No-op (graceful fallback) | No-op | No-op | Compile error (requires implementation) |

---

## License

See LICENSE file.

---

## References

### Cryptographic Algorithms

| Algorithm | Usage | Specification |
|-----------|-------|---------------|
| XChaCha20-Poly1305 | AEAD encryption (objects, headers, DEK wrapping) | D. J. Bernstein, "ChaCha20 and Poly1305 for IETF Protocols," RFC 8439; Extended nonce construction per draft-irtf-cfrg-xchacha |
| Argon2id | Password-based key derivation (User Root) | RFC 9106 — "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications" |
| HKDF | Key expansion (Recovery Root, Leaf Keys) | RFC 5869 — "HMAC-based Extract-and-Expand Key Derivation Function" |
| HMAC-SHA3-512 | Key fusion (Master Root, Context Root) | FIPS 198-1 — "The Keyed-Hash Message Authentication Code" with SHA-3 (FIPS 202) |
| HMAC-SHA3-256 | Header MAC, Stream Integrity MAC | FIPS 198-1 with SHA-3 (FIPS 202) |
| SHA-3 (Keccak) | Hash family underlying HMAC and HKDF operations | FIPS 202 — "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions" |

### Security Standards

| Standard | Relevance |
|----------|-----------|
| NIST SP 800-132 | Password-Based Key Derivation — guides Argon2id parameter selection |
| NIST SP 800-38D | Recommendation for GCM Mode — informs AEAD tag handling patterns |
| NIST SP 800-56C Rev. 2 | Key Derivation Methods — informs HKDF usage for key expansion |
| NIST SP 800-108 Rev. 1 | KDF in Counter Mode — informs label/context separation design |
| NIST SP 800-131A Rev. 2 | Transitioning Cryptographic Algorithms — confirms algorithm strength adequacy |

### Memory and Process Security

| Technique | Reference |
|-----------|-----------|
| mlock / VirtualLock | POSIX.1-2017 (IEEE Std 1003.1); Win32 API Memory Management |
| Zeroization | NIST SP 800-88 Rev. 1 — "Guidelines for Media Sanitization"; secure_clear (C23) semantics |
| Core Dump Prevention | POSIX setrlimit(RLIMIT_CORE); Linux prctl(PR_SET_DUMPABLE); Windows SetErrorMode |
| Constant-Time Comparison | Timing attack mitigation per Brumley & Boneh (2003); implemented via subtle crate |

### Rust Cryptographic Libraries

| Crate | Version | Purpose |
|-------|---------|---------|
| chacha20poly1305 | 0.10 | XChaCha20-Poly1305 AEAD |
| argon2 | 0.5 | Argon2id password hashing |
| hkdf | 0.12 | HMAC-based Key Derivation |
| hmac | 0.12 | HMAC construction |
| sha3 | 0.10 | SHA-3 hash family (Keccak) |
| subtle | 2.5 | Constant-time operations |
| zeroize | 1.8 | Secure memory zeroing |
| aead | 0.5 | AEAD trait abstraction |
| getrandom | 0.2 | OS-level CSPRNG |
