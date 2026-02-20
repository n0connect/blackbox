# BlackBox: Secure Vault Architecture

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Shell](https://img.shields.io/badge/Shell-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue?style=for-the-badge)

BlackBox is a Zero-Trust, Layered Security vault system designed for extreme data protection. It employs a 512-bit Cryptographic Pipeline, Hardware Security Binding, Memory Hardening, and Streaming I/O to ensure data confidentiality and integrity.

---

## Quick Overview

```
                        ┌─────────────────────────────────────┐
  Password ────────────▶│            Argon2id                 │
  Salt (from vault) ───▶│  (64 MiB memory, 3 iterations)      │
                        └─────────────────┬───────────────────┘
                                          │
                                          ▼
                               ┌─────────────────────┐
                               │  User Root (UR)     │ 64 bytes
                               └──────────┬──────────┘
                                          │
          ╔═══════════════════════════════╧═══════════════════════════════╗
          ║                     HARDWARE ENCLAVE                          ║
          ║  ┌─────────────────────────────────────────────────────────┐  ║
          ║  │  macOS: Secure Enclave (ECDH)  │  Linux/Win: TPM 2.0    │  ║
          ║  └─────────────────────────────────────────────────────────┘  ║
          ║                                                               ║
          ║              HW_KEY + UR ──▶ MR  (key NEVER leaves chip)      ║
          ╚═══════════════════════════════╤═══════════════════════════════╝
                                          │
                                          ▼
                               ┌─────────────────────┐
                               │  Master Root (MR)   │ 64 bytes
                               └──────────┬──────────┘
                                          │
          VID + Timestamp ───────────────▶│
                                          ▼
                               ┌─────────────────────┐
                               │  Context Root (CR)  │ 64 bytes
                               └──────────┬──────────┘
                                          │
                               HKDF-SHA3-512 Expand
                     ┌────────────────────┼────────────────────┐
                     ▼                    ▼                    ▼
              ┌────────────┐       ┌────────────┐       ┌────────────┐
              │    KEK     │       │     MK     │       │     CK     │
              │  (32 byte) │       │  (32 byte) │       │  (32 byte) │
              └─────┬──────┘       └─────┬──────┘       └────────────┘
                    │                    │
                    │                    │
═════════════════════════════════════════════════════════════════════════════════════════
                                   VAULT UNLOCKED
═════════════════════════════════════════════════════════════════════════════════════════
                    │                    │
                    ▼                    ▼
          ┌─────────────────┐    ┌─────────────────┐
          │   Unwrap DEKs   │    │  Verify Header  │
          │   (per-object)  │    │      MAC        │
          └────────┬────────┘    └─────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │                      BLACKBOX VAULT (.bbx)                       │
    │  ┌────────────────────────────────────────────────────────────┐  │
    │  │  Object 1: [Wrapped DEK][Nonce][Encrypted Data][Tags]      │  │
    │  │  Object 2: [Wrapped DEK][Nonce][Encrypted Data][Tags]      │  │
    │  │  Object N: ...                                             │  │
    │  └────────────────────────────────────────────────────────────┘  │
    └──────────────────────────────────────────────────────────────────┘
```

---

## Security Warnings

**Read before use. These limitations are inherent to the design.**

1. **No Password Change**: Password cannot be changed. Create a new vault to change.

2. **Single Session Only**: Concurrent access will corrupt the vault.

3. **COW Filesystem Limitation**: On ZFS/APFS, secure deletion cannot guarantee erasure of decrypted files.

4. **Memory Constraints**: SecureBox uses mlock. Systems with limited memory may fail.

---

## Key Features

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DEFENSE IN DEPTH                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│   │   KERNEL    │  │   MEMORY    │  │  HARDWARE   │  │   CRYPTO    │    │
│   │   LEVEL     │  │   LEVEL     │  │   LEVEL     │  │   LEVEL     │    │
│   ├─────────────┤  ├─────────────┤  ├─────────────┤  ├─────────────┤    │
│   │ • Core dump │  │ • mlock()   │  │ • TPM 2.0   │  │ • Argon2id  │    │
│   │   disabled  │  │ • zeroize   │  │ • Secure    │  │ • XChaCha20 │    │
│   │ • No debug  │  │   on drop   │  │   Enclave   │  │ • SHA3-512  │    │
│   │ • File lock │  │ • SecureBox │  │ • HW-bound  │  │ • HKDF      │    │
│   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

- **512-bit Native Pipeline**: All key derivations use SHA3-512 and Argon2id
- **Hardware Security Binding**: TPM 2.0 (Linux/Windows) or Secure Enclave (macOS)
- **Zero-Trust Architecture**: Every component assumes hostile environment
- **Streaming I/O**: 1 MiB chunked encryption with constant memory usage
- **Authenticated Storage**: XChaCha20-Poly1305 + HMAC-SHA3-256

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CRATE DEPENDENCY GRAPH                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Level 5: Interface                                                    │
│   ┌───────────────────────────────────────────────────────────────┐     │
│   │  scb-vka-cli          scb-vka-shell                           │     │
│   │  (CLI commands)       (Interactive REPL)                      │     │
│   └─────────────────────────────┬─────────────────────────────────┘     │
│                                 │                                       │
│   Level 4: Orchestration        ▼                                       │
│   ┌───────────────────────────────────────────────────────────────┐     │
│   │  scb-vka-orchestrator                                         │     │
│   │  (VaultManager: coordinates Keys + IO + Crypto)               │     │
│   └───────────┬─────────────────┬─────────────────┬───────────────┘     │
│               │                 │                 │                     │
│   Level 3:    ▼       Level 2:  ▼       Level 2:  ▼                     │
│   ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐           │
│   │ scb-vka-crypto  │ │  scb-vka-io     │ │  scb-vka-hsp    │           │
│   │ (CryptoEngine)  │ │  (Layout/Lock)  │ │  (TPM/Enclave)  │           │
│   └────────┬────────┘ └────────┬────────┘ └────────┬────────┘           │
│            │                   │                   │                    │
│            └───────────────────┴───────────────────┘                    │
│                                │                                        │
│   Level 1: Core Logic          ▼                                        │
│   ┌───────────────────────────────────────────────────────────────┐     │
│   │  scb-vka-common                                               │     │
│   │  (Constants, Error types, Logging)                            │     │
│   └─────────────────────────────┬─────────────────────────────────┘     │
│                                 │                                       │
│   Level 0: Kernel & Memory      ▼                                       │
│   ┌───────────────────────────────────────────────────────────────┐     │
│   │  scb-vka-memory                                               │     │
│   │  (SecureBox, mlock, zeroize-on-drop)                          │     │
│   └───────────────────────────────────────────────────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Security Model

### The 512-bit Key Derivation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     KEY DERIVATION PIPELINE                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌──────────────┐    ┌──────────────┐                                  │
│   │   Password   │    │     Salt     │                                  │
│   │  (user input)│    │  (32 bytes)  │                                  │
│   └──────┬───────┘    └──────┬───────┘                                  │
│          │                   │                                          │
│          └─────────┬─────────┘                                          │
│                    ▼                                                    │
│          ┌─────────────────────┐                                        │
│          │      Argon2id       │                                        │
│          │  ┌───────────────┐  │                                        │
│          │  │ Memory: 64 MiB│  │                                        │
│          │  │ Iterations: 3 │  │                                        │
│          │  │ Parallelism: 4│  │                                        │
│          │  └───────────────┘  │                                        │
│          └──────────┬──────────┘                                        │
│                     │                                                   │
│                     ▼                                                   │
│          ┌─────────────────────┐                                        │
│          │  User Root (UR)     │◄─────── 64 bytes                       │
│          └──────────┬──────────┘                                        │
│                     │                                                   │
│                     │  ┌─────────────────────────────────────────┐      │
│                     │  │         HARDWARE ENCLAVE                │      │
│                     │  │  ┌─────────────────────────────────┐    │      │
│                     └──┼─▶│  TPM 2.0: HMAC(HW_KEY, UR)      │    │      │
│                        │  │  Enclave: ECDH(HW_KEY, H2C(UR)) │    │      │
│                        │  │  ─────────────────────────────  │    │      │
│                        │  │  Key NEVER leaves the chip!     │    │      │
│                        │  └───────────────┬─────────────────┘    │      │
│                        └──────────────────┼──────────────────────┘      │
│                                           │                             │
│                                           ▼                             │
│          ┌─────────────────────┐                                        │
│          │  Master Root (MR)   │◄─────── 64 bytes                       │
│          └──────────┬──────────┘                                        │
│                     │                                                   │
│      VID ──────────▶│                                                   │
│      Timestamp ────▶│                                                   │
│      Version ──────▶│                                                   │
│                     ▼                                                   │
│          ┌─────────────────────┐                                        │
│          │   HMAC-SHA3-512     │                                        │
│          └──────────┬──────────┘                                        │
│                     │                                                   │
│                     ▼                                                   │
│          ┌─────────────────────┐                                        │
│          │  Context Root (CR)  │◄─────── 64 bytes                       │
│          └──────────┬──────────┘                                        │
│                     │                                                   │
│                     ▼                                                   │
│          ┌─────────────────────┐                                        │
│          │   HKDF-SHA3-512     │                                        │
│          │   (Expand Phase)    │                                        │
│          └──────────┬──────────┘                                        │
│                     │                                                   │
│     ┌───────────────┼───────────────┐                                   │
│     │               │               │                                   │
│     ▼               ▼               ▼                                   │
│ ┌────────┐     ┌────────┐     ┌────────┐                                │
│ │  KEK   │     │   MK   │     │   CK   │                                │
│ │ 32 B   │     │  32 B  │     │  32 B  │                                │
│ └────────┘     └────────┘     └────────┘                                │
│     │               │               │                                   │
│     │               │               └──▶ (Reserved for future use)      │
│     │               │                                                   │
│     │               └───────────────────▶ Header MAC computation        │
│     │                                                                   │
│     └───────────────────────────────────▶ Wrap per-object DEKs          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Hardware Security Binding

```
┌────────────────────────────────────────────────────────────────────────┐
│                    PLATFORM-SPECIFIC HARDWARE SECURITY                 │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                         macOS                                   │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │                    SECURE ENCLAVE                         │  │   │
│  │  │                                                           │  │   │
│  │  │    UR (64 bytes)                                          │  │   │
│  │  │         │                                                 │  │   │
│  │  │         ▼                                                 │  │   │
│  │  │  ┌─────────────────────────────────────────────────────┐  │  │   │
│  │  │  │  hash-to-curve (RFC 9380 SSWU)                      │  │  │   │
│  │  │  │  UR → Valid P-256 point (deterministic)             │  │  │   │
│  │  │  └───────────────────────┬─────────────────────────────┘  │  │   │
│  │  │                          │                                │  │   │
│  │  │                          ▼ Peer Public Key                │  │   │
│  │  │  ┌─────────────────┐    ┌──────────────────────────────┐  │  │   │
│  │  │  │  P-256 Private  │───▶│  ECDH Key Agreement          │  │  │   │
│  │  │  │     Key         │    │  SecKeyCopyKeyExchangeResult │  │  │   │
│  │  │  │  (non-export)   │    │  ─────────────────────────── │  │  │   │
│  │  │  │                 │    │  Computed INSIDE the chip!   │  │  │   │
│  │  │  └─────────────────┘    └──────────────┬───────────────┘  │  │   │
│  │  │                                        │                  │  │   │
│  │  └────────────────────────────────────────┼──────────────────┘  │   │
│  │                                           │                     │   │
│  │       MR = SHA3-512(shared_secret)◄───────┘                     │   │
│  │                                                                 │   │
│  │  ✓ Private key NEVER leaves the Secure Enclave                  │   │
│  │  ✓ ECDH computed INSIDE the chip (same as TPM HMAC)             │   │
│  │  ✓ Deterministic: same UR = same P-256 point = same MR          │   │
│  │  ✓ Equivalent security level to TPM 2.0 HMAC                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Linux / Windows                              │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │                      TPM 2.0                              │  │   │
│  │  │  ┌─────────────────┐    ┌──────────────────────────────┐  │  │   │
│  │  │  │  HMAC Primary   │    │  context.hmac(HW_KEY, UR)    │  │  │   │
│  │  │  │     Key         │───▶│  Execute HMAC inside TPM     │  │  │   │
│  │  │  │  (non-export)   │    └──────────────┬───────────────┘  │  │   │
│  │  │  └─────────────────┘                   │                  │  │   │
│  │  └────────────────────────────────────────┼──────────────────┘  │   │
│  │                                           │                     │   │
│  │       MR = SHA3-512(HMAC_result)◄─────────┘                     │   │
│  │                                                                 │   │
│  │  ✓ HMAC computed INSIDE TPM chip                                │   │
│  │  ✓ Attacker cannot compute MR without TPM access                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │  Unsupported Platform → COMPILE ERROR (no mock/fallback)          │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Security Equivalence: macOS vs TPM

```
┌────────────────────────────────────────────────────────────────────────┐
│              EQUIVALENT SECURITY MODEL (Both Platforms)                │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ┌────────────────────────────┬────────────────────────────────────┐  │
│   │         TPM 2.0            │     Apple Secure Enclave           │  │
│   ├────────────────────────────┼────────────────────────────────────┤  │
│   │                            │                                    │  │
│   │  UR ──────────────────▶    │  UR ──────────────────▶            │  │
│   │        │                   │        │                           │  │
│   │        ▼                   │        ▼                           │  │
│   │  ╔═══════════════════╗     │  ┌─────────────────────┐           │  │
│   │  ║    TPM CHIP       ║     │  │  hash-to-curve      │           │  │
│   │  ║  ┌─────────────┐  ║     │  │  (RFC 9380 SSWU)    │           │  │
│   │  ║  │  HMAC-256   │  ║     │  └──────────┬──────────┘           │  │
│   │  ║  │  (HW_KEY)   │  ║     │             │                      │  │
│   │  ║  └─────────────┘  ║     │             ▼                      │  │
│   │  ╚════════╤══════════╝     │  ╔═══════════════════════╗         │  │
│   │           │                │  ║   SECURE ENCLAVE      ║         │  │
│   │           ▼                │  ║  ┌─────────────────┐  ║         │  │
│   │    32-byte result          │  ║  │  ECDH (HW_KEY)  │  ║         │  │
│   │           │                │  ║  └────────┬────────┘  ║         │  │
│   │           ▼                │  ╚═══════════╪═══════════╝         │  │
│   │    SHA3-512 expand         │              │                     │  │
│   │           │                │              ▼                     │  │
│   │           ▼                │       32-byte shared secret        │  │
│   │     MR (64 bytes)          │              │                     │  │
│   │                            │              ▼                     │  │
│   │                            │       SHA3-512 expand              │  │
│   │                            │              │                     │  │
│   │                            │              ▼                     │  │
│   │                            │        MR (64 bytes)               │  │
│   ├────────────────────────────┼────────────────────────────────────┤  │
│   │  ✓ Operation INSIDE chip   │  ✓ Operation INSIDE chip           │  │
│   │  ✓ HW_KEY never exported   │  ✓ HW_KEY never exported           │  │
│   │  ✓ Deterministic result    │  ✓ Deterministic result            │  │
│   │  ✓ Requires physical chip  │  ✓ Requires physical chip          │  │
│   └────────────────────────────┴────────────────────────────────────┘  │
│                                                                        │
│   Attack Surface Analysis:                                             │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  Without physical chip access:                                  │  │
│   │  • Attacker has: Password, Salt, UR (from memory dump)          │  │
│   │  • Attacker needs: HW_KEY (inside chip)                         │  │
│   │  • Result: CANNOT compute MR → CANNOT derive KEK → NO DECRYPT   │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Zero-Trust Storage Layout

```
┌────────────────────────────────────────────────────────────────────────┐
│                         VAULT FILE STRUCTURE                           │
│                            (.bbx format)                               │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Offset 0                                                              │
│  ┌───────────────────────────────────────────────────────┐             │
│  │                    SUPERBLOCK (8 KiB)                 │             │
│  │  ┌─────────────────────────────────────────────────┐  │             │
│  │  │  Magic: "BLACKBOX"  │  Version: u32             │  │             │
│  │  ├─────────────────────┼───────────────────────────┤  │             │
│  │  │  Salt (32 bytes)    │  VID (16 bytes)           │  │             │
│  │  ├─────────────────────┼───────────────────────────┤  │             │
│  │  │  Created Timestamp  │  Total Blocks             │  │             │
│  │  └─────────────────────┴───────────────────────────┘  │             │
│  └───────────────────────────────────────────────────────┘             │
│                                                                        │
│  Offset 8 KiB                                                          │
│  ┌───────────────────────────────────────────────────────┐             │
│  │               HEADER SLOT A (256 KiB)                 │             │
│  │  ┌─────────────────────────────────────────────────┐  │             │
│  │  │  Blob Size (8 B) │ MAC (32 B) │ Encrypted Blob  │  │             │
│  │  │  ┌─────────────────────────────────────────┐    │  │             │
│  │  │  │  Wrapped DEK │ Nonce │ Ciphertext │ Tag │    │  │             │
│  │  │  │  ┌─────────────────────────────────┐    │    │  │   A/B       │
│  │  │  │  │  VaultHeader (epoch, count)     │    │    │  │ Ping-Pong   │
│  │  │  │  │  Bitmap (space allocation)      │    │    │  │  Design     │
│  │  │  │  │  FileTable (object metadata)    │    │    │  │             │
│  │  │  │  └─────────────────────────────────┘    │    │  │             │
│  │  │  └─────────────────────────────────────────┘    │  │             │
│  │  └─────────────────────────────────────────────────┘  │             │
│  └───────────────────────────────────────────────────────┘             │
│                                                                        │
│  Offset 264 KiB                                                        │
│  ┌───────────────────────────────────────────────────────┐             │
│  │               HEADER SLOT B (256 KiB)                 │             │
│  │  (Same structure as Slot A - alternating writes)      │             │
│  └───────────────────────────────────────────────────────┘             │
│                                                                        │
│  Offset 1 MiB (DATA_REGION_START)                                      │
│  ┌───────────────────────────────────────────────────────┐             │
│  │                    DATA REGION                        │             │
│  │  ┌────────────────────────────────────────────────┐   │             │
│  │  │  OBJECT 1                                      │   │             │
│  │  │  ┌───────────┬───────────┬─────────────────┐   │   │             │
│  │  │  │WrappedDEK │  Nonce    │ Encrypted Data  │   │   │             │
│  │  │  │ (72 bytes)│ (24 bytes)│ (chunks + tags) │   │   │             │
│  │  │  └───────────┴───────────┴─────────────────┘   │   │             │
│  │  │  Stream: [Chunk1|Tag1][Chunk2|Tag2]...[MAC]    │   │             │
│  │  └────────────────────────────────────────────────┘   │             │
│  │                                                       │             │
│  │  ┌────────────────────────────────────────────────┐   │             │
│  │  │  OBJECT 2                                      │   │             │
│  │  │  (Same structure)                              │   │             │
│  │  └────────────────────────────────────────────────┘   │             │
│  │                          ...                          │             │
│  └───────────────────────────────────────────────────────┘             │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Streaming Encryption

```
┌────────────────────────────────────────────────────────────────────────┐
│                    STREAMING ENCRYPTION PIPELINE                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   Plaintext Stream                                                     │
│   ─────────────────────────────────────────────────────────────────▶   │
│   │ Chunk 0 │ Chunk 1 │ Chunk 2 │ Chunk 3 │ ... │ Chunk N │            │
│   │  1 MiB  │  1 MiB  │  1 MiB  │  1 MiB  │     │ ≤1 MiB  │            │
│   └────┬────┴────┬────┴────┬────┴────┬────┴─────┴────┬────┘            │
│        │         │         │         │               │                 │
│        ▼         ▼         ▼         ▼               ▼                 │
│   ┌─────────┬─────────┬─────────┬─────────┬─────┬─────────┐            │
│   │ Nonce+0 │ Nonce+1 │ Nonce+2 │ Nonce+3 │ ... │ Nonce+N │            │
│   └────┬────┴────┬────┴────┬────┴────┬────┴─────┴────┬────┘            │
│        │         │         │         │               │                 │
│        ▼         ▼         ▼         ▼               ▼                 │
│   ╔═════════╗ ╔═════════╗ ╔═════════╗ ╔═════════╗   ╔═════════╗        │
│   ║XChaCha20║ ║XChaCha20║ ║XChaCha20║ ║XChaCha20║   ║XChaCha20║        │
│   ║Poly1305 ║ ║Poly1305 ║ ║Poly1305 ║ ║Poly1305 ║   ║Poly1305 ║        │
│   ║  (DEK)  ║ ║  (DEK)  ║ ║  (DEK)  ║ ║  (DEK)  ║   ║  (DEK)  ║        │
│   ╚════╤════╝ ╚════╤════╝ ╚════╤════╝ ╚════╤════╝   ╚════╤════╝        │
│        │           │           │           │             │             │
│        ▼           ▼           ▼           ▼             ▼             │
│   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   ┌─────────┐        │
│   │Cipher+  │ │Cipher+  │ │Cipher+  │ │Cipher+  │   │Cipher+  │        │
│   │Tag (16B)│ │Tag (16B)│ │Tag (16B)│ │Tag (16B)│   │Tag (16B)│        │
│   └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘   └────┬────┘        │
│        │           │           │           │             │             │
│        └───────────┴───────────┴───────────┴─────────────┘             │
│                                    │                                   │
│                                    ▼                                   │
│                           ┌───────────────┐                            │
│                           │ HMAC-SHA3-256 │                            │
│                           │   (DEK key)   │                            │
│                           └───────┬───────┘                            │
│                                   │                                    │
│                                   ▼                                    │
│                           ┌───────────────┐                            │
│                           │   Global MAC  │                            │
│                           │   (32 bytes)  │                            │
│                           └───────────────┘                            │
│                                                                        │
│   Output: [CT0|Tag0][CT1|Tag1]...[CTn|Tagn][GlobalMAC]                 │
│                                                                        │
│   ✓ Per-chunk authentication (Poly1305)                                │
│   ✓ Full-stream integrity (HMAC-SHA3-256)                              │
│   ✓ No truncation/splicing attacks                                     │
│   ✓ Constant memory usage (1 chunk at a time)                          │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Nonce Management

```
┌────────────────────────────────────────────────────────────────────────┐
│                      NONCE STRUCTURE (24 bytes)                        │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ┌────────────────────────────────┬─────────────────────────────┐     │
│   │     Random Portion             │     Counter Portion         │     │
│   │        (16 bytes)              │        (8 bytes)            │     │
│   └────────────────────────────────┴─────────────────────────────┘     │
│                                                                        │
│   Single-shot operations:                                              │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │  CSPRNG(24 bytes) - fully random nonce                        │    │
│   └───────────────────────────────────────────────────────────────┘    │
│                                                                        │
│   Streaming operations:                                                │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │  Base: [CSPRNG(16 bytes)][0x0000000000000000]                 │    │
│   │                                                               │    │
│   │  Chunk 0: [random_16][counter = 0]                            │    │
│   │  Chunk 1: [random_16][counter = 1]                            │    │
│   │  Chunk 2: [random_16][counter = 2]                            │    │
│   │  ...                                                          │    │
│   │  Chunk N: [random_16][counter = N]                            │    │
│   └───────────────────────────────────────────────────────────────┘    │
│                                                                        │
│   ConsumedNonce Type:                                                  │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │  #[must_use]                                                  │    │
│   │  pub struct ConsumedNonce(Nonce);                             │    │
│   │                                                               │    │
│   │  // Nonce is MOVED (consumed) - cannot be reused              │    │
│   │  fn encrypt(nonce: ConsumedNonce, ...) { ... }                │    │
│   └───────────────────────────────────────────────────────────────┘    │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

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

### Compact Vault (Vacuum)

```bash
./blackbox vacuum --vault my.bbx
# Reclaims space from deleted objects
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

```
┌────────────┬─────────────────┬─────────────────┬───────────────────┬─────────────────┐
│  Platform  │  Memory Locking │  File Locking   │  Core Dump Prev.  │  Hardware Sec.  │
├────────────┼─────────────────┼─────────────────┼───────────────────┼─────────────────┤
│  Linux     │  mlock/munlock  │  POSIX flock    │  setrlimit +      │  TPM 2.0        │
│            │                 │                 │  PR_SET_DUMPABLE  │  (/dev/tpmrm0)  │
├────────────┼─────────────────┼─────────────────┼───────────────────┼─────────────────┤
│  macOS     │  mlock/munlock  │  POSIX flock    │  setrlimit        │  Secure Enclave │
│            │                 │                 │                   │  (T2/M1/M2/M3)  │
├────────────┼─────────────────┼─────────────────┼───────────────────┼─────────────────┤
│  Windows   │  VirtualLock    │  LockFileEx     │  SetErrorMode     │  TPM 2.0 (TBS)  │
├────────────┼─────────────────┼─────────────────┼───────────────────┼─────────────────┤
│  Other     │  COMPILE ERROR  │  COMPILE ERROR  │  COMPILE ERROR    │  COMPILE ERROR  │
│            │  (not supported)│  (not supported)│  (not supported)  │  (not supported)│
└────────────┴─────────────────┴─────────────────┴───────────────────┴─────────────────┘
```

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
| Hash-to-Curve | Convert UR to P-256 point (macOS Secure Enclave ECDH) | RFC 9380 — "Hashing to Elliptic Curves" (SSWU method for P-256) |
| ECDH | Key agreement inside Secure Enclave (macOS) | SEC 1 v2.0 — "Elliptic Curve Cryptography"; NIST SP 800-56A Rev. 3 |

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
| tss-esapi | 7.5 | TPM 2.0 integration (Linux/Windows) |
| security-framework | 2.11 | macOS Security.framework bindings (Secure Enclave ECDH) |
| p256 | 0.13 | P-256 elliptic curve (hash-to-curve, ECDH) |
| elliptic-curve | 0.13 | Elliptic curve traits (hash2curve feature) |
