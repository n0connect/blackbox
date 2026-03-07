# BlackBox: Secure Vault Architecture

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Shell](https://img.shields.io/badge/Shell-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational?style=for-the-badge)
![License](https://img.shields.io/badge/License-Apache--2.0-blue?style=for-the-badge)

BlackBox is a Zero-Trust, Layered Security vault system designed for extreme data protection. It employs a 512-bit Cryptographic Pipeline, Hardware Security Binding, Memory Hardening, and Streaming I/O to ensure data confidentiality and integrity.

> **⚠️ Disclaimer:** This is an experimental security research project. It intentionally offers no password recovery, no backup mechanism, and no multi-device support. Not intended for production use.

---

> **⚠️ WARNINGS**
>
> | Risk | Description |
> |------|-------------|
> | **Password Lost** | No recovery mechanism. Password cannot be reset or changed. If you lost ur password (permanent data loss) |
> | **Hardware Bound** | Vault is locked to this machine's TPM/Secure Enclave. Moving to another device or if the chip becomes unusable (permanent data loss). |
> | **Single Session** | Concurrent access will corrupt the vault irreversibly. |
> | **No Backup Key** | There is no master key, no backdoor, no recovery phrase. |
>
> **This is by design.** If you need password recovery or multi-device sync, this tool is NOT FOR YOU.

---

## Quick Overview

```
                        ┌─────────────────────────────────────┐
  Password ────────────▶│            Argon2id                 │
  Salt (from vault) ───▶│  (64 MB memory, 3 iterations)       │
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
│          │  ┌───────────────┐  │
│          │  │ Memory: 64 MB │  │
│          │  │ Iterations: 3 │  │
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

### Initialize Hardware (First Run)

Before creating any vaults, you must initialize the hardware security module. This is a one-time operation per device that creates a permanent, non-exportable key in the Secure Enclave or TPM.

```bash
./target/release/bb init
```

### Create a Vault

```bash
./target/release/bb create --vault my.bbx
# Password: [hidden input]
# Confirm password: [hidden input]
```

### Add an Object

```bash
# From a file
./target/release/bb add --vault my.bbx --file document.pdf --purpose "backup"

# From inline data
./target/release/bb add --vault my.bbx --data "secret text" --purpose "note"
```

### Read an Object

```bash
# To file
./target/release/bb read --vault my.bbx --id <OBJECT_ID> --output restored.pdf

# To stdout
./target/release/bb read --vault my.bbx --id <OBJECT_ID>
```

### List Objects

```bash
./target/release/bb list --vault my.bbx
```

### Delete an Object

```bash
./target/release/bb delete --vault my.bbx --id <OBJECT_ID>
```

### Compact Vault (Vacuum)

```bash
./target/release/bb vacuum --vault my.bbx
# Reclaims space from deleted objects
```

### Interactive Shell

```bash
./blackbox shell --vault my.bbx
```

Shell commands: `ls`, `cat <id>`, `rm <id>`, `help`, `exit`

---

## Compilation

BlackBox uses `make` to orchestrate the build process, especially on macOS where it must be properly signed and packaged into a `.app` bundle to access the Secure Enclave.

### Setup (macOS only)

1. Copy the example environment file:
   ```bash
   cp tools/macos_signing/.env.example .env
   ```
2. Edit `.env` and fill in your Apple Developer `TEAM_ID` and `PROVISION_PROFILE` path.

### Build

```bash
make build
```

This will run `cargo build --release`, package the binary, and strictly sign it with entitlements. A convenience symlink will be created at `./target/release/bb`.

> **Note:** KDF always uses minimum 64 MiB memory for brute-force resistance.

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

- **XChaCha20-Poly1305 (Cryptographic Algorithm)**: AEAD encryption (objects, headers, DEK wrapping) — D. J. Bernstein, "ChaCha20 and Poly1305 for IETF Protocols," RFC 8439; Extended nonce construction per draft-irtf-cfrg-xchacha
- **Argon2id (Cryptographic Algorithm)**: Password-based key derivation (User Root) — RFC 9106 "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications"
- **HKDF (Cryptographic Algorithm)**: Key expansion (Recovery Root, Leaf Keys) — RFC 5869 "HMAC-based Extract-and-Expand Key Derivation Function"
- **HMAC-SHA3-512 (Cryptographic Algorithm)**: Key fusion (Master Root, Context Root) — FIPS 198-1 "The Keyed-Hash Message Authentication Code" with SHA-3 (FIPS 202)
- **HMAC-SHA3-256 (Cryptographic Algorithm)**: Header MAC, Stream Integrity MAC — FIPS 198-1 with SHA-3 (FIPS 202)
- **SHA-3 (Keccak) (Cryptographic Algorithm)**: Hash family underlying HMAC and HKDF operations — FIPS 202 "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
- **Hash-to-Curve (Cryptographic Algorithm)**: Convert UR to P-256 point (macOS Secure Enclave ECDH) — RFC 9380 "Hashing to Elliptic Curves" (SSWU method for P-256)
- **ECDH (Cryptographic Algorithm)**: Key agreement inside Secure Enclave (macOS) — SEC 1 v2.0 "Elliptic Curve Cryptography"; NIST SP 800-56A Rev. 3
- **NIST SP 800-132 (Security Standard)**: Password-Based Key Derivation — guides Argon2id parameter selection
- **NIST SP 800-38D (Security Standard)**: Recommendation for GCM Mode — informs AEAD tag handling patterns
- **NIST SP 800-56C Rev. 2 (Security Standard)**: Key Derivation Methods — informs HKDF usage for key expansion
- **NIST SP 800-108 Rev. 1 (Security Standard)**: KDF in Counter Mode — informs label/context separation design
- **NIST SP 800-131A Rev. 2 (Security Standard)**: Transitioning Cryptographic Algorithms — confirms algorithm strength adequacy
- **mlock / VirtualLock (Memory and Process Security)**: POSIX.1-2017 (IEEE Std 1003.1); Win32 API Memory Management
- **Zeroization (Memory and Process Security)**: NIST SP 800-88 Rev. 1 "Guidelines for Media Sanitization"; secure_clear (C23) semantics
- **Core Dump Prevention (Memory and Process Security)**: POSIX setrlimit(RLIMIT_CORE); Linux prctl(PR_SET_DUMPABLE); Windows SetErrorMode
- **Constant-Time Comparison (Memory and Process Security)**: Timing attack mitigation per Brumley & Boneh (2003); implemented via subtle crate
- **chacha20poly1305 v0.10.x (Rust Crate)**: XChaCha20-Poly1305 AEAD
- **argon2 v0.5.x (Rust Crate)**: Argon2id password hashing
- **hkdf v0.12.x (Rust Crate)**: HMAC-based Key Derivation
- **hmac v0.12.x (Rust Crate)**: HMAC construction
- **sha3 v0.10.x (Rust Crate)**: SHA-3 hash family (Keccak)
- **subtle v2.5.x (Rust Crate)**: Constant-time operations
- **zeroize v1.8.x (Rust Crate)**: Secure memory zeroing
- **aead v0.5.x (Rust Crate)**: AEAD trait abstraction
- **getrandom v0.2.x (Rust Crate)**: OS-level CSPRNG
- **tss-esapi v7.5.x (Rust Crate)**: TPM 2.0 integration (Linux/Windows)
- **security-framework v2.11.x (Rust Crate)**: macOS Security.framework bindings (Secure Enclave ECDH)
- **p256 v0.13.x (Rust Crate)**: P-256 elliptic curve (hash-to-curve, ECDH)
- **elliptic-curve v0.13.x (Rust Crate)**: Elliptic curve traits (hash2curve feature)
