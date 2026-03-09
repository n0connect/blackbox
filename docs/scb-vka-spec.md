# SCB-VKA v2: Multi-Secret Stateless Context-Bound Vault Key Architecture

**Specification Version:** 2.0.0  
**Status:** Draft  
**Author:** Kairos  
**Date:** 2025-02  
**Category:** Cryptographic Architecture Specification

---

## Abstract

This document defines SCB-VKA v2, a multi-secret, stateless, deterministic symmetric key management architecture for local encrypted storage systems. Unlike single-root architectures, SCB-VKA v2 requires the simultaneous presence of three independent secrets — a User Key (UK), a Recovery Secret (RS), and a dynamically computed Context Material (CM) — to derive any usable cryptographic key. No individual secret, nor any pair of secrets, is sufficient to recover any key material or encrypted data.

All key derivation is deterministic and stateless. No key material is stored at rest. Security relies exclusively on symmetric primitives, maintaining ≥128-bit strength under post-quantum threat models (Grover-bounded).

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology and Notation](#2-terminology-and-notation)
3. [Threat Model](#3-threat-model)
4. [Cryptographic Primitives](#4-cryptographic-primitives)
5. [Data Encoding](#5-data-encoding)
6. [Secret Architecture](#6-secret-architecture)
7. [Vault Initialization](#7-vault-initialization)
8. [Key Derivation Chain](#8-key-derivation-chain)
9. [Object Encryption](#9-object-encryption)
10. [Object Decryption](#10-object-decryption)
11. [Key Confirmation](#11-key-confirmation)
12. [Metadata Integrity](#12-metadata-integrity)
13. [Vault Migration](#13-vault-migration)
14. [Stateless Invariant](#14-stateless-invariant)
15. [Security Analysis](#15-security-analysis)
16. [Compromise Scenarios](#16-compromise-scenarios)
17. [Implementation Requirements](#17-implementation-requirements)
18. [Explicit Non-Goals](#18-explicit-non-goals)
19. [Compliance Criteria](#19-compliance-criteria)
20. [References](#20-references)

---

## 1. Introduction

### 1.1 Problem Statement

Single-root key architectures suffer from a fundamental fragility: compromise of the root secret exposes the entire vault. Even with deep derivation chains, the security of every derived key reduces to the security of a single point of failure. This is an architectural limitation, not a primitive limitation.

SCB-VKA v2 eliminates single-point-of-failure by requiring three cryptographically independent secrets for key derivation. Each secret occupies a distinct trust domain, and no trust domain is sufficient on its own.

### 1.2 Design Goals

| ID | Goal | Description |
|----|------|-------------|
| G-MULTISECRET | No single secret sufficiency | Any single secret, or any pair of two secrets, is computationally insufficient to derive any key. |
| G-DEADKEY | Stolen key is dead key | Any individual compromised secret is cryptographic garbage without the remaining secrets. |
| G-STATELESS | No stored key material | No derived key, intermediate value, or key-equivalent data is ever stored at rest. |
| G-DETERMINISTIC | Reproducible derivation | Identical inputs always produce identical outputs across all platforms. |
| G-CONTEXTBOUND | Environmental binding | Key derivation is bound to vault-specific, version-specific, non-portable context. |
| G-ISOLATED | Object-level isolation | Compromise of any object key reveals nothing about any other object key or any root material. |
| G-INDISTINGUISHABLE | Failure opacity | An attacker cannot determine which secret is wrong, missing, or corrupted. |
| G-POSTQUANTUM | Symmetric-only PQ resilience | ≥128-bit security under Grover-bounded quantum adversary. |
| G-OFFLINE | No network dependency | All operations are fully offline. |
| G-HW-ANCHORED | Hardware-anchored secret | At least one secret MUST reside behind a hardware trust boundary (Secure Enclave, TPM 2.0, or FIDO2 security key). |

### 1.3 Scope

This specification defines the secret architecture, key derivation chain, encryption/decryption procedures, encoding formats, and security properties. It does not define storage formats, transport protocols, user interface behavior, or RS provisioning mechanisms.

---

## 2. Terminology and Notation

### 2.1 Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

### 2.2 Symbols

| Symbol | Name | Trust Domain | Description |
|--------|------|--------------|-------------|
| UK | User Key | Human memory | User-provided passphrase |
| RS | Recovery Secret | Separate storage | Vault-specific high-entropy secret |
| CM | Context Material | Vault state | Deterministic, non-portable vault context |
| VS | Vault Salt | Public | Random salt, unique per vault |
| VID | Vault Identifier | Public | Unique vault identity (UUIDv4) |
| VCT | Vault Creation Time | Public | Unix timestamp at vault creation |
| VPH | Vault Policy Hash | Public | Integrity digest of vault policy |
| SV | Spec Version | Public | SCB-VKA specification version |
| UR | User Root | Volatile | Memory-hard derivative of UK |
| RR | Recovery Root | Volatile | Derivative of RS bound to vault |
| MR | Master Root | Volatile | Fusion of UR and RR (neither alone sufficient) |
| CR | Context Root | Volatile | MR bound to CM (final root) |
| KEK | Key Encryption Key | Volatile | Wraps/unwraps DEKs |
| MK | Metadata Key | Volatile | Protects vault header integrity |
| CK | Canary Key | Volatile | Key confirmation mechanism |
| DEK | Data Encryption Key | Volatile | Per-object encryption key |
| CTX | Object Context | Public | Unique identity of a single encrypted object |

### 2.3 Operators

| Notation | Meaning |
|----------|---------|
| `\|\|` | Concatenation |
| `⊕` | Bitwise XOR |
| `←` | Assignment |
| `CSPRNG(n)` | Cryptographically secure random generation of n bits |
| `TLV(tag, value)` | Tag-Length-Value encoding of a single field |

### 2.4 Trust Domain Separation

```
┌─────────────────────────────────────────────────────┐
│              TRUST DOMAIN MAP                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Domain A: HUMAN MEMORY         ──── UK             │
│  Domain B: HARDWARE SECURITY     ──── RS (sealed)       │
│           (SEP / TPM / FIDO2)                           │
│  Domain C: VAULT STATE          ──── CM             │
│  Domain D: VOLATILE MEMORY      ──── All derived    │
│  Domain E: PERSISTENT STORAGE   ──── Ciphertexts    │
│                                                     │
│  KEY INSIGHT:                                       │
│  Domains A, B, C never coexist at rest.             │
│  They converge only in Domain D, transiently.       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## 3. Threat Model

### 3.1 Attacker Capabilities

| ID | Capability |
|----|------------|
| AT-1 | Full read/write access to persistent storage (all ciphertexts, headers, metadata). |
| AT-2 | Knowledge of this specification and all public parameters. |
| AT-3 | Possession of ANY ONE secret: UK alone, RS alone, or CM alone. |
| AT-4 | Possession of ANY TWO secrets: (UK, RS), (UK, CM), or (RS, CM). |
| AT-5 | Ability to modify, reorder, duplicate, or delete stored objects. |
| AT-6 | Access to quantum computing (Grover-bounded: √N search). |
| AT-7 | Unlimited offline computation time. |

### 3.2 Attacker Limitations

| ID | Limitation |
|----|------------|
| AL-1 | Does NOT possess all three secrets simultaneously: UK ∧ RS ∧ CM. |
| AL-2 | Does NOT have continuous access to process memory during active session. |
| AL-3 | Cannot break the cryptographic primitives beyond known theoretical bounds. |

### 3.3 Critical Distinction from v1

SCB-VKA v1 collapses under AT-3 if the single secret (VK) is the compromised one. SCB-VKA v2 survives AT-3 and AT-4 by design. Only simultaneous possession of all three secrets (violating AL-1) compromises the vault.

---

## 4. Cryptographic Primitives

### 4.1 Primitive Selection

| Function | Primitive | Reference |
|----------|-----------|-----------|
| Password KDF | Argon2id | RFC 9106 |
| PRF / MAC | HMAC-SHA3-512 | RFC 2104 + FIPS 202 |
| KDF | HKDF-SHA3-512 | RFC 5869 + FIPS 202 |
| AEAD | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha |
| Hash | SHA3-512 | FIPS 202 |

### 4.2 Rationale

- **HMAC-SHA3-512** replaces KMAC256. HMAC with SHA3-512 is fully battle-tested and audited in the RustCrypto ecosystem (`hmac` + `sha3` crates). KMAC256's native customization string is replaced by domain separator prefixes in HMAC message inputs, providing equivalent domain separation with superior library maturity. Security equivalence: both are PRFs built on Keccak; HMAC's double-pass construction adds negligible overhead on modern hardware.
- **HKDF-SHA3-512** replaces HKDF-SHA-256. SHA3-512 provides a wider internal state (1600-bit Keccak permutation), eliminating theoretical multi-collision concerns. The 512-bit output provides headroom for multi-key extraction from a single HKDF call.
- **SHA3-512** for general-purpose hashing. Keccak sponge construction is structurally distinct from Merkle-Damgård (SHA2), providing algorithm diversity.
- **XChaCha20-Poly1305** retained from v1. 192-bit nonce eliminates birthday-bound collision under CSPRNG nonce generation.
- **Argon2id** retained from v1. Memory-hard, side-channel resistant hybrid.

### 4.3 Algorithm Agility

This specification does NOT support algorithm negotiation. All vaults MUST use exactly the primitives listed above. Changes are handled exclusively through vault migration (Section 13).

---

## 5. Data Encoding

### 5.1 Canonical TLV Format

All structured inputs to cryptographic functions MUST use Tag-Length-Value encoding:

```
┌────────┬────────┬────────┐
│  Tag   │ Length │  Value │
│ 1 byte │ 2 byte │ N byte │
└────────┴────────┴────────┘
```

- **Tag:** 1 byte, unsigned, unique field identifier.
- **Length:** 2 bytes, unsigned big-endian, byte length of Value.
- **Value:** Raw bytes.

### 5.2 Tag Assignments

| Tag | Field | Value Encoding |
|-----|-------|----------------|
| 0x01 | VID | 16 bytes, raw UUID |
| 0x02 | VCT | 8 bytes, big-endian Unix timestamp |
| 0x03 | RESERVED | (removed — formerly VPH) |
| 0x04 | SV | 2 bytes (major, minor) |
| 0x05 | RS_salt | 32 bytes |
| 0x10 | object_type | UTF-8, max 64 bytes |
| 0x11 | object_id | 16 bytes, raw UUID |
| 0x12 | object_version | 4 bytes, big-endian uint32 |
| 0x13 | purpose | UTF-8, max 32 bytes |
| 0x20 | cm_counter | 8 bytes, big-endian uint64 |
| 0x21 | RESERVED | (removed — formerly structural_hash) |
| 0xF0 | domain_separator | UTF-8 |

### 5.3 Encoding Rules

- Fields MUST appear in strictly ascending tag order.
- Duplicate tags are FORBIDDEN.
- No padding between fields.
- Big-endian for all integers.
- UTF-8 without null terminators.

### 5.4 Collision Resistance

TLV encoding as defined above is injective: distinct logical inputs always produce distinct byte sequences. Fixed tag ordering, explicit length fields, and no padding guarantee this property.

---

## 6. Secret Architecture

This section defines the three independent secrets and their trust domains.

### 6.1 Secret Independence Principle

The three secrets — UK, RS, and CM — MUST satisfy:

```
I(UK; RS) = 0          // Zero mutual information
I(UK; CM) = 0
I(RS; CM) = 0
```

No secret is derived from, correlated with, or dependent on any other secret. They originate from distinct trust domains and converge only transiently in volatile memory during vault operations.

### 6.2 UK — User Key (Domain A: Human Memory)

- A passphrase or password provided by the user.
- Stored only in human memory.
- Entropy depends on user behavior (see A6).
- Processed through Argon2id to produce UR.

### 6.3 RS — Recovery Secret (Domain B: Hardware Security Boundary)

- A 256-bit high-entropy value generated by CSPRNG at vault creation.
- MUST be sealed inside the platform's Hardware Security Provider (HSP).
- RS never leaves the hardware boundary in plaintext. The HSP performs HMAC/KDF operations on RS internally.
- At vault unlock, the implementation requests a derived response from the HSP. The result (RS_response) replaces raw RS in the derivation chain.
- MUST NOT be exportable, copyable, or readable in raw form after initial sealing.
- Backup mechanism: at vault creation, RS is displayed once as a BIP-39 emergency recovery mnemonic before sealing. This mnemonic is the ONLY recovery path if hardware fails.
- Purpose: eliminates single-point-of-failure and removes user responsibility for secret storage. Even if UK is compromised, RS remains sealed inside hardware silicon.

### 6.3.1 Hardware Security Provider (HSP) Abstraction

The specification defines a platform-agnostic HSP interface. Each platform maps to a concrete backend:

```
┌──────────────────────────────────────────────────────────────┐
│              HARDWARE SECURITY PROVIDER (HSP)                │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ABSTRACT INTERFACE:                                         │
│    HSP.seal(secret, policy)    → handle                      │
│    HSP.hmac(handle, data)      → response                    │
│    HSP.destroy(handle)         → void                        │
│                                                              │
│  PLATFORM BACKENDS (implementation priority order):          │
│                                                              │
│  ┌────────────┬──────────────────┬────────────────────────┐  │
│  │ Priority   │ Platform         │ Backend                │  │
│  ├────────────┼──────────────────┼────────────────────────┤  │
│  │ 1 (first)  │ macOS / iOS      │ Secure Enclave (SEP)   │  │
│  │ 2          │ Linux            │ TPM 2.0 (tpm2-tss)     │  │
│  │ 3          │ Windows          │ TPM 2.0 (TBS API)      │  │
│  │ fallback   │ any              │ USB Security Key       │  │
│  │            │                  │ (FIDO2 hmac-secret)    │  │
│  └────────────┴──────────────────┴────────────────────────┘  │
│                                                              │
│  INVARIANT: Regardless of backend, RS never exists in        │
│  host memory after sealing. All backends MUST provide        │
│  hardware-isolated HMAC capability.                          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 6.3.2 macOS Secure Enclave Backend (Priority 1)

```
┌─────────────────────────────────────────────────────────────┐
│             macOS SECURE ENCLAVE (SEP) BACKEND              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  VAULT CREATION:                                            │
│  1. RS ← CSPRNG(256)                                       │
│  2. Display RS as BIP-39 mnemonic (one-time backup)         │
│  3. Generate SEP-bound key:                                 │
│     sep_key = SecKeyCreateRandomKey(                        │
│       kSecAttrKeyTypeECSECPrimeRandom,                      │
│       kSecAttrKeySizeInBits: 256,                           │
│       kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,        │
│       kSecAttrAccessControl: biometryOrPasscode             │
│     )                                                       │
│  4. Encrypt RS under SEP key:                               │
│     sealed_RS = SecKeyCreateEncryptedData(sep_key, RS)      │
│  5. Store sealed_RS in Keychain (kSecAttrAccessible:        │
│     kSecAttrAccessibleWhenUnlockedThisDeviceOnly)           │
│  6. Zeroize RS from host memory                             │
│                                                             │
│  VAULT UNLOCK (normal):                                     │
│  1. challenge = SHA3-512(VID || VS || session_nonce)         │
│  2. Retrieve sealed_RS from Keychain                        │
│  3. RS_temp = SecKeyCreateDecryptedData(sep_key, sealed_RS) │
│  4. RS_response = HMAC-SHA3-512(key=RS_temp,               │
│                    msg="scb-vka-sep-v2" || challenge)       │
│  5. Zeroize RS_temp immediately                             │
│  6. RS_response enters derivation chain as RR input         │
│                                                             │
│  NOTE: SEP does not natively support HMAC on arbitrary      │
│  sealed data. Therefore RS is briefly decrypted in host     │
│  memory for HMAC computation, then immediately zeroized.      │
│  This is a known trade-off vs TPM's internal HMAC.          │
│  The exposure window is minimized to microseconds.          │
│                                                             │
│  BIOMETRIC GATE: SEP key access requires Touch ID / Face ID │
│  or device passcode, adding a physical presence factor.     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3.3 TPM 2.0 Backend (Priority 2: Linux / Priority 3: Windows)

```
┌─────────────────────────────────────────────────────────────┐
│                  TPM 2.0 BACKEND                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  VAULT CREATION:                                            │
│  1. RS ← CSPRNG(256)                                       │
│  2. Display RS as BIP-39 mnemonic (one-time backup)         │
│  3. TPM2_Create(parent=SRK, sensitive=RS, policy=auth)      │
│  4. Zeroize RS from host memory                             │
│  5. Store TPM object handle in vault header                 │
│                                                             │
│  VAULT UNLOCK (normal):                                     │
│  1. challenge = SHA3-512(VID || VS || session_nonce)         │
│  2. RS_response = TPM2_HMAC(handle=RS_handle,               │
│                              data=challenge,                │
│                              auth=TPM_auth_policy)          │
│  3. RS_response enters derivation chain as RR input         │
│                                                             │
│  ADVANTAGE: RS never leaves TPM silicon, even transiently.  │
│  TPM performs HMAC internally — zero host memory exposure.  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3.4 USB Security Key Fallback (FIDO2 hmac-secret)

```
┌─────────────────────────────────────────────────────────────┐
│            USB SECURITY KEY FALLBACK                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  For platforms without TPM or Secure Enclave.               │
│  Uses FIDO2 hmac-secret extension (e.g., YubiKey 5).       │
│                                                             │
│  VAULT CREATION:                                            │
│  1. credential = FIDO2_MakeCredential(rp="scb-vka",        │
│                    extensions={hmac-secret: true})           │
│  2. RS derived from hmac-secret during registration         │
│  3. Display BIP-39 backup mnemonic                          │
│  4. Store credential_id in vault header                     │
│                                                             │
│  VAULT UNLOCK:                                              │
│  1. challenge = SHA3-512(VID || VS || session_nonce)         │
│  2. RS_response = FIDO2_GetAssertion(credential_id,         │
│                    extensions={hmac-secret: challenge})      │
│  3. RS_response enters derivation chain as RR input         │
│                                                             │
│  NOTE: Requires physical touch on the key (user presence).  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3.5 Emergency Recovery (All Platforms)

```
┌─────────────────────────────────────────────────────────────┐
│              EMERGENCY RECOVERY PATH                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  When hardware fails (dead TPM, lost YubiKey, broken SEP):  │
│                                                             │
│  1. User provides BIP-39 mnemonic → RS_raw                  │
│  2. challenge = SHA3-512(VID || VS || session_nonce)         │
│  3. RS_response = HMAC-SHA3-512(key=RS_raw,                 │
│                    msg="scb-vka-emergency-v2" || challenge)  │
│  4. RS_response enters derivation chain as RR input         │
│  5. Vault migration REQUIRED: re-seal RS to new hardware    │
│                                                             │
│  WARNING: Emergency recovery temporarily places RS_raw      │
│  in host memory. Migration to new hardware MUST be          │
│  performed immediately after emergency unlock.              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3.6 HSP Authorization Policy

- macOS: Secure Enclave key access MUST require biometry (Touch ID / Face ID) or device passcode via `SecAccessControl`.
- TPM: Access MUST require HMAC session or password session. Implementations SHOULD use `TPM2_PolicyPCR` for measured boot binding.
- FIDO2: Physical user presence (touch) is inherent to the protocol.
- All backends: failed authentication attempts MUST NOT reveal whether RS exists or is valid.

### 6.4 CM — Context Material (Domain C: Vault State)

CM is a deterministic, non-portable digest of the vault's structural state:

```
CM = SHA3-512(
    TLV(0x01, VID)               ||
    TLV(0x02, VCT)               ||
    TLV(0x04, SV)                ||
    TLV(0x20, epoch)
)
```

Where:

- `epoch` is the sole mutable input to CM and is managed by the Volume Format Specification (superblock).
- Object integrity is guaranteed by per-object AEAD, encrypted index, and encrypted BAM; no separate structural hash feeds CM.

**Properties of CM:**

- Deterministic: same vault state always produces same CM.
- Tamper-evident: epoch is protected by dual-superblock CRC and Header MAC.
- Minimal: only immutable fields + atomic epoch counter feed CM.

### 6.5 Why Three Secrets?

```
┌─────────────────────────────────────────────────────────────┐
│              COMPROMISE MATRIX                              │
├──────────────────┬──────────────────────────────────────────┤
│  Compromised     │  Attacker's Position                    │
├──────────────────┼──────────────────────────────────────────┤
│  UK alone        │  Must brute-force RS (256-bit) + know   │
│                  │  exact vault state for CM.              │
│                  │  Cost: computationally infeasible.      │
├──────────────────┼──────────────────────────────────────────┤
│  RS alone        │  RS is sealed in hardware (SEP/TPM/     │
│                  │  FIDO2), cannot be extracted without     │
│                  │  invasive physical attack. Even then,    │
│                  │  must brute-force UK (Argon2id) +        │
│                  │  reconstruct CM.                         │
│                  │  Cost: Argon2id wall + CM uncertainty.   │
├──────────────────┼──────────────────────────────────────────┤
│  CM alone        │  Must brute-force UK through Argon2id   │
│                  │  + brute-force RS (256-bit).            │
│                  │  Cost: computationally infeasible.      │
├──────────────────┼──────────────────────────────────────────┤
│  UK + RS         │  Must reconstruct exact CM.             │
│                  │  Requires precise vault state.          │
│                  │  Cost: state reconstruction attack.     │
├──────────────────┼──────────────────────────────────────────┤
│  UK + CM         │  Must brute-force RS (256-bit).         │
│                  │  Cost: 2^256 (2^128 post-quantum).      │
│                  │  DEAD.                                  │
├──────────────────┼──────────────────────────────────────────┤
│  RS + CM         │  Must brute-force UK through Argon2id.  │
│                  │  Cost: Argon2id memory-hard wall.       │
│                  │  Depends on UK entropy.                 │
├──────────────────┼──────────────────────────────────────────┤
│  UK + RS + CM    │  Full compromise. Vault is open.        │
│                  │  This is the ONLY path.                 │
└──────────────────┴──────────────────────────────────────────┘
```

---

## 7. Vault Initialization

### 7.1 Generated Parameters

At vault creation:

```
VS      ← CSPRNG(256)                        // Vault Salt: 32 bytes
RS      ← CSPRNG(256)                        // Recovery Secret: 32 bytes
RS_salt ← CSPRNG(256)                        // RS processing salt: 32 bytes
VID     ← UUIDv4()                           // Vault Identifier
VCT     ← current_unix_timestamp()           // Creation Time
SV      ← (0x02, 0x00)                       // Spec Version v2.0
```

### 7.2 Vault Policy Blob

Deterministic canonical serialization of:

- Argon2id parameters (memory, iterations, parallelism)
- Maximum object size
- AEAD identifier string

Serialization format is implementation-defined but MUST be documented and deterministic.

### 7.3 RS Provisioning and Hardware Sealing

At vault creation:

1. RS ← CSPRNG(256).
2. RS MUST be displayed as a BIP-39 mnemonic for one-time emergency backup.
3. RS MUST be sealed to the platform HSP via the appropriate backend (Section 6.3).
4. HSP handle/reference MUST be stored in the vault header.
5. RS MUST be zeroized from host memory immediately after sealing.
6. The implementation MUST NOT offer to "skip hardware sealing" or store RS in software.
7. If no supported HSP is available, vault creation MUST fail with an explicit error.

### 7.4 Vault Header

```
┌──────────────────────────────────────────┐
│             VAULT HEADER                 │
├──────────────────────────────────────────┤
│  Magic Bytes: "SCBVKA02"               │   8 bytes
│  VS  (Vault Salt)                       │  32 bytes
│  HSP Backend Identifier           │  1 byte
│  HSP Handle / Reference           │  variable (max 128 bytes)
│  RS_salt (RS processing salt)     │  32 bytes
│  VID (Vault Identifier)                 │  16 bytes
│  VCT (Creation Timestamp)              │   8 bytes
│  VPH (Policy Hash)                      │  64 bytes
│  SV  (Spec Version)                     │   2 bytes
│  epoch (synced with volume superblock)  │   8 bytes
│  Header MAC                             │  64 bytes
├──────────────────────────────────────────┤
│  Canary Object                          │  variable
├──────────────────────────────────────────┤
│  Wrapped DEK Table                      │  variable
├──────────────────────────────────────────┤
│  Encrypted Objects                      │  variable
└──────────────────────────────────────────┘
```

---

## 8. Key Derivation Chain

### 8.1 Architecture Overview

```
UK (human memory)          RS (separate storage)          CM (vault state)
 │                          │                              │
 ▼                          ▼                              │
UR = Argon2id(UK, VS)      RR = HKDF(RS, RS_salt)        │
 │                          │                              │
 ▼                          ▼                              │
 └──────────┬───────────────┘                              │
            ▼                                              │
  MR = HMAC-SHA3-512(key=UR, msg="scb-vka-fusion-v2" || RR)    │
            │                                              │
            ▼                                              ▼
  CR = HMAC-SHA3-512(key=MR, msg="scb-vka-context-v2" || CM)
            │
            ├──► KEK = HKDF(CR, info="scb-vka-kek-v2",    len=32)
            ├──► MK  = HKDF(CR, info="scb-vka-meta-v2",   len=32)
            └──► CK  = HKDF(CR, info="scb-vka-canary-v2", len=32)
```

### 8.2 Layer 1 — Independent Root Extraction

**8.2.1 User Root (UR)**

```
UR = Argon2id(
    password    = UK,
    salt        = VS,
    memory      = 1048576,       // 1 GiB (MINIMUM)
    iterations  = 3,             // MINIMUM
    parallelism = 4,             // FIXED
    tag_length  = 64             // 512 bits
)
```

**Requirements:**

- UK MUST be UTF-8 encoded, no BOM, no null terminator.
- Memory minimum is 1 GiB (increased from v1's 512 MiB) to reflect modern hardware capabilities and increase attack cost.
- Output is 512 bits to provide adequate entropy for HMAC-SHA3-512 (fusion) keying.

**8.2.2 Recovery Root (RR)**

```
RR = HKDF-SHA3-512(
    IKM  = RS_response,              // TPM2_HMAC output (normal) or HMAC-SHA3-512 output (emergency)
    salt = RS_salt,
    info = "scb-vka-recovery-v2",
    len  = 64                        // 512 bits
)
```

**Requirements:**

- In normal operation, RS_response is the output of `TPM2_HMAC(RS, challenge)`. RS never leaves TPM silicon.
- In emergency recovery, RS_response is `HMAC-SHA3-512(key=RS_raw, msg="scb-vka-emergency-v2" || challenge)` where RS_raw is reconstructed from BIP-39 mnemonic.
- Both paths produce a 512-bit input to HKDF, maintaining equivalent entropy.
- RS_salt binds RR to this specific vault, preventing RS reuse across vaults from producing identical RR values.

### 8.3 Layer 2 — Multi-Secret Fusion

```
MR = HMAC-SHA3-512(
    key              = UR,                           // 512 bits
    msg              = "scb-vka-fusion-v2" || RR     // domain separator || 512 bits
)
```

Output: 512 bits (64 bytes).

**Critical Security Property:**

MR cannot be computed without BOTH UR and RR. HMAC-SHA3-512's security as a PRF guarantees that:

- Given only UR (knowing UK but not RS): MR is indistinguishable from random.
- Given only RR (knowing RS but not UK): MR is indistinguishable from random.
- The domain separator prefix "scb-vka-fusion-v2" provides domain separation from all other HMAC-SHA3-512 uses in the protocol.

**Why HMAC-SHA3-512 instead of XOR?**

XOR (as used in BBX-01) preserves entropy but has a subtle weakness: if UR is partially known (e.g., through a side-channel leak of some Argon2id internal state), XOR leaks corresponding bits of RR. HMAC-SHA3-512 as a PRF provides computational hiding — even partial knowledge of one input reveals nothing about the output without full knowledge of both inputs.

### 8.4 Layer 3 — Context Binding

```
CR = HMAC-SHA3-512(
    key              = MR,                            // 512 bits
    msg              = "scb-vka-context-v2" || CM     // domain separator || 512 bits
)
```

Output: 512 bits (64 bytes).

CR is the final root from which all operational keys derive. It requires all three secrets (UK via UR, RS via RR, vault state via CM) and cannot be computed if any one is missing.

### 8.5 Layer 4 — Purpose-Specific Key Extraction

```
KEK = HKDF-SHA3-512(
    IKM  = CR,
    salt = empty,
    info = "scb-vka-kek-v2",
    len  = 32                    // 256 bits
)

MK = HKDF-SHA3-512(
    IKM  = CR,
    salt = empty,
    info = "scb-vka-meta-v2",
    len  = 32                    // 256 bits
)

CK = HKDF-SHA3-512(
    IKM  = CR,
    salt = empty,
    info = "scb-vka-canary-v2",
    len  = 32                    // 256 bits
)
```

Distinct `info` strings guarantee cryptographic independence under HKDF security model.

**Invariant:** KEK, MK, CK, and all intermediate values (UR, RR, MR, CR) are NEVER stored at rest and MUST be zeroized after use.

---

## 9. Object Encryption

### 9.1 DEK Generation

Each object receives its own randomly generated Data Encryption Key:

```
DEK ← CSPRNG(256)               // 32 bytes, per-object
```

Unlike v1 where object keys were derived deterministically from RS via HKDF, v2 uses random DEKs wrapped by KEK. This provides an additional isolation layer: even if the derivation chain is somehow partially compromised, each DEK is an independent random value.

### 9.2 DEK Wrapping

```
dek_wrap_ctx = TLV(0x01, VID)             ||
               TLV(0x11, object_id)        ||
               TLV(0x12, object_version)   ||
               TLV(0xF0, "dek-wrap")

dek_nonce ← CSPRNG(192)                    // 24 bytes

wrapped_dek || wrap_tag = XChaCha20-Poly1305.Encrypt(
    key       = KEK,
    nonce     = dek_nonce,
    plaintext = DEK,
    aad       = dek_wrap_ctx
)
```

### 9.3 Data Encryption

```
data_ctx = TLV(0x01, VID)             ||
           TLV(0x10, object_type)     ||
           TLV(0x11, object_id)       ||
           TLV(0x12, object_version)  ||
           TLV(0x13, purpose)

data_nonce ← CSPRNG(192)               // 24 bytes

ciphertext || data_tag = XChaCha20-Poly1305.Encrypt(
    key       = DEK,
    nonce     = data_nonce,
    plaintext = data,
    aad       = data_ctx
)
```

### 9.4 Stored Object Format

```
┌──────────────────────────────────────────────┐
│              ENCRYPTED OBJECT                │
├──────────────────────────────────────────────┤
│  object_type       (TLV)                    │
│  object_id         (TLV)                    │
│  object_version    (TLV)                    │
│  purpose           (TLV)                    │
│  dek_nonce         (24 bytes)               │
│  wrapped_dek       (32 bytes)               │
│  wrap_tag          (16 bytes)               │
│  data_nonce        (24 bytes)               │
│  ciphertext        (variable)               │
│  data_tag          (16 bytes)               │
└──────────────────────────────────────────────┘
```

### 9.5 Post-Encryption Hygiene

After encryption completes:

1. Zeroize DEK.
2. Zeroize plaintext buffer (if owned by the vault layer).
3. Update epoch (increment via volume layer; see Volume Format Specification).
4. Recompute CM.
5. Recompute Header MAC with new metadata state.

**Important:** Steps 4-5 mean that after any mutation, the next unlock will require the new CM. This is intentional — it binds the vault to its latest state.

---

## 10. Object Decryption

### 10.1 Procedure

```
1. Read vault header, reconstruct CM from current vault state
2. Derive full chain: UK → UR, RS → RR, (UR,RR) → MR, (MR,CM) → CR → KEK
3. Reconstruct dek_wrap_ctx from object metadata
4. DEK = XChaCha20-Poly1305.Decrypt(
       key        = KEK,
       nonce      = stored_dek_nonce,
       ciphertext = stored_wrapped_dek,
       tag        = stored_wrap_tag,
       aad        = dek_wrap_ctx
   )
5. Reconstruct data_ctx from object metadata
6. plaintext = XChaCha20-Poly1305.Decrypt(
       key        = DEK,
       nonce      = stored_data_nonce,
       ciphertext = stored_ciphertext,
       tag        = stored_data_tag,
       aad        = data_ctx
   )
7. Zeroize DEK and KEK from memory
```

### 10.2 Failure Behavior

- ANY failure (wrong UK, wrong RS, wrong CM, corrupted ciphertext, tampered metadata) MUST produce a single, generic, constant-time error.
- The implementation MUST NOT distinguish between: wrong password, wrong recovery secret, corrupted vault state, tampered ciphertext, modified nonce, or invalid tag.
- No partial plaintext is ever released.
- Timing of error responses MUST be constant regardless of failure cause.

This property directly supports G-INDISTINGUISHABLE.

---

## 11. Key Confirmation (Canary Mechanism)

### 11.1 Construction

At vault creation:

```
canary_plaintext ← CSPRNG(256)              // 32 random bytes
canary_nonce     ← CSPRNG(192)              // 24 bytes

canary_ctx = TLV(0x01, VID) || TLV(0xF0, "canary-v2")

canary_ciphertext || canary_tag = XChaCha20-Poly1305.Encrypt(
    key       = CK,
    nonce     = canary_nonce,
    plaintext = canary_plaintext,
    aad       = canary_ctx
)
```

### 11.2 Verification

On vault unlock, after deriving CK:

1. Attempt AEAD decryption of canary object.
2. Success → all three secrets are correct, proceed.
3. Failure → at least one secret is wrong, abort with generic error.

### 11.3 Security Properties

- Canary plaintext is random, reveals nothing about any secret.
- CK is derived through a separate HKDF `info` string, independent from KEK and MK.
- Does NOT create a key validation oracle beyond what any AEAD decryption provides.
- Cost of each validation attempt = full Argon2id evaluation + HMAC fusion + context binding.

---

## 12. Metadata Integrity

### 12.1 Header MAC Construction

```
header_data = TLV(0x01, VID)                ||
              TLV(0x02, VCT)                ||
              TLV(0x04, SV)                 ||
              TLV(0x05, RS_salt)            ||
              TLV(0xF0, VS)

header_mac = HMAC-SHA3-512(
    key           = MK,
    msg           = "scb-vka-header-v2" || header_data
)
```

### 12.2 Verification

On every vault unlock, after deriving MK:

1. Recompute header_mac from stored header fields.
2. Constant-time compare with stored Header MAC.
3. Mismatch → abort with generic error.

### 12.3 Circular Dependency Resolution

Same resolution as v1: read header → derive chain → verify MAC. Attacker cannot forge MAC without MK, MK requires UK + RS + CM.

---

## 13. Vault Migration

### 13.1 Triggers

Migration is required when:

- Specification version changes (primitive updates, parameter changes).
- UK is changed (password rotation).
- RS is rotated (recovery secret refresh).
- Argon2id parameters are increased.

### 13.2 Procedure

```
1.  Unlock vault with current (UK, RS) and current vault state
2.  Decrypt all objects (unwrap all DEKs, decrypt all data)
3.  Generate new parameters as needed:
      VS_new, RS_salt_new ← CSPRNG(256) each
      VID_new ← UUIDv4()  (if full migration)
      RS_new ← CSPRNG(256) (if RS rotation)
4.  Reset epoch to 0 (via volume layer)
5.  Derive new chain with new/updated secrets
6.  Re-wrap all DEKs under new KEK
7.  Re-encrypt canary under new CK
8.  Compute new CM, Header MAC
9.  Write new vault atomically (write-then-rename)
10. Zeroize ALL old and new key material
11. Securely delete old vault (best-effort)
```

### 13.3 DEK Preservation

During migration, DEKs themselves do NOT change — only their wrapping changes. This means data ciphertexts can optionally be preserved without re-encryption, significantly reducing migration time for large vaults. However, if the migration is triggered by a suspected compromise, full re-encryption with new DEKs is RECOMMENDED.

### 13.4 Atomicity

Migration MUST be atomic. Implementations MUST use write-then-rename or equivalent mechanism.

---

## 14. Stateless Invariant

### 14.1 Definition

At rest, no stored data reduces the cost of deriving any key below the cost defined by the derivation chain with all three secrets.

### 14.2 Formal Statement

Let S be all data at rest. For any key K ∈ {UR, RR, MR, CR, KEK, MK, CK, DEK}:

```
H∞(K | S) = H∞(K | public_parameters)
```

Stored data provides zero advantage in computing any key.

### 14.3 DEK Exception

DEKs are stored at rest in wrapped form. However, wrapped DEKs are AEAD ciphertexts under KEK, which is never stored. Therefore:

```
H∞(DEK | wrapped_DEK) = H∞(DEK | random_bytes)
```

under the IND-CCA2 assumption on XChaCha20-Poly1305.

### 14.4 Prohibited Storage

MUST NOT store at rest: UR, RR, MR, CR, KEK, MK, CK, or any unwrapped DEK, or any intermediate derivation product, or any hash/MAC/ciphertext of any key (except wrapped DEKs and canary).

### 14.5 Memory Hygiene

All volatile key material MUST be zeroized immediately after final use. Implementations MUST use platform-specific secure zeroization (`explicit_bzero`, `SecureZeroMemory`, `zeroize` crate). Implementations SHOULD use memory-locked pages (`mlock`, `VirtualLock`).

---

## 15. Security Analysis

### 15.1 Assumptions

| ID | Assumption |
|----|------------|
| A1 | Argon2id is memory-hard with pre-image resistance (RFC 9106). |
| A2 | HMAC-SHA3-512 is a secure PRF (RFC 2104 + FIPS 202). |
| A3 | HKDF-SHA3-512 is a secure KDF (RFC 5869, FIPS 202). |
| A4 | XChaCha20-Poly1305 is IND-CCA2 secure with 192-bit nonces. |
| A5 | TLV encoding (Section 5) is injective. |
| A6 | UK has sufficient entropy to resist offline search given Argon2id parameters. |
| A7 | RS is 256-bit CSPRNG output sealed in platform HSP (Secure Enclave, TPM 2.0, or FIDO2). |
| A8 | CSPRNG produces output indistinguishable from uniform random. |
| A9 | SHA3-512 is collision-resistant and preimage-resistant. |

### 15.2 Security Guarantees

**SG1 — Multi-Secret Requirement (G-MULTISECRET)**

No polynomial-time algorithm can derive MR from UR alone, RR alone, or any value not involving both UR and RR. By A2 (HMAC-SHA3-512 PRF security), MR = HMAC-SHA3-512(UR, RR) is indistinguishable from random given only one input.

Similarly, CR = HMAC-SHA3-512(MR, CM) cannot be computed without MR, which itself requires both UR and RR.

**SG2 — Dead Key Property (G-DEADKEY)**

Any single compromised secret is computationally useless:

- UK alone → UR is computable, but MR requires RR (256-bit brute-force).
- RS alone → RR is computable, but MR requires UR (Argon2id wall).
- CM alone → CM enters at Layer 3, but MR at Layer 2 requires both UR and RR.

**SG3 — Object Isolation (G-ISOLATED)**

Each DEK is an independent CSPRNG output. Compromise of one DEK reveals nothing about any other DEK (by A8). KEK compromise reveals all DEKs, but KEK requires the full three-secret chain.

**SG4 — Failure Indistinguishability (G-INDISTINGUISHABLE)**

All failure modes (wrong UK, wrong RS, wrong CM, tampered data) produce the same AEAD authentication failure. By A4 and constant-time implementation, the attacker gains zero bits of information about which secret is incorrect.

**SG5 — Offline Attack Cost**

Each brute-force attempt requires:

- Full Argon2id evaluation (≥1 GiB, ≥3 iterations) for UK guessing.
- Full HMAC-SHA3-512 + HKDF chain for each (UK, RS) pair.
- Correct CM reconstruction for each vault state hypothesis.

**SG6 — Post-Quantum Security (Conditional)**

All primitives are symmetric. Under Grover's algorithm:

- XChaCha20 256-bit → 128-bit effective security.
- RS 256-bit → 128-bit effective brute-force cost.
- HMAC-SHA3-512, HKDF-SHA3-512 maintain ≥128-bit security.
- Argon2id quantum resistance remains an open research question (conditional).

**SG7 — Context Binding (G-CONTEXTBOUND)**

Any vault state change (object add/modify/delete) updates epoch (in the volume superblock), producing a different CM, producing a different CR, invalidating all previously derived keys. Vault files cannot be copied and used in a different state.

**SG8 — Metadata Tamper Detection**

Header MAC under HMAC-SHA3-512 with MK detects any modification to vault header fields with probability 1 - 2⁻⁵¹².

---

## 16. Compromise Scenarios

### 16.1 Scenario A — UK Compromised (Phishing, Keylogger)

Attacker knows: UK, all public parameters, all ciphertexts.
Attacker can compute: UR.
Attacker needs: RS (256-bit brute-force) + CM (vault state reconstruction).
**Result:** Computationally infeasible. UK is a dead key.

### 16.2 Scenario B — RS Compromised (Hardware Physical Attack)

Attacker knows: RS (extracted via invasive hardware attack — decapping, probing, side-channel), all public parameters.
Attacker can compute: RR.
Attacker needs: UK (Argon2id wall) + CM.
**Result:** Hardware's tamper-resistant boundary makes RS extraction require invasive physical attack. Cost varies by backend: Secure Enclave ~$100K+ (Apple silicon hardening), TPM ~$10K-$100K (depends on certification level), FIDO2 key ~$5K-$50K. Even after extraction, each UK guess costs ≥1 GiB memory + 3 iterations. Offline brute-force is economically infeasible for reasonable UK entropy.

### 16.3 Scenario C — Full Disk Exfiltration

Attacker knows: all vault files, headers, ciphertexts, public parameters.
Attacker can reconstruct: CM (vault state is in the header).
Attacker needs: UK (Argon2id wall) + RS (256-bit).
**Result:** Even with CM, the two remaining secrets make recovery infeasible.

### 16.4 Scenario D — UK + RS Compromised

Attacker knows: UK, RS.
Attacker can compute: UR, RR, MR.
Attacker needs: exact CM.
**Assessment:** This is the most dangerous two-secret compromise. If the attacker also has the vault files, CM can be reconstructed from the superblock (epoch) and header (VID, VCT, SV). **THIS MEANS UK + RS + VAULT FILES = FULL COMPROMISE.**

This is by design: CM is not a secret in the traditional sense. It is a binding mechanism that prevents key reuse across vault states and provides tamper evidence. The true two-factor security boundary is UK + RS.

**Mitigation:** RS MUST be stored in a separate trust domain from the vault files. If both are compromised simultaneously, the vault is compromised. This is the architectural minimum — no symmetric-only system can do better without hardware trust anchors.

### 16.5 Scenario E — Memory Snapshot During Active Session

Attacker captures: process memory containing derived keys.
**Result:** All in-memory keys (UR, RR, MR, CR, KEK, DEKs) are exposed. Full compromise for the duration of the snapshot. This is an explicit non-goal (Section 18).

### 16.6 "Dead but Unprovable" Property

In Scenarios A, B, and C: the attacker cannot prove the vault contains data, that their secret is correct, or that the vault is functional. AEAD failure is indistinguishable from corruption, wrong secret, or empty vault. This provides **Cryptographic Plausible Failure** — analogous to hidden volumes but at the key architecture level.

---

## 17. Implementation Requirements

### 17.1 MUST

1. All primitives MUST match Section 4.1 exactly.
2. All encoding MUST follow Section 5 exactly.
3. RS MUST be generated from CSPRNG with ≥256 bits.
4. RS MUST be provisioned to a separate trust domain (Section 7.3).
5. RS MUST be sealed to platform HSP per Section 6.3.
6. If no supported HSP is available, vault creation MUST fail.
7. AEAD failure MUST produce generic, constant-time error.
7. All derived keys MUST be zeroized after use.
8. Header MAC MUST be verified on every unlock.
9. Canary mechanism MUST be implemented per Section 11.
10. Superblock epoch serves as sole mutable CM input (managed by Volume Format Spec).

### 17.2 SHOULD

1. Use memory-locked pages for key material.
2. Use atomic write operations for vault mutations.
3. Provide secure vault deletion mechanism.
4. Allow Argon2id parameters above minimums.
5. Implement RS provisioning as BIP-39 mnemonic for usability.

### 17.3 MUST NOT

1. Store any unwrapped key material at rest.
2. Implement algorithm negotiation.
3. Differentiate between error types during decryption.
4. Log, trace, or serialize any key material.
5. Store RS alongside vault files.
6. Store RS in software or alongside vault files.
7. Offer "skip hardware sealing" option.
8. Target WASM (no reliable memory zeroization or HSP access).

---

## 18. Explicit Non-Goals

1. **Endpoint compromise resistance** — persistent memory access exposes all in-memory keys.
2. **Continuous RAM scraping resistance** — requires hardware-level protection.
3. **Coercion resistance** — without hidden volumes or decoy vaults.
4. **Multi-party access** — single-user by design.
5. **Key escrow** — loss of UK or hardware (without BIP-39 backup) = permanent data loss by design.
6. **UK quality enforcement** — specification concern vs. implementation concern.
7. **Hardware-less operation** — a supported HSP (Secure Enclave, TPM 2.0, or FIDO2 key) is a hard requirement.

---

## 19. Compliance Criteria

An implementation is **SCB-VKA v2.0 compliant** if and only if:

1. All key derivation follows Section 8 exactly.
2. All encoding follows Section 5 exactly.
3. Three independent secrets (UK, RS, CM) are required for every key derivation.
4. RS is provisioned per Section 7.3.
5. No persistent key material exists at rest (Section 14).
6. Failure behavior conforms to Section 10.2.
7. Canary mechanism implemented per Section 11.
8. Header MAC implemented and verified per Section 12.
9. All Section 17.1 (MUST) and 17.3 (MUST NOT) requirements satisfied.
10. Only primitives listed in Section 4.1 are used.

---

## 20. References

| Reference | Title |
|-----------|-------|
| RFC 9106 | Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| RFC 2119 | Key words for use in RFCs to Indicate Requirement Levels |
| NIST SP 800-185 | SHA-3 Derived Functions (reference only — KMAC not used) |
| FIPS 202 | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions |
| draft-irtf-cfrg-xchacha | XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305 |
| BIP-39 | Mnemonic code for generating deterministic keys |
| RFC 2104 | HMAC: Keyed-Hashing for Message Authentication |
| Grover 1996 | A fast quantum mechanical algorithm for database search |

---

*End of Specification*