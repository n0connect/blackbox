# SCB-VKA v2 — Module Architecture Map

**Version:** 1.0.0  
**Date:** 2025-02

---

## 1. Module Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                       ORCHESTRATOR                              │
│            (coordinates all modules, owns vault lifecycle)      │
│                                                                 │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────┤
│          │          │          │          │          │         │
│  CRYPTO  │  DISK    │  MEMORY  │   HSP    │  ERROR   │  LOG    │
│  CORE    │  IO      │  GUARD   │ PROVIDER │ HANDLER  │  GER    │
│          │          │          │          │          │         │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────┘
```

**Rule:** No horizontal communication. Every module talks ONLY to Orchestrator via its public API trait. Orchestrator is the sole coordinator.

---

## 2. Module Definitions

### 2.1 CryptoCore

**Responsibility:** All cryptographic operations. Nothing else.

**Public API Trait: `CryptoEngine`**

```
┌─────────────────────────────────────────────────────────┐
│  CryptoEngine                                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  // Layer 1: Root Extraction                            │
│  derive_user_root(uk, vs, params) → UR                  │
│  derive_recovery_root(rs_response, rs_salt) → RR        │
│                                                         │
│  // Layer 2: Fusion                                     │
│  fuse_roots(ur, rr) → MR                                │
│                                                         │
│  // Layer 3: Context Binding                            │
│  bind_context(mr, cm) → CR                              │
│                                                         │
│  // Layer 4: Key Extraction                             │
│  extract_kek(cr) → KEK                                  │
│  extract_mk(cr) → MK                                    │
│  extract_ck(cr) → CK                                    │
│                                                         │
│  // AEAD Operations                                     │
│  aead_encrypt(key, plaintext, aad) → (nonce, ct, tag)   │
│  aead_decrypt(key, nonce, ct, tag, aad) → plaintext     │
│                                                         │
│  // DEK Management                                      │
│  generate_dek() → DEK                                   │
│  wrap_dek(kek, dek, aad) → WrappedDEK                   │
│  unwrap_dek(kek, wrapped, aad) → DEK                    │
│                                                         │
│  // MAC                                                 │
│  compute_header_mac(mk, header_data) → MAC              │
│  verify_header_mac(mk, header_data, mac) → bool         │
│                                                         │
│  // Hashing                                             │
│  compute_cm(vid, vct, sv, epoch) → CM                   │
│                                                         │
│  // Entropy                                             │
│  csprng(len) → bytes                                    │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  OWNS: Nothing persistent. Pure functions.              │
│  TOUCHES: No other module. Zero dependencies.           │
│  STATE: Stateless. Every call is independent.           │
└─────────────────────────────────────────────────────────┘
```

**Internal primitives (not exposed):**

- Argon2id (derive_user_root)
- HMAC-SHA3-512 (fuse_roots, bind_context, header MAC)
- HKDF-SHA3-512 (derive_recovery_root, extract_*)
- XChaCha20-Poly1305 (aead_*)
- SHA3-512 (compute_cm)
- CSPRNG (csprng, generate_dek, nonces)

**Crate dependencies:** `argon2`, `hmac`, `sha3`, `hkdf`, `chacha20poly1305`, `rand`, `zeroize`

---

### 2.2 DiskIO

**Responsibility:** All persistent storage operations. Reads and writes bytes to/from container file. Knows nothing about encryption.

**Public API Trait: `StorageEngine`**

```
┌─────────────────────────────────────────────────────────┐
│  StorageEngine                                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  // Container Lifecycle                                 │
│  create_container(path, block_size, total_blocks) → ()  │
│  open_container(path) → ContainerHandle                 │
│  close_container(handle) → ()                           │
│                                                         │
│  // Superblock                                          │
│  read_superblock(handle) → SuperblockData               │
│  write_superblock(handle, data) → ()                    │
│  // Dual-write internally: A then B, fsync each         │
│                                                         │
│  // Block I/O                                           │
│  read_blocks(handle, start, count) → bytes              │
│  write_blocks(handle, start, data) → ()                 │
│  sync(handle) → ()                                      │
│                                                         │
│  // WAL                                                 │
│  wal_append_frame(handle, frame) → ()                   │
│  wal_read_frames(handle) → Vec<WALFrame>                │
│  wal_commit(handle, epoch) → ()                         │
│  wal_clear(handle) → ()                                 │
│  wal_checkpoint(handle, frames) → ()                    │
│                                                         │
│  // Atomic Operations                                   │
│  set_dirty_flag(handle) → ()                            │
│  clear_dirty_flag(handle, new_epoch) → ()               │
│                                                         │
│  // File Locking                                        │
│  acquire_write_lock(handle) → bool                      │
│  release_write_lock(handle) → ()                        │
│                                                         │
│  // Resize                                              │
│  grow_container(handle, new_total_blocks) → ()          │
│  shrink_container(handle, new_total_blocks) → ()        │
│                                                         │
│  // Secure Overwrite                                    │
│  overwrite_blocks(handle, start, count, data) → ()      │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  OWNS: File descriptors, file locks.                    │
│  TOUCHES: OS filesystem only.                           │
│  STATE: ContainerHandle (fd, lock state, geometry).     │
└─────────────────────────────────────────────────────────┘
```

**Crate dependencies:** `std::fs`, `std::io`, platform file locking (`flock`/`LockFileEx`)

---

### 2.3 MemoryGuard

**Responsibility:** All volatile memory management for sensitive data. Allocation, zeroization, locking, lifetime enforcement.

**Public API Trait: `SecureMemory`**

```
┌─────────────────────────────────────────────────────────┐
│  SecureMemory                                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  // Secure Allocation                                   │
│  alloc_secure<T>(value: T) → SecureBox<T>               │
│  // Returns memory-locked, zeroize-on-drop container    │
│                                                         │
│  // Secure Buffer                                       │
│  alloc_buffer(size: usize) → SecureBuffer               │
│  // Locked, zeroed-on-drop byte buffer                  │
│                                                         │
│  // Lifetime Control                                    │
│  scope<F, R>(f: F) → R                                  │
│  // All SecureBox/Buffer allocated within f              │
│  // are guaranteed zeroized when f returns               │
│                                                         │
│  // Explicit Zeroize                                    │
│  wipe<T>(target: &mut T) → ()                           │
│                                                         │
│  // Status                                              │
│  active_allocations() → usize                           │
│  // Debug: how many secure allocs are live              │
│  // MUST be zero after vault lock                       │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  OWNS: mlock'd memory pages.                            │
│  TOUCHES: OS mlock/VirtualLock APIs.                    │
│  STATE: Allocation counter, page tracking.              │
│  INVARIANT: active_allocations() == 0 after vault lock. │
└─────────────────────────────────────────────────────────┘
```

**Key types:**

- `SecureBox<T>`: Drop → zeroize → munlock. Cannot be cloned, cannot be serialized.
- `SecureBuffer`: Same guarantees for raw bytes.
- Both implement `Deref` for read access but NOT `DerefMut` for uncontrolled writes.

**Crate dependencies:** `zeroize`, `memsec` or `region` (for mlock), `std::alloc`

---

### 2.4 HSPProvider

**Responsibility:** All hardware security module communication. Sealing, unsealing, hardware HMAC. Abstracts platform differences.

**Public API Trait: `HardwareSecurityProvider`**

```
┌─────────────────────────────────────────────────────────┐
│  HardwareSecurityProvider                               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  // Discovery                                           │
│  detect_backend() → HSPBackend                          │
│  // Returns: SecureEnclave | TPM2 | FIDO2 | None        │
│                                                         │
│  // RS Lifecycle                                        │
│  seal(rs: &[u8], policy: SealPolicy) → HSPHandle        │
│  unseal_hmac(handle: HSPHandle, challenge: &[u8])       │
│      → SecureBuffer                                     │
│  // Normal unlock: returns HMAC(RS, challenge)           │
│  // RS never enters host memory (TPM/FIDO2)             │
│  // RS briefly in host memory (SEP — see spec note)     │
│                                                         │
│  // Emergency                                           │
│  emergency_hmac(rs_raw: &[u8], challenge: &[u8])        │
│      → SecureBuffer                                     │
│  // BIP-39 recovery path — software HMAC fallback       │
│                                                         │
│  // Destruction                                         │
│  destroy(handle: HSPHandle) → ()                        │
│                                                         │
│  // Handle Serialization                                │
│  export_handle(handle: &HSPHandle) → Vec<u8>            │
│  import_handle(data: &[u8]) → HSPHandle                 │
│  // For storing handle reference in vault header        │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  OWNS: HSP session, key handles.                        │
│  TOUCHES: Platform HSP only (SEP/TPM/FIDO2).           │
│  STATE: Active handles, backend type.                   │
└─────────────────────────────────────────────────────────┘
```

**Platform backends (compile-time selection):**

```
┌────────────────┬────────────────────────────────┐
│ Platform       │ Implementation                 │
├────────────────┼────────────────────────────────┤
│ macOS          │ SEPProvider (security-framework)│
│ Linux          │ TPMProvider (tss-esapi)         │
│ Windows        │ Compile-time error (backend WIP)│
│ Fallback       │ FIDO2Provider (ctap-hid-fido2)  │
└────────────────┴────────────────────────────────┘
```

---

### 2.5 ErrorHandler

**Responsibility:** All error mapping. Every module's internal errors collapse to a single opaque error type. No information leakage through error variants.

**Public API Trait: `ErrorPolicy`**

```
┌─────────────────────────────────────────────────────────┐
│  ErrorPolicy                                            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  // The ONLY public error type                          │
│  VaultError {                                           │
│      kind: VaultErrorKind,                              │
│      // NO inner error, NO source chain, NO details     │
│  }                                                      │
│                                                         │
│  VaultErrorKind:                                        │
│      AuthenticationFailed    // UK, RS, CM, or AEAD     │
│      StorageUnavailable      // disk I/O failure        │
│      HardwareUnavailable     // HSP not found/failed    │
│      VaultBusy               // write lock held         │
│      VaultCorrupted          // crash recovery failed   │
│      OperationFailed         // generic catch-all       │
│                                                         │
│  // Mapping                                             │
│  map_crypto_error(e: CryptoError) → VaultError          │
│  map_io_error(e: IoError) → VaultError                  │
│  map_hsp_error(e: HSPError) → VaultError                │
│  map_memory_error(e: MemError) → VaultError             │
│                                                         │
│  CRITICAL RULE:                                         │
│  Wrong UK, wrong RS, wrong CM, tampered data,           │
│  corrupted ciphertext — ALL map to                      │
│  AuthenticationFailed. No differentiation.              │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  OWNS: Nothing.                                         │
│  TOUCHES: Nothing. Pure mapping functions.              │
│  STATE: Stateless.                                      │
└─────────────────────────────────────────────────────────┘
```

---

### 2.6 Logger

**Responsibility:** Structured event logging for all vault operations. Audit trail without leaking sensitive data.

**Public API Trait: `VaultLogger`**

```
┌─────────────────────────────────────────────────────────┐
│  VaultLogger                                            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  // Event Logging                                       │
│  log_event(event: VaultEvent) → ()                      │
│                                                         │
│  VaultEvent:                                            │
│      VaultCreated { vid, timestamp }                    │
│      VaultUnlockAttempt { vid, timestamp, success }     │
│      VaultLocked { vid, timestamp }                     │
│      ObjectAdded { vid, object_id, timestamp }          │
│      ObjectRead { vid, object_id, timestamp }           │
│      ObjectDeleted { vid, object_id, timestamp }        │
│      ObjectModified { vid, object_id, timestamp }       │
│      MigrationStarted { vid, from_ver, to_ver }         │
│      MigrationCompleted { vid, timestamp }              │
│      CrashRecoveryStarted { vid, timestamp }            │
│      CrashRecoveryCompleted { vid, epoch_restored }     │
│      HSPOperationPerformed { backend, op_type }         │
│      DefragStarted { vid, fragmentation_ratio }         │
│      DefragCompleted { vid, timestamp }                 │
│      Error { vid, error_kind, timestamp }               │
│                                                         │
│  // Configuration                                       │
│  set_output(sink: LogSink) → ()                         │
│  // LogSink: File, Stdout, Custom(Box<dyn Write>)       │
│                                                         │
│  set_level(level: LogLevel) → ()                        │
│  // LogLevel: Silent, Error, Warn, Info, Debug          │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  OWNS: Log output handle.                               │
│  TOUCHES: OS I/O (log file/stdout).                     │
│  STATE: Current log level, output sink.                 │
│                                                         │
│  SECURITY INVARIANT:                                    │
│  VaultEvent MUST NEVER contain:                         │
│    - Any key material (UK, RS, UR, RR, MR, CR, KEK...) │
│    - Plaintext data or plaintext fragments              │
│    - Nonces, tags, or ciphertext                        │
│    - HSP handles or sealed data                         │
│    - Error details beyond VaultErrorKind                │
│  Only identifiers (VID, object_id) and timestamps.      │
└─────────────────────────────────────────────────────────┘
```

---

### 2.7 Orchestrator

**Responsibility:** Vault lifecycle coordination. The ONLY module that knows all other modules exist. Routes data between modules without understanding the data.

**Public API Trait: `VaultManager`**

```
┌─────────────────────────────────────────────────────────┐
│  VaultManager                                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  // Vault Lifecycle                                     │
│  create_vault(path, uk) → Result<VaultInfo>             │
│  // 1. DiskIO.create_container                          │
│  // 2. CryptoCore.csprng → VS, RS                       │
│  // 3. HSP.seal(RS)                                     │
│  // 4. Display BIP-39 mnemonic (one-time)               │
│  // 5. Derive full chain → write header, canary         │
│  // 6. Logger.log(VaultCreated)                         │
│                                                         │
│  unlock_vault(path, uk) → Result<VaultSession>          │
│  // 1. DiskIO.open_container → read superblock          │
│  // 2. DiskIO.read vault header                         │
│  // 3. HSP.unseal_hmac(challenge) → RS_response         │
│  // 4. MemoryGuard.scope {                              │
│  //      CryptoCore.derive_user_root(uk)                │
│  //      CryptoCore.derive_recovery_root(rs_response)   │
│  //      CryptoCore.fuse_roots → MR                     │
│  //      CryptoCore.compute_cm → CM                     │
│  //      CryptoCore.bind_context → CR                   │
│  //      CryptoCore.extract_kek/mk/ck                   │
│  //      CryptoCore.verify canary                       │
│  //      CryptoCore.verify header MAC                   │
│  //    }                                                │
│  // 5. Crash recovery if DIRTY flag set                 │
│  // 6. Decrypt BAM, load index                          │
│  // 7. Logger.log(VaultUnlockAttempt)                   │
│                                                         │
│  lock_vault(session) → Result<()>                       │
│  // 1. MemoryGuard.wipe all keys                        │
│  // 2. DiskIO.release_write_lock                        │
│  // 3. DiskIO.close_container                           │
│  // 4. Assert MemoryGuard.active_allocations() == 0     │
│  // 5. Logger.log(VaultLocked)                          │
│                                                         │
│  // Object Operations                                   │
│  add_object(session, type, purpose, data)               │
│      → Result<ObjectId>                                 │
│  read_object(session, object_id) → Result<Vec<u8>>      │
│  modify_object(session, object_id, data) → Result<()>   │
│  delete_object(session, object_id) → Result<()>         │
│  list_objects(session) → Result<Vec<ObjectMeta>>         │
│                                                         │
│  // Maintenance                                         │
│  migrate_vault(session, new_params) → Result<()>        │
│  change_password(session, old_uk, new_uk) → Result<()>  │
│  rotate_rs(session) → Result<()>                        │
│  defragment(session) → Result<()>                       │
│  resize_vault(session, new_size) → Result<()>           │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  OWNS: VaultSession (active key handles in              │
│        MemoryGuard SecureBoxes).                        │
│  TOUCHES: ALL modules via their public traits.          │
│  STATE: Active sessions, module references.             │
│                                                         │
│  COORDINATION RULE:                                     │
│  Orchestrator NEVER performs crypto, I/O, or HSP        │
│  operations directly. It ONLY calls module APIs         │
│  and routes results between them.                       │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Data Flow

### 3.1 Vault Unlock Flow

```
User                Orchestrator    HSP       Crypto    Memory    DiskIO    Logger
 │                       │           │          │         │         │         │
 │──uk──────────────────►│           │          │         │         │         │
 │                       │──open────────────────────────────────►│         │
 │                       │◄──superblock + header─────────────────│         │
 │                       │──challenge──────────►│          │         │         │
 │                       │           │◄─────────│          │         │         │
 │                       │◄──rs_response────────│          │         │         │
 │                       │──────────alloc scope────────►│         │         │
 │                       │──derive(uk,rs_resp)─►│         │         │         │
 │                       │◄──UR,RR,MR,CR,KEK────│◄─secure─┤         │         │
 │                       │──verify canary──────►│         │         │         │
 │                       │◄──ok/fail────────────│         │         │         │
 │                       │──log─────────────────────────────────────────────►│
 │◄──session/error───────│           │          │         │         │         │
```

### 3.2 Object Write Flow

```
Orchestrator     Crypto       Memory      DiskIO       Logger
     │              │           │            │            │
     │──gen_dek───►│           │            │            │
     │◄──dek────────│──secure──►│            │            │
     │──encrypt────►│           │            │            │
     │◄──ct─────────│           │            │            │
     │──wrap_dek───►│           │            │            │
     │◄──wrapped────│           │            │            │
     │──set_dirty──────────────────────────►│            │
     │──wal_write──────────────────────────►│            │
     │──wal_commit─────────────────────────►│            │
     │──checkpoint─────────────────────────►│            │
     │──clear_dirty────────────────────────►│            │
     │──wipe(dek)──────────────►│            │            │
     │──log────────────────────────────────────────────►│
```

---

## 4. Dependency Matrix

```
              CryptoCore  DiskIO  MemoryGuard  HSP  ErrorHandler  Logger  Orchestrator
CryptoCore       —         ✗        ✗          ✗       ✗           ✗         ✗
DiskIO           ✗         —        ✗          ✗       ✗           ✗         ✗
MemoryGuard      ✗         ✗        —          ✗       ✗           ✗         ✗
HSPProvider      ✗         ✗        ✗          —       ✗           ✗         ✗
ErrorHandler     ✗         ✗        ✗          ✗       —           ✗         ✗
Logger           ✗         ✗        ✗          ✗       ✗           —         ✗
Orchestrator     ✓         ✓        ✓          ✓       ✓           ✓         —
```

**✓ = depends on (via trait)  |  ✗ = zero dependency**

Only Orchestrator has dependencies. All other modules are fully independent.

---

*End of Module Architecture*
