# SCB-VKA Volume Format Specification

**Specification Version:** 1.0.0  
**Status:** Draft  
**Author:** Kairos  
**Date:** 2025-02  
**Category:** Encrypted Container Format Specification  
**Parent Specification:** SCB-VKA v2 (Cryptographic Architecture)

---

## Abstract

This document defines the on-disk volume format for SCB-VKA v2 encrypted containers. It specifies the physical layout of a single-file encrypted vault, including container structure, object storage, indexing, free space management, secure deletion, and atomic mutation semantics. This specification operates strictly below the cryptographic layer defined in SCB-VKA v2 and assumes all key derivation, encryption, and decryption follow that parent specification.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Design Goals](#3-design-goals)
4. [Container Model](#4-container-model)
5. [Physical Layout](#5-physical-layout)
6. [Superblock](#6-superblock)
7. [Vault Header](#7-vault-header)
8. [Block Allocation](#8-block-allocation)
9. [Object Storage](#9-object-storage)
10. [Encrypted Index](#10-encrypted-index)
11. [Free Space Management](#11-free-space-management)
12. [Write-Ahead Log (WAL)](#12-write-ahead-log-wal)
13. [Atomic Mutation Protocol](#13-atomic-mutation-protocol)
14. [Secure Deletion](#14-secure-deletion)
15. [Container Resize](#15-container-resize)
16. [Defragmentation](#16-defragmentation)
17. [Crash Recovery](#17-crash-recovery)
18. [Concurrency](#18-concurrency)
19. [Security Properties](#19-security-properties)
20. [Implementation Requirements](#20-implementation-requirements)
21. [Compliance Criteria](#21-compliance-criteria)

---

## 1. Introduction

### 1.1 Relationship to SCB-VKA v2

SCB-VKA v2 defines the cryptographic architecture: key derivation, encryption, and decryption. This volume format specification defines where encrypted data physically lives. The separation is intentional — the cryptographic layer is storage-agnostic, the volume layer is crypto-agnostic. They interface through well-defined boundaries:

```
┌──────────────────────────────────────────┐
│          APPLICATION LAYER               │
│   (vault operations: add, read, delete)  │
├──────────────────────────────────────────┤
│        CRYPTOGRAPHIC LAYER               │
│   (SCB-VKA v2: key derivation, AEAD)     │
├──────────────────────────────────────────┤
│         VOLUME FORMAT LAYER              │  ← This specification
│   (container layout, blocks, index, WAL) │
├──────────────────────────────────────────┤
│         OPERATING SYSTEM / FS            │
│   (file I/O, fsync, rename)             │
└──────────────────────────────────────────┘
```

### 1.2 Scope

This specification defines the binary format of an SCB-VKA container file, mutation semantics, crash safety, and secure deletion. It does not define cryptographic operations, key management, or HSP interaction.

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| Container | A single file on disk representing one encrypted vault. |
| Superblock | Fixed-size, unencrypted header identifying the container format. |
| Vault Header | Cryptographic metadata (as defined in SCB-VKA v2 Section 7.4). |
| Block | Fixed-size allocation unit within the container (default: 4 KiB). |
| Slot | One or more contiguous blocks allocated to a single object. |
| Object | An encrypted data item stored in the vault. |
| Index | Encrypted B-tree mapping object identifiers to physical slot locations. |
| BAM | Block Allocation Map — bitmap tracking free/used blocks. |
| WAL | Write-Ahead Log — journal for atomic multi-block mutations. |
| Epoch | A monotonically increasing counter incremented on every committed mutation. |

---

## 3. Design Goals

| ID | Goal | Description |
|----|------|-------------|
| VG-SINGLEFILE | Single-file container | Entire vault is one file — portable, copyable, backupable as a unit. |
| VG-ATOMIC | Atomic mutations | Every vault mutation either fully completes or fully rolls back. |
| VG-CRASHSAFE | Crash recovery | Container is recoverable to a consistent state after any crash. |
| VG-SECUREDELETE | Cryptographic erasure | Deleted objects are irrecoverable without re-encryption of remaining data. |
| VG-EFFICIENT | Efficient access | Object lookup is O(log n) via encrypted B-tree index. |
| VG-COMPACT | Minimal overhead | Block size and metadata overhead are minimized for small vaults. |
| VG-OPAQUE | Uniform appearance | Container file is indistinguishable from random data beyond the superblock. |

---

## 4. Container Model

### 4.1 Single-File Design

The vault is a single contiguous file on the host filesystem. All vault data — metadata, index, objects, free space — resides within this file.

**Rationale:** Single-file containers are atomically copyable, trivially backupable, and leave no scattered metadata across the filesystem. Directory-based layouts leak object count, sizes, and modification times through filesystem metadata.

### 4.2 Block-Based Allocation

The container is divided into fixed-size blocks. All allocations are block-aligned.

```
Default block size: 4096 bytes (4 KiB)
Minimum block size: 4096 bytes
Maximum block size: 65536 bytes (64 KiB)
```

Block size is fixed at container creation and stored in the superblock. It MUST NOT change after creation.

**Rationale:** 4 KiB aligns with OS page size and filesystem block size, minimizing read-modify-write amplification. Larger blocks reduce index overhead for large objects but waste space for small objects.

### 4.3 Block Addressing

Blocks are addressed by zero-indexed 48-bit block numbers:

```
Maximum blocks:     2^48 = 281,474,976,710,656
Maximum capacity:   2^48 × 4 KiB = 1 EiB (at default block size)
```

48-bit addressing provides sufficient capacity while keeping block references compact (6 bytes each).

---

## 5. Physical Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                      CONTAINER FILE                             │
├──────────┬──────────────────────────────────────────────────────┤
│ Block 0  │  SUPERBLOCK (unencrypted, format identification)     │
├──────────┼──────────────────────────────────────────────────────┤
│ Block 1  │  VAULT HEADER (SCB-VKA v2 cryptographic metadata)    │
│   ..N    │  (occupies 1-2 blocks depending on HSP handle size)  │
├──────────┼──────────────────────────────────────────────────────┤
│ Block N+1│  WAL REGION (write-ahead log, fixed size)            │
│   ..M    │  (default: 64 blocks = 256 KiB)                     │
├──────────┼──────────────────────────────────────────────────────┤
│ Block M+1│  BAM (Block Allocation Map, encrypted)               │
│   ..P    │  (size scales with container capacity)               │
├──────────┼──────────────────────────────────────────────────────┤
│ Block P+1│  INDEX (encrypted B-tree root + nodes)               │
│   ..Q    │  (size scales with object count)                     │
├──────────┼──────────────────────────────────────────────────────┤
│ Block Q+1│  DATA REGION (encrypted objects in slots)            │
│   ..end  │  (bulk of the container)                             │
└──────────┴──────────────────────────────────────────────────────┘
```

### 5.1 Region Boundaries

Region boundaries are stored in the superblock as block numbers. Regions MUST NOT overlap. The data region extends from its start block to the end of the container file.

---

## 6. Superblock

### 6.1 Format

The superblock occupies Block 0 and is the ONLY unencrypted region besides the vault header.

```
┌─────────────────────────────────────────────────┐
│                 SUPERBLOCK (Block 0)            │
├────────────────┬────────┬───────────────────────┤
│ Field          │ Size   │ Description           │
├────────────────┼────────┼───────────────────────┤
│ magic          │ 8 B    │ "SCBVKA02"            │
│ format_version │ 2 B    │ Volume format version  │
│ block_size     │ 4 B    │ Block size in bytes    │
│ total_blocks   │ 6 B    │ Total blocks (48-bit)  │
│ vault_hdr_start│ 6 B    │ Vault header block     │
│ vault_hdr_len  │ 2 B    │ Vault header blocks    │
│ wal_start      │ 6 B    │ WAL region start block │
│ wal_len        │ 2 B    │ WAL region blocks      │
│ bam_start      │ 6 B    │ BAM region start block │
│ bam_len        │ 4 B    │ BAM region blocks      │
│ index_start    │ 6 B    │ Index region start     │
│ index_len      │ 4 B    │ Index region blocks    │
│ data_start     │ 6 B    │ Data region start      │
│ epoch          │ 8 B    │ Current mutation epoch  │
│ flags          │ 4 B    │ Container state flags   │
│ reserved       │ var    │ Zero-filled to block_sz │
│ superblock_crc │ 4 B    │ CRC32C of all above    │
└────────────────┴────────┴───────────────────────┘
```

### 6.2 Flags

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | DIRTY | Set before mutation, cleared after commit. If set on open → crash recovery needed. |
| 1 | COMPACTING | Defragmentation in progress. If set on open → resume or rollback compaction. |
| 2-31 | RESERVED | Must be zero. |

### 6.3 CRC32C

The superblock CRC covers all fields except itself. CRC32C is NOT a security mechanism — it detects accidental corruption only. Cryptographic integrity of all meaningful data is provided by AEAD at the object level and HMAC at the header level.

### 6.4 Dual Superblock

To protect against superblock corruption during writes, the container maintains TWO superblocks:

```
Block 0: Superblock A (primary)
Block 1: Superblock B (mirror)
```

Update protocol:

1. Write new superblock to the non-active copy.
2. `fsync`.
3. Write new superblock to the active copy.
4. `fsync`.

On open, read both. Use the one with higher epoch and valid CRC. If both are valid with equal epoch, use A. If one is corrupt, use the valid one and repair the other.

**Note:** This shifts the vault header to Block 2+.

### 6.5 Revised Physical Layout with Dual Superblock

```
┌──────────┬──────────────────────────────────────────────────────┐
│ Block 0  │  SUPERBLOCK A (primary)                              │
├──────────┼──────────────────────────────────────────────────────┤
│ Block 1  │  SUPERBLOCK B (mirror)                               │
├──────────┼──────────────────────────────────────────────────────┤
│ Block 2  │  VAULT HEADER                                        │
│   ..N    │                                                      │
├──────────┼──────────────────────────────────────────────────────┤
│ Block N+1│  WAL REGION                                          │
│   ..M    │                                                      │
├──────────┼──────────────────────────────────────────────────────┤
│ Block M+1│  BAM (encrypted)                                     │
│   ..P    │                                                      │
├──────────┼──────────────────────────────────────────────────────┤
│ Block P+1│  INDEX (encrypted)                                   │
│   ..Q    │                                                      │
├──────────┼──────────────────────────────────────────────────────┤
│ Block Q+1│  DATA REGION (encrypted objects)                     │
│   ..end  │                                                      │
└──────────┴──────────────────────────────────────────────────────┘
```

---

## 7. Vault Header

The vault header region stores the SCB-VKA v2 cryptographic metadata as defined in the parent specification (Section 7.4). It is written at vault creation and updated during migration or state mutation (epoch increment; epoch is held in the superblock).

The vault header is treated as an opaque blob by the volume layer. Its internal format is defined entirely by SCB-VKA v2.

---

## 8. Block Allocation

### 8.1 Block Allocation Map (BAM)

The BAM is a bitmap where each bit represents one block in the data region:

```
bit = 0 → block is free
bit = 1 → block is allocated
```

### 8.2 BAM Encryption

The BAM is encrypted as a single object under a dedicated BAM DEK:

```
BAM_DEK ← CSPRNG(256)

Wrapped_BAM_DEK = AEAD_Encrypt(
    key   = KEK,
    nonce = CSPRNG(192),
    aad   = TLV(0x01, VID) || TLV(0xF0, "bam"),
    data  = BAM_DEK
)

Encrypted_BAM = AEAD_Encrypt(
    key   = BAM_DEK,
    nonce = CSPRNG(192),
    aad   = TLV(0x01, VID) || TLV(0xF0, "bam-data") || TLV(0x20, epoch),
    data  = BAM_plaintext
)
```

**Rationale:** Encrypting the BAM prevents an attacker from learning vault utilization, object count approximation, or allocation patterns.

### 8.3 BAM Size

```
BAM bits = total_data_blocks
BAM bytes = ceil(total_data_blocks / 8)
BAM blocks = ceil(BAM_bytes / block_size) + 1   // +1 for wrapped DEK + nonces
```

### 8.4 Allocation Strategy

Block allocation uses a **first-fit** strategy scanning the BAM from the lowest free block. Implementations MAY use more sophisticated strategies (best-fit, buddy system) but MUST maintain BAM consistency.

---

## 9. Object Storage

### 9.1 Slot Model

Each object occupies a **slot**: one or more contiguous blocks in the data region.

```
┌─────────────────────────────────────────────────────┐
│                    SLOT                              │
├─────────────────────────────────────────────────────┤
│  Slot Header (plaintext within encrypted envelope)  │
│  ┌───────────────────────────────────────────────┐  │
│  │  object_id         (16 bytes)                 │  │
│  │  object_version    (4 bytes)                  │  │
│  │  object_type_len   (2 bytes)                  │  │
│  │  object_type       (variable, UTF-8)          │  │
│  │  purpose_len       (2 bytes)                  │  │
│  │  purpose           (variable, UTF-8)          │  │
│  │  payload_size      (8 bytes)                  │  │
│  │  created_epoch     (8 bytes)                  │  │
│  │  modified_epoch    (8 bytes)                  │  │
│  └───────────────────────────────────────────────┘  │
│  Payload (actual user data)                         │
│  Padding (zero-fill to block boundary)              │
├─────────────────────────────────────────────────────┤
│  AEAD overhead:                                     │
│    dek_nonce       (24 bytes)                       │
│    wrapped_dek     (32 bytes)                       │
│    wrap_tag        (16 bytes)                       │
│    data_nonce      (24 bytes)                       │
│    data_tag        (16 bytes)                       │
└─────────────────────────────────────────────────────┘
```

### 9.2 Slot Size Calculation

```
header_size   = 16 + 4 + 2 + object_type_len + 2 + purpose_len + 8 + 8 + 8
payload_size  = len(user_data)
aead_overhead = 24 + 32 + 16 + 24 + 16 = 112 bytes
raw_size      = header_size + payload_size + aead_overhead
slot_blocks   = ceil(raw_size / block_size)
```

### 9.3 Padding

Slots are zero-padded to the next block boundary BEFORE encryption. This ensures:

- All slots are block-aligned (simplifies I/O).
- Exact payload size is hidden from block-level observation (attacker sees only slot_blocks × block_size).

### 9.4 Size Classes

To reduce fragmentation and further obscure object sizes, slot allocation SHOULD use size classes:

| Class | Slot Size | Object Range |
|-------|-----------|--------------|
| TINY | 1 block (4 KiB) | ≤ ~3.9 KiB |
| SMALL | 4 blocks (16 KiB) | ≤ ~15.8 KiB |
| MEDIUM | 16 blocks (64 KiB) | ≤ ~63.8 KiB |
| LARGE | 64 blocks (256 KiB) | ≤ ~255.8 KiB |
| HUGE | exact fit (block-aligned) | > 256 KiB |

Objects in TINY through LARGE classes are allocated to the next size class, wasting some space but making all objects within a class indistinguishable in size. HUGE objects use exact block-aligned allocation.

---

## 10. Encrypted Index

### 10.1 Purpose

The index provides O(log n) object lookup by object_id without decrypting every slot in the data region.

### 10.2 Structure

The index is an encrypted **B-tree** with the following parameters:

```
Key:    object_id (16 bytes, UUID)
Value:  IndexEntry {
            slot_start:     u48,        // Starting block number
            slot_blocks:    u16,        // Number of blocks
            object_version: u32,        // Current version
            object_type:    [u8; 64],   // Padded, fixed-width
            epoch_created:  u64,        // Creation epoch
            epoch_modified: u64,        // Last modification epoch
        }

B-tree order: chosen so that one node fits in one block
Node capacity: floor((block_size - node_overhead) / entry_size)
```

### 10.3 Index Encryption

Each B-tree node is individually encrypted as a separate object:

```
INDEX_DEK ← CSPRNG(256)                    // One DEK for entire index

Wrapped_INDEX_DEK = AEAD_Encrypt(
    key   = KEK,
    nonce = CSPRNG(192),
    aad   = TLV(0x01, VID) || TLV(0xF0, "index"),
    data  = INDEX_DEK
)

// Per-node encryption:
Encrypted_Node[i] = AEAD_Encrypt(
    key   = INDEX_DEK,
    nonce = CSPRNG(192),
    aad   = TLV(0x01, VID) || TLV(0xF0, "index-node") || TLV(0x20, node_id),
    data  = Node[i]_plaintext
)
```

**Rationale:** Per-node encryption allows reading individual nodes without decrypting the entire index. A single INDEX_DEK avoids per-node key derivation overhead during traversal.

### 10.4 Index Updates

On object insertion, modification, or deletion:

1. Traverse B-tree to locate insertion/update point.
2. Modify affected nodes in memory.
3. Re-encrypt modified nodes with fresh nonces.
4. Write modified nodes through WAL (Section 12).

### 10.5 Root Node Location

The index root node is always at the first block of the index region. The wrapped INDEX_DEK is stored immediately before the root node in the same block.

---

## 11. Free Space Management

### 11.1 Free List

In addition to the BAM bitmap, a **free list** is maintained as an in-memory structure rebuilt from the BAM on vault open. The free list groups contiguous free blocks:

```
FreeExtent {
    start_block: u48,
    length:      u48,
}
```

The free list is sorted by start_block for efficient first-fit allocation.

### 11.2 Free List Recovery

The free list is NOT stored on disk. It is reconstructed by scanning the BAM on vault open. This avoids an additional encrypted structure and a second source of truth that could become inconsistent.

### 11.3 Fragmentation Metric

```
fragmentation = 1 - (largest_free_extent / total_free_blocks)
```

When fragmentation exceeds a threshold (RECOMMENDED: 0.7), the implementation SHOULD suggest or trigger defragmentation (Section 16).

---

## 12. Write-Ahead Log (WAL)

### 12.1 Purpose

The WAL ensures atomic multi-block mutations. Every mutation that touches more than one block (e.g., write object + update BAM + update index + update superblock) goes through the WAL.

### 12.2 WAL Structure

The WAL region is a fixed-size circular buffer of WAL frames:

```
┌─────────────────────────────────────────────────┐
│                  WAL FRAME                      │
├─────────────────┬────────┬──────────────────────┤
│ Field           │ Size   │ Description          │
├─────────────────┼────────┼──────────────────────┤
│ frame_magic     │ 4 B    │ "WALF"               │
│ epoch           │ 8 B    │ Mutation epoch        │
│ sequence        │ 4 B    │ Frame sequence in txn │
│ total_frames    │ 4 B    │ Total frames in txn   │
│ target_block    │ 6 B    │ Destination block #   │
│ data_len        │ 4 B    │ Payload length        │
│ data            │ var    │ Block content to write │
│ frame_crc       │ 4 B    │ CRC32C of frame       │
└─────────────────┴────────┴──────────────────────┘
```

### 12.3 WAL Encryption

WAL frames contain block data that may include encrypted content (objects, index nodes, BAM). The WAL itself adds an additional encryption layer:

```
WAL_DEK ← CSPRNG(256)                      // Rotated each vault session

Encrypted_WAL_Frame = AEAD_Encrypt(
    key   = WAL_DEK,
    nonce = CSPRNG(192),
    aad   = epoch || sequence || target_block,
    data  = WAL_Frame_plaintext
)
```

WAL_DEK exists only in volatile memory. On vault close, WAL is flushed and WAL_DEK is zeroized. An unclean WAL after crash contains encrypted frames that can only be replayed if the vault is unlocked (key derivation succeeds).

### 12.4 WAL Capacity

```
Default WAL size: 64 blocks = 256 KiB
Maximum single transaction: must fit within WAL capacity
```

If a transaction exceeds WAL capacity, it MUST be split into multiple atomic sub-transactions, each independently crash-safe.

---

## 13. Atomic Mutation Protocol

### 13.1 Write Path

Every mutation follows this protocol:

```
MUTATION PROTOCOL (e.g., "add object")
═══════════════════════════════════════

Phase 1: PREPARE
  1. Allocate slot in BAM (in-memory only)
  2. Encrypt object → ciphertext
  3. Compute new index node(s) with new entry
  4. Re-encrypt modified index nodes
  5. Update BAM bitmap
  6. Re-encrypt BAM

Phase 2: WAL WRITE
  7. Set DIRTY flag in superblock
  8. fsync superblock
  9. Write all modified blocks as WAL frames:
     - New object slot block(s)
     - Modified index node block(s)
     - Modified BAM block(s)
  10. Write WAL COMMIT marker (final frame with sequence == total_frames)
  11. fsync WAL region

Phase 3: CHECKPOINT
  12. Copy WAL frame data to target blocks
  13. fsync data region, index region, BAM region
  14. Increment epoch
  15. Update superblock (new epoch, clear DIRTY flag)
  16. fsync superblock (dual-write protocol, Section 6.4)

Phase 4: CLEANUP
  17. Invalidate WAL frames (write zero to frame_magic)
  18. Update vault header (Header MAC; epoch is in superblock per Section 6)
  19. fsync vault header
```

### 13.2 Crash at Any Phase

| Crash Point | Recovery Action |
|-------------|-----------------|
| During Phase 1 | No on-disk changes. Clean restart. |
| During Phase 2 (before COMMIT) | Incomplete WAL. Discard all frames for this epoch. |
| During Phase 2 (after COMMIT) | WAL is complete. Replay WAL to target blocks. |
| During Phase 3 | Some blocks written, some not. Replay entire WAL. |
| During Phase 4 | Blocks are consistent. Re-run Phase 4 cleanup. |

**Invariant:** At no point does the container have partially written data without a recoverable path.

---

## 14. Secure Deletion

### 14.1 Cryptographic Erasure

When an object is deleted:

```
DELETE PROTOCOL
═══════════════

1. Mark slot blocks as free in BAM.
2. Remove object from index.
3. Destroy the object's wrapped DEK:
   - Overwrite wrapped_dek bytes in slot with CSPRNG output.
   - This is the PRIMARY deletion mechanism.
   - Without DEK, ciphertext is computationally indistinguishable from random.
4. Optionally overwrite slot data blocks with CSPRNG output (defense-in-depth).
5. Commit via Atomic Mutation Protocol.
```

### 14.2 Why Cryptographic Erasure is Sufficient

Each object has an independent random DEK. Destroying the wrapped DEK makes the ciphertext irrecoverable regardless of whether the actual ciphertext blocks are overwritten. This is because:

- DEK was CSPRNG(256) — no derivation path exists to reconstruct it.
- KEK is never stored at rest — rewrapping is impossible without vault unlock.
- Ciphertext without DEK is indistinguishable from random (IND-CCA2).

### 14.3 Physical Overwrite (Defense-in-Depth)

Implementations SHOULD overwrite freed blocks with CSPRNG output when:

- The vault is on an HDD (no wear-leveling concerns).
- The vault is on an SSD with TRIM support (issue TRIM after overwrite).

Implementations MUST NOT rely solely on physical overwrite — cryptographic erasure is the normative mechanism.

### 14.4 Limitations

- SSD wear-leveling may retain old block copies in hidden sectors. Cryptographic erasure handles this — even if old ciphertext is recovered from wear-leveled sectors, the DEK is destroyed.
- Copy-on-write filesystems (ZFS, Btrfs) may retain old file versions. Same defense: no DEK, no recovery.

---

## 15. Container Resize

### 15.1 Growth

```
GROW PROTOCOL
═════════════

1. Extend container file to new size (ftruncate / fallocate).
2. Calculate new total_blocks.
3. Extend BAM bitmap (new bits initialized to 0 = free).
4. Re-encrypt BAM.
5. Update superblock (new total_blocks, new BAM size).
6. Commit via Atomic Mutation Protocol.
```

### 15.2 Shrink

```
SHRINK PROTOCOL
═══════════════

1. Verify all blocks beyond new boundary are free.
   - If not: relocate objects to lower blocks (mini-defrag), then retry.
2. Truncate BAM bitmap.
3. Re-encrypt BAM.
4. Update superblock (new total_blocks, new BAM size).
5. Commit via Atomic Mutation Protocol.
6. Truncate container file (ftruncate).
```

### 15.3 Constraints

- Container MUST NOT be shrunk below: superblock + vault header + WAL + BAM + index + allocated data blocks.
- Growth is always safe and non-destructive.
- Shrink requires all data to fit in the new capacity.

---

## 16. Defragmentation

### 16.1 Online Defragmentation

Defragmentation relocates objects to consolidate free space without vault downtime:

```
DEFRAG PROTOCOL (per-object)
════════════════════════════

1. Read object from current slot.
2. Allocate new contiguous slot at lower address.
3. Write object to new slot (data is already encrypted, copy as-is).
4. Update index entry to point to new slot.
5. Free old slot blocks in BAM.
6. Commit via Atomic Mutation Protocol.
7. Overwrite old slot with CSPRNG (secure deletion).
```

### 16.2 Safety

Each object relocation is an independent atomic transaction. Crash during defrag leaves at most one object in an intermediate state, recoverable via WAL replay.

### 16.3 Trigger

Defragmentation SHOULD be triggered when fragmentation metric (Section 11.3) exceeds 0.7, or when a large object allocation fails despite sufficient total free space.

---

## 17. Crash Recovery

### 17.1 Recovery Protocol

On container open, if the DIRTY flag is set in the superblock:

```
CRASH RECOVERY
══════════════

1. Read both superblocks. Select valid one with highest epoch.
2. If DIRTY flag set:
   a. Scan WAL for complete transactions (valid COMMIT marker).
   b. For each complete transaction (by epoch order):
      - Replay WAL frames to their target blocks.
      - fsync affected regions.
   c. Discard incomplete transactions (no COMMIT marker).
   d. Re-encrypt BAM from replayed state.
   e. Clear DIRTY flag, update epoch, write superblock.
   f. fsync superblock.
3. If COMPACTING flag set:
   a. Scan WAL for in-progress defrag transaction.
   b. If complete: replay and finalize.
   c. If incomplete: discard (object remains at original location).
   d. Clear COMPACTING flag.
4. Rebuild free list from BAM.
5. Proceed to normal unlock.
```

### 17.2 Recovery Requires Unlock

WAL frames are encrypted with WAL_DEK, which is session-only. After a crash, WAL frames from the previous session cannot be decrypted — the WAL_DEK is lost.

**Resolution:** WAL frame data contains already-encrypted blocks (objects encrypted under their DEK, BAM encrypted under BAM_DEK, index under INDEX_DEK). The WAL encryption layer is optional defense-in-depth. For crash recovery, the implementation MUST store WAL frames in two modes:

- **Payload-transparent mode (REQUIRED):** WAL frame data is the encrypted block content as it would appear on disk. No additional WAL encryption. Recovery simply copies frame data to target blocks.
- **Payload-encrypted mode (OPTIONAL):** Additional WAL_DEK layer. Provides defense against WAL region forensics but requires WAL_DEK persistence strategy (e.g., sealed to HSP for session duration).

Implementations MUST default to payload-transparent mode to ensure crash recoverability.

### 17.3 Consistency Guarantees

After recovery, the container is in one of two states:

- **Pre-mutation state:** The interrupted transaction was not committed. Container reflects the state before the mutation.
- **Post-mutation state:** The interrupted transaction was committed (COMMIT marker present). Container reflects the completed mutation via WAL replay.

No intermediate state is possible.

---

## 18. Concurrency

### 18.1 Single-Writer Model

SCB-VKA containers use a **single-writer, multiple-reader** model:

- Only one process may hold a write lock on the container at a time.
- Multiple processes may read simultaneously (after independent unlock).
- Write lock is implemented via OS-level file locking (`flock` / `LockFileEx`).

### 18.2 Lock File

```
Lock mechanism: flock(fd, LOCK_EX | LOCK_NB) on the container file.
```

If exclusive lock cannot be acquired, the implementation MUST fail with an explicit "vault in use" error. Implementations MUST NOT queue or retry silently.

### 18.3 Read Concurrency

Readers operate on a snapshot-consistent view:

1. Reader notes current epoch from superblock.
2. Reader uses only blocks consistent with that epoch.
3. If writer commits a new epoch during read, reader continues with its snapshot epoch (stale but consistent reads).

### 18.4 No Network/Distributed Access

SCB-VKA containers are local-only. Network-shared filesystems (NFS, SMB) are NOT supported due to unreliable file locking semantics. Implementations SHOULD detect network-mounted paths and warn the user.

---

## 19. Security Properties

### 19.1 Volume-Level Guarantees

**VS1 — Opacity (VG-OPAQUE)**

Beyond the superblock (which contains only format identification and structural metadata), all container content is encrypted. An attacker observing the container file learns:

- That it is an SCB-VKA container (from magic bytes).
- Total container size (from file size).
- Nothing else. Object count, sizes, types, allocation patterns, and index structure are all encrypted.

**VS2 — Allocation Pattern Hiding**

BAM encryption prevents the attacker from learning which blocks are allocated. The container appears as: known superblock + uniform random data.

**VS3 — Size Class Obfuscation**

Size class allocation (Section 9.4) ensures objects within the same class are indistinguishable in size at the block level.

**VS4 — Deletion Irrecoverability**

Cryptographic erasure (Section 14) ensures deleted objects are irrecoverable without the destroyed DEK, regardless of physical media behavior (wear-leveling, copy-on-write).

**VS5 — Crash Atomicity**

WAL-based mutation protocol (Section 13) guarantees the container is always in a consistent, recoverable state.

**VS6 — Temporal Isolation**

Epoch-bound AAD in BAM and index encryption prevents cross-epoch replay attacks. An attacker cannot substitute an old BAM or index snapshot without detection.

---

## 20. Implementation Requirements

### 20.1 MUST

1. Container MUST be a single file.
2. Block size MUST be fixed at creation and stored in superblock.
3. Dual superblock MUST be implemented per Section 6.4.
4. All mutations MUST go through the WAL-based Atomic Mutation Protocol.
5. BAM MUST be encrypted per Section 8.2.
6. Index MUST be encrypted per Section 10.3.
7. Object deletion MUST perform cryptographic erasure (DEK destruction).
8. File locking MUST be used for write exclusivity.
9. WAL payload-transparent mode MUST be the default.
10. Crash recovery MUST be performed on open if DIRTY flag is set.

### 20.2 SHOULD

1. Size class allocation SHOULD be used for objects ≤ 256 KiB.
2. Physical overwrite SHOULD follow cryptographic erasure on HDDs.
3. Defragmentation SHOULD be triggered at fragmentation > 0.7.
4. Network filesystem detection SHOULD warn the user.
5. Container growth SHOULD use `fallocate` where available for performance.

### 20.3 MUST NOT

1. Container MUST NOT store any key material (this is enforced by SCB-VKA v2).
2. BAM MUST NOT be readable without vault unlock.
3. Index MUST NOT be readable without vault unlock.
4. WAL MUST NOT contain unencrypted object data in payload-encrypted mode.
5. Implementation MUST NOT allow concurrent writers.

---

## 21. Compliance Criteria

An implementation is **SCB-VKA Volume Format v1.0 compliant** if and only if:

1. Container is a single file with the physical layout defined in Section 5/6.5.
2. Dual superblock is implemented per Section 6.4.
3. All data regions (BAM, index, objects) are encrypted per their respective sections.
4. Atomic Mutation Protocol (Section 13) is followed for all mutations.
5. Crash recovery (Section 17) is implemented and tested.
6. Secure deletion via cryptographic erasure (Section 14) is implemented.
7. Single-writer concurrency model (Section 18) is enforced.
8. All Section 20.1 (MUST) and 20.3 (MUST NOT) requirements are satisfied.
9. The volume layer interfaces with SCB-VKA v2 cryptographic layer without violating any SCB-VKA v2 compliance criteria.

---

*End of Specification*