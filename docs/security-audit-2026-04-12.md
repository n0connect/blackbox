# BlackBox Security Audit Notes (2026-04-12)

## Scope
- Workspace-wide security and robustness review aligned with project philosophy:
  - plaintext processing should stay in RAM,
  - key material should remain hardware-bound (`TPM` / `Secure Enclave`) and zeroized in-process,
  - vault mutations should be crash-safe and non-destructive.

## Project Intent (Observed)
- `scb-vka-orchestrator` coordinates all vault operations and enforces A/B header commit strategy.
- `scb-vka-crypto` performs streaming AEAD + MAC and key derivation with hardware-bound MR step.
- `scb-vka-memory` provides `mlock`-based containers and secure wipe primitives.
- CLI/Shell are thin interfaces over orchestrator.

## Findings

### Fixed

1. `create_vault` could silently destroy existing vault files.
- Severity: High
- Location: `crates/scb-vka-orchestrator/src/lib.rs`
- Problem:
  - `OpenOptions` used `create(true).truncate(true)`.
  - Existing vault paths could be truncated before any validation.
- Fix:
  - Switched to `create_new(true)` and mapped `AlreadyExists` to `InvalidInput`.
  - Added secure file mode (`0o600`) on Unix for newly created vault files.
  - CLI now fails early on `create` if target path already exists.

2. `add_object` had incomplete rollback paths after block allocation.
- Severity: High
- Location: `crates/scb-vka-orchestrator/src/lib.rs`
- Problem:
  - Several failure paths after allocation returned early without deallocation.
  - Could drift bitmap state and orphan encrypted chunks.
- Fix:
  - Added transactional post-allocation flow.
  - Any failure now triggers best-effort rollback:
    - secure wipe of allocated region,
    - deallocate in `SpaceManager`,
    - critical error logging if rollback itself fails.

3. `commit_header` could leave in-memory state advanced on failed writes.
- Severity: Medium
- Location: `crates/scb-vka-orchestrator/src/lib.rs`
- Problem:
  - Header epoch/slot could mutate before durable commit succeeded.
- Fix:
  - Added transactional guard:
    - snapshot old header + active slot,
    - restore both if commit fails.

4. CLI command paths did not guarantee `lock_vault` on operation failure.
- Severity: Medium
- Location: `crates/scb-vka-cli/src/main.rs`
- Problem:
  - `add/read/list/delete` returned early on errors before `lock_vault`.
- Fix:
  - Added `with_unlocked_session(...)` helper.
  - Always attempts lock cleanup after operation (both success/failure paths).

5. CLI prompt used `flush().unwrap()` and could panic.
- Severity: Low
- Location: `crates/scb-vka-cli/src/main.rs`
- Fix:
  - Replaced with fallible `flush()` + contextual error propagation.

6. Read output file permissions were not tightened.
- Severity: Low
- Location: `crates/scb-vka-cli/src/main.rs`
- Fix:
  - `read --output` now creates/truncates output with mode `0o600` on Unix.

7. Orchestrator error paths leaked internal diagnostics via `eprintln!`.
- Severity: Low
- Location: `crates/scb-vka-orchestrator/src/lib.rs`
- Fix:
  - Removed `eprintln!` in core mutation flow and mapped to typed errors/logging.

8. Shell `cat` path copied decrypted plaintext to an extra heap allocation.
- Severity: Low
- Location: `crates/scb-vka-shell/src/lib.rs`
- Fix:
  - Replaced `String::from_utf8(buf.to_vec())` with `std::str::from_utf8(buf.as_slice())`.

9. Fuzzing coverage had parser/allocator blind spots.
- Severity: Medium
- Locations: `fuzz/`
- Fix:
  - Added new fuzz targets:
    - `fuzz_layout_parse` (superblock/header/entry parse surfaces),
    - `fuzz_space_manager` (allocation/deallocation/expand state machine).
  - Hardened existing `fuzz_crypto_decrypt` harness by removing `unwrap()`.
  - Updated `Makefile` `fuzz` target to execute new fuzzers.

10. macOS Secure Enclave provisioning fallback path was not explicit to operators.
- Severity: Medium
- Location: `crates/scb-vka-hsp/src/macos.rs`
- Problem:
  - Users could fail direct Secure Enclave initialization in unsigned/outdated profile setups without clear trust posture messaging.
- Fix:
  - Implemented explicit mode flow:
    - try direct Secure Enclave key first,
    - on profile/entitlement-class failures (`-34018`, `-50`) fallback to Keychain-isolated key.
  - Added warning logs that fallback is software-isolated and increases attack surface.
  - Added warning logs on key usage/init when fallback mode is active.
  - `clear_hardware_keys` now removes both direct and fallback key labels.

11. Platform support claims were broader than build reality.
- Severity: Medium
- Locations: `crates/scb-vka-hsp/*`, `README.md`, `docs/scb-vka-modules.md`
- Problem:
  - Windows TPM backend path relied on `tss-esapi-sys`, but upstream tuple support currently excludes Windows.
  - Documentation still advertised production Windows TPM support.
- Fix:
  - Enforced compile-time error on Windows builds with explicit "backend WIP" message.
  - Narrowed current supported runtime matrix to Linux TPM + macOS Secure Enclave.
  - Updated docs to reflect implementation status and avoid false security expectations.

## Open/Residual Risks

1. `SecureBox::new` still has a tiny pre-`mlock` window.
- Location: `crates/scb-vka-memory/src/lib.rs`
- Status: Known limitation documented in code.
- Note:
  - Eliminating this fully requires lower-level allocation strategy (unsafe/uninit/page-locked allocator).

2. User-driven plaintext export is still possible by design (`read --output`).
- Location: CLI behavior
- Status: Intentional feature; operational policy should restrict usage in high-security deployments.

## Verification Plan (Executed)
- Full workspace tests:
  - `cargo test --workspace`
- Full workspace compile checks:
  - `cargo check --workspace --all-targets`
- Additional fuzzing:
  - `cargo +nightly fuzz run fuzz_ansi -- -max_total_time=...`
  - `cargo +nightly fuzz run fuzz_parser -- -max_total_time=...`
  - `cargo +nightly fuzz run fuzz_crypto_decrypt -- -max_total_time=...`
  - `cargo +nightly fuzz run fuzz_layout_parse -- -max_total_time=...`
  - `cargo +nightly fuzz run fuzz_space_manager -- -max_total_time=...`
  - Cross-target smoke checks:
    - `cargo check --workspace --target x86_64-unknown-linux-gnu`
    - `cargo check -p scb-vka-hsp --target x86_64-pc-windows-gnu`
    - `cargo check -p scb-vka-hsp --target x86_64-pc-windows-msvc`

### Verification Result
- `cargo test --workspace`: PASS
- `cargo check --workspace --all-targets`: PASS
- `fuzz_parser`: PASS (`-max_total_time=3`)
- `fuzz_ansi`: PASS (`-max_total_time=3`)
- `fuzz_crypto_decrypt`: PASS (`-max_total_time=3`)
- `fuzz_layout_parse`: PASS (`-max_total_time=3`)
- `fuzz_space_manager`: PASS (`-max_total_time=3`)
- Fuzz re-run in this environment: BLOCKED (offline/DNS restriction while resolving crates.io index for isolated fuzz workspace).
- `cargo check --workspace --target x86_64-unknown-linux-gnu`: FAIL in this macOS env (missing cross pkg-config/sysroot for TPM libs), implementation unaffected.
- `cargo check -p scb-vka-hsp --target x86_64-pc-windows-gnu`: expected COMPILE ERROR (unsupported toolchain/backend).
- `cargo check -p scb-vka-hsp --target x86_64-pc-windows-msvc`: not fully verifiable in this host (target stdlib not installed). Backend is intentionally compile-gated as WIP on Windows.
