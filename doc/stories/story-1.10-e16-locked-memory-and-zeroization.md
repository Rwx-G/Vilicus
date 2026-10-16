---
title: 'E16: locked memory and zeroization'
epic: 1
story: 10
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E16, FR-13, AD-4]
---

# Story 1.10: E16: locked memory and zeroization

As the owner,
I want locked memory and zeroization checked in the Rust runtime, crash paths included,
So that the key hygiene claim of FR-13 is backed by an observation, or the unlock window is shortened.

**Acceptance Criteria:**

**AC1 (E16, FR-13, AD-4)**
**Given** a prototype under `spikes/e16-memory/` holding key buffers in `mlock`ed memory with `zeroize` on drop, `PR_SET_DUMPABLE` off and core dumps disabled
**When** the keys are dropped and the process memory is inspected for the key bytes
**Then** no key material is found in the tested paths

**AC2 (E16, FR-13)**
**Given** the same prototype
**When** it panics and when it is killed while keys are held
**Then** no core dump is written, and the record states what a crash leaves in memory until the process ends

**AC3 (E16, FR-13)**
**Given** key material is found after drop in a tested path
**When** the result is recorded
**Then** the fallback is recorded in `doc/decisions.md`: a shorter unlock window maximum (FR-12) stated in the documentation, a lower web session maximum, and keys of idle partitions dropped earlier

**Spike plan:**
- Question: does locked memory and zeroization behave as designed in the Rust runtime, including on crash (E16)?
- Method: tests with core dumps disabled; inspection of process memory after key drop; panic and kill paths.
- Pass criterion: no key material found after drop in tested paths.
- Timebox: 3 working days.
- Fallback on failure: a shorter unlock window maximum (FR-12) stated in the documentation; lower the web session maximum and drop idle partition keys earlier.
- Result record: E16 status in `doc/research-notes.md` with the inspection method kept for the regression test of Story 4.2.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E16)
- `doc/prd.md` FR-13, section 9
- `doc/architecture-spine.md` AD-4
- `doc/key-management.md` section 10
- `doc/architecture.md` section 4 (memory hygiene)

## Implementation Notes

**What was built.** A standalone crate, `spikes/locked-memory/` (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`), and `spikes/locked-memory/run.sh`, which builds and runs everything in Debian 13 Rust containers pinned by digest (`rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a`, the `rust:1-trixie` tag as pulled on 2026-10-16). It prints one `PASS <name>` or `FAIL <name>` line per step and per check, and `INFO` lines for measurements that are not pass criteria. It exits non-zero on any failure, on any ignored test, or if a container fails.

- `src/pool.rs` is the key memory a `vilicus-crypto` could use.
  - One anonymous mapping, allocated before any key exists, with a `PROT_NONE` guard page on each side. The usable part is advised `MADV_DONTDUMP` and `MADV_WIPEONFORK`, locked with `mlock`, and cut into 64-byte slots.
  - The pool is the process's only one: a second `LockedPool::new` returns `AlreadyRegistered`. `PLANNED_SLOTS` holds the sizing rule (settled task 1).
  - A `Slot` is not `Clone` or `Debug` and wipes its whole slot with volatile writes on drop. A refused `mlock` returns a typed error and unmaps.
  - The module also holds the process hardening (`PR_SET_DUMPABLE` 0, `RLIMIT_CORE` 0) and the AD-9 handler boundary (`handler_boundary`, a thread-local flag around `catch_unwind`). It holds the Core panic hook: it does nothing inside a boundary, and wipes the pool then aborts outside one. It also holds the SIGTERM wiper (SIGTERM blocked, then taken on a `signalfd` thread that wipes the pool before exit).
  - It holds the stack scrub: 64 KiB of zeroes written with volatile writes below the caller's frame, then `vzeroall` when the CPU has AVX. `ScrubOnDrop` is a guard that runs the scrub on every exit path, the error path included.
  - It holds a stack canary (`paint_stack` and `deepest_stack_use`) that measures how deep a key operation reaches, and readers for `/proc/self/smaps`, `status` and `pagemap`.
- `src/material.rs`: the harness draws fresh random secrets for each run: a plain key, a passphrase, a DEK, the household key, a member X25519 private key, and the 32 bytes that seed an HPKE ephemeral key.
  - It writes them to a file, with the public values derived from them: the DEK wrapped under the Argon2id KEK, and the household key wrapped to the member public key with HPKE.
  - The subject reads each secret with `pread` straight into a locked slot, so the only copies in its memory are those the code under test makes.
- `src/subject.rs`: the process under inspection. Each code path runs in two variants:
  - `core` is the shape proposed for the Core: hardened process, keys in slots, Argon2id memory owned and wiped through a wiping wrapper, AEAD and HKDF objects built from the slot and dropped inside the operation, HPKE opened in place, each key operation in an `#[inline(never)]` function under a scrub guard, with the canary depth reported.
  - `asis` is the same operations the way the crates offer them by default: no scrub, `hash_password_into`, the `Vec`-returning `single_shot_open`, and key objects kept by the caller.
  - The paths are:
    - copies of a key to the heap and to the deep end of a 16 KiB stack frame;
    - passphrase unlock: Argon2id KEK, then the DEK opened in place and sealed again with aws-lc-rs AES-256-GCM;
    - file key derivation with aws-lc-rs HKDF-SHA-256, and a record sealed and opened with that key;
    - household key unwrap: HPKE open with the member private key, on the main thread and on a spawned thread;
    - household key wrap: HPKE seal with an ephemeral key seeded from a planted value;
    - a wrong passphrase wrap, where the open fails after Argon2id.
  - The subject stops at `LIVE` (operations done, keys held), at `WIPED` (passphrase path, after the Argon2id wipe and before the buffer is freed) and at `DROPPED` (everything dropped). Further scenarios hold keys and then panic inside and outside a handler boundary, unwind, receive SIGTERM, fork, fault, get signalled, get swapped out, or let the harness open their memory before they harden.
- `src/patterns.rs`: the harness recomputes, from the material, every value it searches for:
  - the secrets, the KEK, and the first 64 bytes of the first and last Argon2id memory blocks;
  - the HKDF PRK and the file key;
  - the X25519 clamped scalars and their radix-16 digits, and the DH outputs;
  - the HPKE `dkp_prk`, ephemeral private key, `eae_prk`, shared secret, key schedule `secret`, AEAD key, base nonce and exporter secret;
  - the SHA-256 states of an HMAC keyed with each PRK;
  - the GHASH key of each AES-GCM key, raw and in the POLYVAL form.
- `src/scan.rs`: the harness reads every mapping of the subject through `/proc/<pid>/mem`, non-readable ones included (guard pages, `PROT_NONE` pages, thread stack guards). The kernel forces the access for a tracer.
  - Only `[vvar]`, `[vvar_vclock]` and `[vsyscall]` are skipped: they are kernel time data and an emulated syscall page, never process memory.
  - A scan fails if any other mapping cannot be read, so an unread region cannot pass as an empty one.
  - Hits are classified as pool, heap, stack, other anonymous memory or file-backed. A pattern is cut into 16-byte windows every 8 bytes; any surviving run of 23 bytes or more is detected.
  - A window shared with another pattern (a key and its clamped form share their middle) is ignored for a pattern that has windows of its own.
- `src/checks.rs`: the checks, in four groups run by four containers (below). `tests/units.rs` has 8 tests:
  - the pool, in one test because the pool is one per process: wipe on drop and reuse, `wipe_all`, refusal of a second registration, of an oversized slot and of an allocation once all slots are taken, and a capacity of at least `PLANNED_SLOTS`;
  - the scanner: whole, damaged and too-short copies, and attribution of shared windows;
  - the pattern derivations against the libraries.

**Containers and capabilities.** Each container gets only what its checks need:

- `main`: `--cap-add SYS_PTRACE`, because the harness must read a non-dumpable subject's memory (the R1 attacker, root on the host, has that capability), and `--ulimit memlock=8388608:8388608`, the systemd default `LimitMEMLOCK` of 8 MiB. Build, format, lint, tests, the zeroize feature check, then the scans, the panics, SIGTERM, kill, fork, the lowered-limit refusal and the scrub cost.
- `noptrace`: no added capability, same memlock limit. Same-user memory reading, the descriptor opened before hardening, and the core dump checks.
- `nomemlock`: no added capability, `--ulimit memlock=0:0`. The refused `mlock` case.
- `swap`: no added capability, `--memory 256m --memory-swap 1g`. Locked and unlocked pages under memory pressure.

No container gets `CAP_IPC_LOCK`.

**Dependencies** (exact versions from `Cargo.lock`):

- `libc` 0.2.190 (already in the tree) and `zeroize` 1.9.1 (in the spine stack). `memsec`, `region` and `secrecy` were not added: the pool is a small module over `libc`, which is the shape Story 4.2 AC3 expects.
- `aws-lc-rs` 1.18.2 (`aws-lc-sys` 0.46.0), features `aws-lc-sys` and `alloc`: the AES-256-GCM and HKDF of AD-18.
- `argon2` =0.6.0, features `alloc` and `zeroize`.
- `hpke` =0.13.0 with `x25519` and `alloc`, plus the U1 lines of `spikes/hpke-review`. These are `x25519-dalek` 2.0.1, `aes` 0.8.4, `aes-gcm` 0.10.3, `ghash` 0.5.1 and `polyval` 0.6.2, each with `zeroize`; `curve25519-dalek` 4.1.3 follows. `run.sh` step `zeroize_features` verifies the resolved features, `argon2` included.
- `hkdf` 0.12.4 and `sha2` 0.10.9 (feature `compress`): used by the harness only, both already in hpke's tree.
- Toolchain: rustc and cargo 1.99.1. `rustfmt` and `clippy` are added by `run.sh`, which needs network access for that step.

**Deviations.**

- Location: AC1 names `spikes/e16-memory/`; the spike is in `spikes/locked-memory/`, as the epic's spike dispatch asked.
- Argon2id runs at the crate default (19 MiB, 2 passes, 1 lane), not the E12 parameters.
- The Core shape is a prototype of the rules below, not `vilicus-crypto`. The passphrase reaches the subject through `pread`, not through the Gateway and the Core's IPC framing.
- The panic hook and the SIGTERM wiper accept an observer callback that pauses so the harness can scan between the wipe and the end of the process. That is spike instrumentation; the Core passes none, so its hook does no I/O before aborting.

**Review follow-up.** A review of the first version raised twelve points. Each was verified against the code and the measurements. All held, and each was fixed or recorded as an accepted limit:

1. The panic hook could not know whether a panic would be caught by an AD-9 boundary. Fixed: a thread-local boundary flag set by `handler_boundary`. Check `panic-inside-boundary-keeps-keys` then `panic-outside-boundary-wipes` runs both cases in one process.
2. A descriptor or ptrace attach taken before `PR_SET_DUMPABLE` 0 keeps working. Confirmed by `preopened-descriptor-survives-hardening`; recorded as a limit, with the dedicated-user rule of settled task 3.
3. Unreadable mappings were counted, not failed, and live controls asserted pool hits only. Fixed: a scan now reads every mapping, non-readable ones included, and fails on any unreadable mapping. Every `asis` run asserts residue on the stack or heap (`*-asis-residue-control`) as the control of the matching `core` absence.
4. The Argon2id wipe was never observed. Fixed: `passphrase-core-argon2-wipe` scans after the wipe, while the buffer is still allocated, against the scan before the wipe.
5. Error paths skipped the Argon2id wipe and the stack scrub. Fixed: a wiping wrapper for the Argon2id memory and a `ScrubOnDrop` guard. The new `passphrase-wrong` scenario fails the open and is scanned afterwards.
6. aws-lc-rs key objects keep the key on the unlocked heap. Confirmed by `*-asis-key-object-on-unlocked-heap`. The Core shape now builds AEAD and HKDF objects per operation and drops them (`*-core-no-key-object-at-rest`). The rule is in settled task 6 and in the proposed decision record.
7. The stack copy had no positive control, and the scrub depth was unmeasured. Fixed: `copies-*-live-stack-control`, and a canary measured on every guarded key operation (`*-stack-depth`, failing when the depth plus 8 KiB exceeds the 64 KiB scrub).
8. The Core-shape rules rested on convention. Recorded: a closure-only slot API is proposed in settled task 9, and the scrub cost is measured (`scrub-cost`). SQLCipher's internal key handling is named outside the rule.
9. Thread stacks were never exercised. Fixed: `hpke-open-thread-core-residue` and `hpke-open-thread-asis-residue`.
10. Vector registers could be spilled after the scrub. Partly fixed: the scrub ends with `vzeroall` (ymm0 to ymm15). AVX-512 registers zmm16 to zmm31 are listed in Limits.
11. Pool gaps. Fixed: a second registration is an error, there are `PROT_NONE` guard pages (`pool-guard-pages`), and there is a sizing rule tested at planned size (unit test). The production hook only wipes and aborts.
12. Abort paths that skip the hook. Listed under AC2. SIGTERM now has a `signalfd` wiper (`sigterm-wipes-pool`).

Weak checks were tightened too: `kill-while-held` requires a read of exactly 0 bytes, `dumpable-off-blocks-same-user-reader` requires `EACCES` or `EPERM`, and the refusal checks require the subject to report `keys_read=0`.

**Open decision tasks settled.** The story lists none explicitly. The spike settles the ones its result forces, with the recommended answer:

1. **Key memory is one locked pool per process.** It is allocated at Core start before any key exists, framed by `PROT_NONE` guard pages, and advised `MADV_DONTDUMP` and `MADV_WIPEONFORK`. Slots are wiped on drop, and a second pool is refused.
   - Sizing rule: the pool holds at least `PLANNED_SLOTS` (in `src/pool.rs`). That is, for each of 8 unlocked adults, the DEK, the household key, the member private key, 16 open file keys and 4 transient slots, plus the instance-level keys and transient slots.
   - The spike's 4-page pool (256 slots) is above it, and the unit test fills the pool to capacity and checks the refusal after it.
2. **When `mlock` is refused, the Core fails closed.** It refuses to start, with a typed error naming `LimitMEMLOCK`, and never falls back to unlocked memory. The unit sets `LimitMEMLOCK` to the pool size with a margin; `CAP_IPC_LOCK` is not granted.
3. **The Core runs under a dedicated user that runs nothing else** (systemd `User=` of its own static user, as AD-24 already gives it).
   - Its first action is `PR_SET_DUMPABLE` 0 and `RLIMIT_CORE` 0, before it reads the instance key, and the unit carries `LimitCORE=0`.
   - A descriptor on `/proc/<pid>/mem` or a ptrace attach taken before that call keeps working (`preopened-descriptor-survives-hardening`). Only a dedicated user with nothing else running under it leaves no such earlier opener.
   - After hardening the Core never calls `execve` and never changes credentials. The kernel resets the dumpable flag on both: to 1 on a plain `execve`, and to `fs.suid_dumpable` on a credential change. It starts other processes through systemd, as AD-24 already says.
4. **Every key operation runs in an `#[inline(never)]` function under a `ScrubOnDrop` guard, on the thread that ran it.** That covers Argon2id, AES-GCM open or seal of a key, HKDF and HPKE. The guard scrubs 64 KiB below the caller and zeroes the AVX registers, on success and on error.
   - Without the scrub, every HPKE call leaves its AEAD key, base nonce, exporter secret, shared secret, an HMAC state and the GHASH key on the stack, on the main thread and on a spawned thread alike.
   - The deepest measured use is 16 288 bytes (HPKE open), against the 64 KiB scrub.
5. **Argon2id memory is owned by the Core**: `hash_password_into_with_memory`, with a buffer in a wiping wrapper that wipes on drop and on the error path.
   - `argon2` 0.6.0's `hash_password_into` frees its blocks without wiping them: its `Blocks` drop only deallocates.
   - At E12 sizes the buffer exceeds the memlock limit and stays unlocked while the KDF runs; swap disabled or encrypted (Story 11.4) covers that.
6. **Key bytes never sit in heap memory the Core does not wipe or lock.**
   - AEAD and HKDF objects (aws-lc-rs `LessSafeKey`, `Prk`) are built from the slot for one operation and dropped before it returns. A live aws-lc-rs key object keeps the key, the DEK input of `Prk` and the GHASH key on the unlocked heap (measured).
   - Where an object must live longer, swap must be off or encrypted.
   - The `Vec`-returning `single_shot_open` stays banned for keys (U5).
7. **Panics.** Release builds keep `panic = "unwind"` (AD-9).
   - A module handler runs inside `handler_boundary`, which sets a thread-local flag around `catch_unwind`. The Core panic hook does nothing while the flag is set, so the panic unwinds to the boundary and member keys stay.
   - Anywhere else, the hook wipes the whole pool and aborts, with no I/O.
8. **SIGTERM is blocked in every thread and taken on a `signalfd` thread**, which wipes the pool and then lets the orderly shutdown run. SIGINT can use the same thread.
9. **Proposed API for `vilicus-crypto`, to make rules 4 and 6 structural.**
   - `Slot::with_key(|bytes| ...)` runs the closure in an `#[inline(never)]` function under a `ScrubOnDrop` guard, and `bytes()` and `bytes_mut()` are crate-private.
   - Cost measured in the harness (`scrub-cost`): 8.3 microseconds per scrub, against 249 ns for one 256-byte record sealed and opened with a key object built for it. So the scrub belongs to key operations (unlock, derivation, HPKE, opening a file), not to each record operation.
   - Record encryption runs inside SQLCipher with the file key it was given. SQLCipher's internal key handling (its key derivation, page cipher contexts and buffers) is outside these rules and outside this spike.
10. **No fallback is taken** (AC3 not triggered).

## Result

Command, from the repository root on the Windows development host with Docker Desktop: `bash spikes/locked-memory/run.sh`.

Run of 2026-10-16, after the review follow-up: exit code 0, with 66 `PASS`, 0 `FAIL` and 21 `INFO` lines. The 66 are 6 steps and 60 checks:

- the steps are `toolchain_components`, `build`, `fmt`, `clippy` (`-D warnings`, all targets), `tests` (8 tests, none ignored) and `zeroize_features`;
- the first version of the spike ended at 40 `PASS`.

Earlier runs printed `FAIL` lines and exited 1, which shows the failure path works:

- a format diff;
- a SIGSEGV sent with `kill`, which the process survived;
- a core dump control that could not write in a read-only working directory;
- a member key copy left in the caller's own frame (settled task 4).

Environment printed by the run:

- rustc 1.99.1, Debian 13.7, kernel 6.18.33.2-microsoft-standard-WSL2 (Docker Desktop);
- `core_pattern` `core`, `RLIMIT_MEMLOCK` 8192 KiB.

The `core_pattern` belongs to the Docker Desktop VM. A probe earlier the same day read `|/wsl-capture-crash %t %E %p %s` (a pipe). The run prints the value each time.

**Inspection method (kept for the regression test of Story 4.2).**

1. A harness process plants fresh random secrets in a file.
2. A subject process reads them with `pread` straight into locked slots and runs one code path. It stops while the keys are live, after any wipe, and after drop.
3. At each stop the harness, a different process with `CAP_SYS_PTRACE`, reads every mapping of the subject through `/proc/<pid>/mem`, non-readable ones included, and fails on any it cannot read.
4. It searches for the secrets and for every intermediate recomputed from them, using 16-byte windows every 8 bytes and classifying hits by mapping.
5. Each absence in the Core shape is paired with residue the default shape leaves on the same path. That residue is asserted, so the scan demonstrably sees that path's residue.

Detection threshold: a run of 23 bytes or more.

Reading the numbers: `name=N[kind:count,...]` is the number of distinct copies found and where they are (`pool`, `heap` for the brk heap, `stack` for the main thread stack, `anon` for other anonymous memory, thread stacks included).

**AC1: PASS (Core shape), with the default-shape residue asserted as the control.**

Process state is asserted by `process-hygiene` and `pool-guard-pages`: `dumpable=0`, `RLIMIT_CORE` 0, `VmLck` 16 kB covering the 16 384-byte pool, pool `VmFlags` `lo dd wf`, and `---p` guard pages on both sides. The subject's memory was about 5 MB, every mapping read.

| Path | Core: held keys live in the pool, nothing else (asserted) | Core after drop (asserted) | Default after drop (asserted non-empty on stack or heap) |
|------|------|------|------|
| copies | key in the pool; the planted stack copy also found live (stack control) | nothing (1 pattern) | `key=2[heap:1,stack:1]` |
| passphrase | passphrase, KEK, DEK only in the pool; Argon2id blocks in the Core buffer until the wipe | nothing (7 patterns) | `argon2-last-block=1[stack:1] kek=2[stack:2] kek-gcm-h-polyval=1[stack:1]` |
| hkdf | DEK, file key only in the pool | nothing (7 patterns) | `file-key-gcm-h-polyval=1[stack:1]` |
| hpke-open | member private key, household key | nothing (17 patterns) | on the stack, `aead-key=12 base-nonce=7 exporter-secret=3 shared-secret=14 aead-key-gcm-h-polyval=5 ks-secret-hmac-ipad=1`; `hk=1[heap:1]` (the `Vec` of `single_shot_open`) |
| hpke-seal | ephemeral seed, household key | nothing (21 patterns) | on the stack, `aead-key=9 base-nonce=5 exporter-secret=2 shared-secret=12 aead-key-gcm-h-polyval=5 ks-secret-hmac-ipad=1` |
| hpke-open on a spawned thread | (not scanned live) | nothing anywhere | 47 hits in that thread's stack mapping after the join: `aead-key=12 aead-key-gcm-h-polyval=6 base-nonce=7 exporter-secret=4 hk=1 ks-secret-hmac-ipad=1 shared-secret=17` |
| passphrase, wrong wrap (open fails) | passphrase, KEK in the pool after the failure | nothing (7 patterns) | (not run) |

- **Argon2id wipe** (`passphrase-core-argon2-wipe`): 2 block patterns are in anonymous memory before the wipe, and 0 after it, with the buffer still allocated.
- **Stack depth of each guarded key operation** (canary, asserted at most 64 KiB minus 8 KiB):

  | Operation | Deepest stack use (bytes) |
  |------|------|
  | passphrase | 10 776 |
  | wrong passphrase | 10 824 |
  | hkdf | 2 808 |
  | hpke-open, main thread and spawned thread | 16 288 |
  | hpke-seal | 12 320 |

- **aws-lc-rs objects** (`*-asis-key-object-on-unlocked-heap`): a live `LessSafeKey` keeps the KEK, and in the hkdf path the file key, in one heap copy each, in a mapping without the `lo` flag. With objects built per operation (`*-core-no-key-object-at-rest`), the key is found only in the pool while live. While alive, aws-lc-rs also keeps the GHASH key in the POLYVAL form (observed in the first version).
- **Findings F1 and F2 of `spikes/hpke-review/REVIEW.md`, measured.**
  - F2: with U1 applied, an HPKE call still leaves the key schedule outputs on the stack, and the scrub removes them all.
  - F1: polyval 0.6.2's x86_64 `autodetect` backend holds its backends in a `ManuallyDrop` union with no `Drop`, so the GHASH key of a RustCrypto AES-GCM instance survives U1. This is from code reading; the residue is consistent with it.
  - The dalek scalar forms and the DH outputs were never found.
- **Patterns never found in any scan**, so their absence has no positive control in the scans:
  - the raw GHASH key H;
  - the aws-lc-rs HKDF PRK and its HMAC states;
  - the HPKE `dkp_prk`, ephemeral private key, `eae_prk` and key schedule `secret`;
  - the opad HMAC states;
  - the clamped and radix-16 scalars and the DH outputs.

  The unit tests validate their recomputation: the HPKE chain through the opened wrap, the ephemeral key, and the HKDF output.

**AC2: PASS.** All asserted:

- **Panic** (`panic-inside-boundary-keeps-keys`, `panic-outside-boundary-wipes`, `panic-abort-no-core-dump`): one process.
  - A panic inside the handler boundary is caught, and the key and the DEK are still in the pool.
  - A panic outside it runs the hook, which wipes the pool; the scan before the abort finds neither.
  - The process ends by SIGABRT with no dump.
- **Unwind** (`panic-unwind-drops`): a worker thread holding both in slots panics, and after it unwinds neither is found.
- **SIGTERM** (`sigterm-wipes-pool`): the `signalfd` thread wipes the pool, nothing is found before exit, and the exit status is 0.
- **SIGKILL** (`kill-while-held`): no core dump. After the kill, and before reaping, reading the pool through a descriptor opened while live returns exactly 0 bytes: the address space is already gone.
- **Dump control** (`core-dump-control`): a dumpable subject does dump. `core-file-excludes-locked-pool` shows its 491 520-byte core file holds the heap DEK copy (the control, 1 copy) and not the pool key (0).
- **Signals** (`no-core-dump-SIGABRT`, `no-core-dump-SIGSEGV-fault`, `no-core-dump-SIGQUIT`): no dump and no core file. A SIGSEGV sent with `kill(2)` does not end a Rust process, which is why the check uses a real fault.
- **`RLIMIT_CORE` only** (observed, `INFO`): with the process left dumpable and only `RLIMIT_CORE` 0, there is no dump either, with this file `core_pattern`. A pipe `core_pattern` was not run here.

**Abort paths that skip the panic hook.** No user code runs on these, so the pool is not wiped: keys stay in the process pages until the kernel tears the address space down at exit, and no dump is written while the process is non-dumpable.

- An allocation failure: Rust's allocation error handler aborts without the panic hook.
- A stack overflow: the runtime's guard page handler prints a message and aborts.
- A panic raised while already unwinding, such as a panic in a destructor during unwinding: the runtime aborts.
- An explicit `std::process::abort`.
- A fatal signal with no handler: SIGKILL, a memory fault, SIGABRT or SIGQUIT sent from outside, or the OOM killer.

SIGTERM, the normal stop signal, is covered by the `signalfd` wiper.

**What a crash leaves in memory until the process ends.**

- A panic outside a handler: the pool is wiped before the abort. Only copies outside the pool remain until exit; under the Core rules there are none at rest, but an operation in progress on another thread has its intermediates on that thread's stack.
- A panic inside a handler: member keys stay in the pool by design.
- The abort paths above: everything stays until the kernel releases the pages at exit.
- After exit: physical pages go back to the kernel without being cleared (unless the kernel runs with `init_on_free=1`) and are zeroed when next handed out. Reading them needs kernel-level access (R1).

**AC3: not triggered.** No key material was found after drop in any tested path in the Core shape. The pass holds under settled tasks 1 to 8. The default shape leaves keys and HPKE schedule values behind, so the rules are the condition of the result.

**Other checks (all PASS).**

- **mlock refused:** `mlock-over-limit-fails-closed` (`ENOMEM`) and `mlock-refused-fails-closed` (`EPERM`, `--ulimit memlock=0:0`). The subject exits with the dedicated code and reports `keys_read=0`.
- **Same-user reading:** `same-user-reads-dumpable-process` is the control. `dumpable-off-blocks-same-user-reader` gets `EACCES` on opening a hardened subject's memory.
  - `preopened-descriptor-survives-hardening`: a descriptor opened before the subject hardened itself still reads the key from the pool afterwards, while a fresh open is refused. This is the limit behind settled task 3.
  - With `CAP_SYS_PTRACE` the harness reads every live key, which is R1 as designed.
- **Fork:** `fork-wipes-pool`: in a forked child the pool slot reads as zeroes while a heap copy is still there.
- **Swap:** `swap-control-unlocked-page-swapped` and `swap-locked-pool-resident`: under memory pressure the page of an unlocked copy is swapped out, while the pool page stays present.
- **Zeroize features:** `zeroize_features` confirms the resolved features of `x25519-dalek`, `curve25519-dalek`, `aes`, `aes-gcm`, `ghash`, `polyval` and `argon2` include `zeroize`.
- **Scrub cost** (`INFO`): 8.3 microseconds per scrub, against 249 ns per record operation.

**Limits, not run here.**

- **Reference host:** the run used the Docker Desktop WSL2 kernel. FR-13's "E16 passes on the reference host" is met only when `run.sh`, or the binary's four groups with the same capabilities and limits, passes there (Story 2.3's VM harness).
- **Pipe `core_pattern`:** not run. Procedure: on a Debian 13 host with `systemd-coredump`, run the `noptrace` group. `coredumpctl list` must show nothing for the hardened subjects and one entry for `core-dump-control`.
- **Registers:** `vzeroall` clears ymm0 to ymm15 on the scrubbing thread only. AVX-512 registers zmm16 to zmm31, mask registers, other threads' registers and the register state the kernel saves on a context switch are not cleared or searched.
- **Kernel-side copies and earlier access:** not searchable from user space are pipe and socket buffers, the page cache of the material file, freed physical pages, the swap device and hibernation images (hibernation must be disabled, or swap encrypted). A ptrace attach or a `/proc/<pid>/mem` descriptor taken before hardening, by a process of the same user, keeps access (measured for the descriptor; settled task 3).
- **Paths not exercised:**
  - the passphrase through the Gateway, TLS and the Core's IPC framing;
  - the async runtime;
  - the recovery and backup secrets;
  - SQLCipher's internal key handling.
- **Detection:** copies shorter than 23 bytes, and transformed forms beyond `patterns.rs`, are not detected.
- **Code generation:** results hold for this build (release profile, rustc 1.99.1). Story 4.2's regression test must run on the product build, with the canary depth checks.

## Proposed design document updates

Not applied: this spike does not edit shared design documents. Where a decision is needed it is written as "new decision record", and the number is assigned when it is added.

1. **`doc/research-notes.md`, section 3, E16 row, Pass criterion column.** After "No key material found after drop in tested paths", add:

   > **Passed** in a Debian 13 container (story 1.10, `spikes/locked-memory/`). With keys in a locked, guarded, dump-excluded pool wiped on drop, key operations under a stack scrub guard, Argon2id memory wiped by the Core, AEAD and HKDF objects built per operation and HPKE opened in place, no key or derived secret is found in the process memory after drop, on the main thread or a worker thread, on success or failure. No crash path writes a core dump, and panics outside a handler and SIGTERM wipe the pool. Without those rules the HPKE key schedule, the Argon2id state, freed heap copies and live key objects stay in memory (new decision record). The reference host run and a pipe `core_pattern` remain to do. The inspection method is kept for the regression test of Story 4.2.

2. **`doc/research-notes.md`, status line.** Add E16 to what has been proven by a prototype, citing the new decision record. At the end of the update paragraph, add: "Story 1.10 then passed E16 in a container, under the key memory rules of the new decision record."

3. **`doc/decisions.md`.** Add a new decision record, "Key memory rules from E16", status Accepted, amending AD-4:

   > Context: FR-13 and key management section 10 rely on locked memory and zeroization, and E16 measured them in the Rust runtime.
   >
   > Decision:
   >
   > - The Core runs under its own static user, which runs nothing else. Its first action, before reading the instance key, is `PR_SET_DUMPABLE` 0 and `RLIMIT_CORE` 0. The unit also carries `LimitCORE=0`, and the Core never calls `execve` or changes credentials afterwards.
   > - It allocates one key pool, refuses a second one, frames it with `PROT_NONE` guard pages, locks it with `mlock` and advises it `MADV_DONTDUMP` and `MADV_WIPEONFORK`. The pool is sized by the planned slot count (per unlocked adult the DEK, the household key, the member private key, the open file keys and transient slots, plus the instance-level keys), cut into slots wiped on drop.
   > - If the lock is refused, the Core refuses to start with an error naming `LimitMEMLOCK` and never falls back to unlocked memory. The unit sets `LimitMEMLOCK` to the pool size with a margin, without `CAP_IPC_LOCK`.
   > - Every key operation runs in a non-inlined function under a guard that scrubs the stack below the caller and zeroes the AVX registers, on success and on error, on the thread that ran it. `vilicus-crypto` exposes slots only through a closure API that applies the guard.
   > - AEAD and HKDF objects are built from a slot for one operation and dropped. Key bytes are never held in heap memory the Core does not wipe or lock.
   > - Argon2id runs on memory the Core owns and wipes (`hash_password_into_with_memory`).
   > - Release builds keep `panic = "unwind"` (AD-9). A module handler runs inside a boundary that marks the thread, and the panic hook wipes the pool and aborts only for a panic outside such a boundary.
   > - SIGTERM is taken on a `signalfd` thread that wipes the pool before shutdown.
   >
   > Consequences:
   >
   > - No key material was found after drop in the tested paths.
   > - At E12 sizes the Argon2id memory is wiped but not locked, so swap must be disabled or encrypted.
   > - Abort paths without user code (allocation failure, stack overflow, panic during unwinding, fatal signals) leave keys in memory until the process ends, without a dump.
   > - An opener of the Core's memory from before hardening keeps access.
   > - Registers beyond ymm15, kernel buffers, freed physical pages, hibernation images and SQLCipher's internal key handling are outside the claim.

4. **`doc/key-management.md`, section 10.** After "are never logged, swapped or dumped;" add:

   > the locked memory is one guarded pool allocated at start, excluded from core dumps and wiped in fork children, and the Core does not start if it cannot lock it; each key operation is followed by a scrub of the stack it used, and AEAD and HKDF objects live for one operation (E16, new decision record);

   Then replace "Process crashes drop keys and lock the instance." with:

   > Process crashes drop keys and lock the instance: a panic outside a module handler and a SIGTERM wipe the pool before the process ends, and the other abort paths leave the keys in memory only until the kernel releases the process's pages at exit, without any dump (E16).

5. **`doc/architecture.md`, section 4, memory hygiene bullet.** Replace "key buffers in locked memory (`mlock`) and zeroized on drop, swap disabled or encrypted." with:

   > key buffers in one guarded, locked pool (`mlock`, `MADV_DONTDUMP`, `MADV_WIPEONFORK`) allocated at start, the Core refusing to start if it cannot be locked, zeroized on drop, with a stack scrub after each key operation; the Core under a user that runs nothing else, never calling `execve` or changing credentials after it hardens itself; swap disabled or encrypted, and hibernation disabled (E16, new decision record).

6. **`doc/architecture-spine.md`.**
   - AD-4 rule: after "zeroized on drop and held in locked memory", add "(one guarded pool locked at start, fail closed if the lock is refused, slots reached only through a closure that scrubs the stack; new decision record)".
   - AD-9: after "release builds use `panic = "unwind"`.", add: "Each handler runs inside a boundary that marks the thread; a panic outside any boundary runs a hook that wipes the key pool and aborts the Core (E16)."

7. **`spikes/hpke-review/REVIEW.md` (story 1.2).**
   - In F1, add: "polyval 0.6.2's x86_64 `autodetect` backend wraps its backends in a `ManuallyDrop` union with no `Drop`, so the GHASH key is not wiped even with U1; E16 found it on the stack after HPKE calls."
   - In F2, add: "Measured by E16 (story 1.10): without a scrub, an HPKE seal or open leaves the AEAD key, base nonce, exporter secret, shared secret, an HMAC state of the key schedule and the GHASH key on the stack of the thread that ran it; a stack scrub after the call removes all of them."
   - Add usage rule U9: "Every HPKE call runs in a non-inlined function under a stack scrub guard on the same thread, and no RustCrypto AES-GCM object is kept on the heap (F1, F2, E16)."

8. **`spikes/argon2id-params/Cargo.toml` (story 1.8).** Replace the comment "`zeroize` wipes the memory blocks after use" with "`zeroize` wipes H0 and the final block hash; the memory blocks are wiped only when the caller owns them (`hash_password_into_with_memory`, E16)."

9. **Stories.**
   - `doc/stories/story-4.2-locked-memory-and-key-hygiene.md`: AC2's regression test reuses the inspection method above, with the default-shape residue and the canary depth as controls, and adds the paths E16 did not cover: the passphrase through the Gateway and IPC, the async runtime, and the recovery and backup secrets. AC1 adds the guard pages, the single registration and the sizing rule.
   - `doc/stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md`: uses Core-owned, wiped Argon2id memory.
   - `doc/stories/story-4.6-household-key-hpke-wrap-with-ci-cross-test.md`: applies U5 and U9.
   - `doc/stories/story-5.4-systemd-units-and-sandbox-profile-check.md`: the Core unit sets `LimitMEMLOCK` and `LimitCORE=0`, without `CAP_IPC_LOCK`, under a static user that runs nothing else.

10. **`doc/prd.md`, FR-13.** No change to the text. Its consequence "E16 passes on the reference host" stays open until the reference host run above.
