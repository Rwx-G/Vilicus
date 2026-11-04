---
title: 'Locked memory and key hygiene'
epic: 4
story: 2
status: review
author: Rwx-G
created: 2026-10-16
implements: [FR-13, E16, AD-4, NFR-2, D131, AD-9]
---

# Story 4.2: Locked memory and key hygiene

As a member,
I want my keys held in locked memory, wiped on drop and kept out of logs and core dumps,
So that an unlocked partition exposes as little key material as the design allows.

**Acceptance Criteria:**

**AC1 (FR-13, AD-4)**
**Given** a key buffer allocated by `vilicus-crypto`
**When** it is created
**Then** it lives in locked memory (`mlock`) and the process has `PR_SET_DUMPABLE` turned off
**And** an allocation that cannot be locked fails closed with a typed error instead of falling back to swappable memory

**AC2 (FR-13, E16)**
**Given** a key that was dropped, on the normal path and on a crash path
**When** the regression test derived from E16 inspects the process memory
**Then** no copy of the key material is found
**And** core dumps are disabled for the process, so a crash writes no dump

**AC3 (AD-4)**
**Given** the source of `vilicus-crypto`
**When** the `unsafe` code is reviewed by a CI check
**Then** `unsafe` appears only in the memory-locking code of `vilicus-crypto`, each block with a comment stating why it is sound, and nowhere else in the workspace outside the documented list

**AC4 (FR-13, NFR-2)**
**Given** a test that seeds a key, a passphrase, a recovery secret and a capability token through the Core's code paths
**When** the `tracing` output of the run is captured
**Then** none of the seeded values appears in it, in clear or hex or base64 form

**AC5 (E16, FR-13, D131)**
**Given** E16 passed in containers and on a Debian 13 VM without its fallback (D131), so no shorter unlock window maximum is introduced
**When** the reference host exists
**Then** the regression test of AC10, or `spikes/locked-memory/run.sh` with its four groups and their capabilities and limits, runs there, which FR-13's consequence "E16 passes on the reference host" requires (gate E16-1)
**And** its result is recorded in the E16 entry of `doc/research-notes.md`; if key material is then found after drop, the AC3 fallback of Story 1.10 is recorded as a decision.

**AC6 (D131, AD-4)**
**Given** the Core starting
**When** `vilicus-crypto` allocates key memory, before any key exists
**Then** it maps one pool, framed by a `PROT_NONE` guard page on each side, advised `MADV_DONTDUMP` and `MADV_WIPEONFORK`, locked with `mlock` and cut into slots wiped on drop with volatile writes; a second pool is refused
**And** the pool holds at least the planned slot count (per unlocked adult the DEK, the household key, the member private key, the open file keys and transient slots, plus the instance-level keys; `PLANNED_SLOTS` of `spikes/locked-memory/src/pool.rs` counts 8 adults with 16 file keys and 4 transient slots each), checked by a test that fills the pool and is refused one slot past it
**And** when the lock is refused, the Core refuses to start with a typed error naming `LimitMEMLOCK`, never falling back to unlocked memory, and holds no `CAP_IPC_LOCK`.

**AC7 (D131, FR-13)**
**Given** the Core process
**When** it starts
**Then** its first action, before it reads the instance key, is `PR_SET_DUMPABLE` 0 and `RLIMIT_CORE` 0, and it never calls `execve` or changes credentials afterwards, since the kernel resets the dumpable flag on both
**And** non-dumpable is the barrier, not `RLIMIT_CORE` 0 alone: under Debian's `systemd-coredump` pipe the kernel pipes the image whatever the limit (Story 1.10, "Debian 13 VM run"; gate E16-2), so a test under the pipe `core_pattern` shows no `coredumpctl` entry for the hardened process.

**AC8 (D131, AD-4)**
**Given** a key operation (Argon2id, AES-GCM open or seal of a key, HKDF, HPKE)
**When** it runs
**Then** it runs in an `#[inline(never)]` function under a guard that scrubs 64 KiB of stack below the caller and zeroes the AVX registers (`vzeroall`), on success and on error, on the thread that ran it; `vilicus-crypto` exposes slots only through a closure API (`Slot::with_key(|bytes| ...)`) that applies the guard, the raw accessors staying crate-private
**And** a stack canary measures each guarded operation and fails when its depth plus 8 KiB exceeds the scrub (the spike measured at most 16 288 bytes, for an HPKE open); the scrub belongs to key operations, not to each record operation (8.3 microseconds per scrub against 249 ns per record operation).

**AC9 (D131, AD-9)**
**Given** release builds with `panic = "unwind"`
**When** a panic or a signal reaches the Core
**Then** a module handler runs inside a boundary that marks its thread, a panic inside it unwinds and member keys stay, and a panic outside any boundary runs a hook that wipes the pool and aborts with no I/O; SIGTERM is blocked in every thread and taken on a `signalfd` thread that wipes the pool before the orderly shutdown
**And** tests show each case (`panic-inside-boundary-keeps-keys`, `panic-outside-boundary-wipes`, `sigterm-wipes-pool`) and that a forked child reads the pool as zeroes (`fork-wipes-pool`).

**AC10 (E16, D131)**
**Given** the product build (release profile)
**When** the AC2 regression test runs
**Then** it reuses the inspection method of Story 1.10 (Result, "Inspection method"): a harness process with `CAP_SYS_PTRACE` reads every mapping of the subject through `/proc/<pid>/mem`, non-readable ones included, fails on any mapping it cannot read, searches the secrets and every recomputed intermediate in 16-byte windows every 8 bytes, and pairs each absence with residue the default shape leaves on the same path, asserted as the control (gate E16-3)
**And** it adds the paths E16 did not cover: the passphrase through the Gateway and the Core's IPC framing, the async runtime, and the recovery and backup secrets
**And** its swap group checks its precondition and reports `SKIP` with the reason on a host without swap (gate E16-5).

**Dependencies:**
- Story 4.1 (key types)
- Story 1.10 (E16 result, inspection method, D131)
- Story 2.3 (Debian 13 VM, pipe `core_pattern`)

**References:**
- `doc/prd.md` FR-13, FR-12
- `doc/architecture-spine.md` AD-4, AD-9, Consistency Conventions (Unsafe code, Logging)
- `doc/key-management.md` section 10
- `doc/decisions.md` D131
- `doc/research-notes.md` E16
- `spikes/locked-memory/` (`src/pool.rs`, `src/scan.rs`, `src/patterns.rs`, `run.sh`)
- `doc/qa/gates/1.10-e16-locked-memory-and-zeroization.yml` (E16-1 to E16-5)

## Implementation Notes

**What was built**
- `crates/vilicus-crypto/`:
  - `memory.rs` (new), the crate's one module with unsafe code (D140, AC3):
    - the pool: one anonymous mapping between two `PROT_NONE` guard pages, advised `MADV_DONTDUMP` and `MADV_WIPEONFORK`, locked with `mlock` and cut into `PLANNED_SLOTS` slots of `KEY_LEN` bytes (D131's sizing rule, from named constants: the planned adults with their keys, open file keys and transient slots, then the instance's keys and transient slots). `lock_key_memory()` maps it once, under a lock, and refuses a process that is not hardened, one holding `CAP_IPC_LOCK`, a second pool, and a pool `mlock` turns down (`KeyMemoryError::Lock`, whose message names `LimitMEMLOCK`); any failure undoes the mapping;
    - `Slot`, moved here from `key.rs`: a slot of the pool, zeroes when taken, wiped with `zeroize` (volatile writes) on drop. `Slot::new()` fails with `KeyMemoryError::NotLocked`, `Exhausted` or `Wiped`. Its bytes are lent only through `with_key` and `with_key_mut`; the raw accessors are private to the module;
    - the guard: `with_key` and `with_key_mut` run the closure through `guarded`, never inlined, the closure in a non-inlined frame below it. The outermost guarded call of a thread overwrites `STACK_SCRUB_LEN` (64 KiB) of stack below it with volatile writes and runs `vzeroall` when the CPU has AVX, on return and while unwinding; a guarded call inside another does neither, the outer one covering both;
    - `harden_process()` (`PR_SET_DUMPABLE` 0, then `RLIMIT_CORE` 0 soft and hard); `take_sigterm(on_term)` (refused unless the process has one thread, then SIGTERM blocked and read on a `signalfd` thread that wipes the pool and runs `on_term`); `install_panic_hook(in_handler_boundary)` (returns for a panic inside a boundary, otherwise wipes the pool and aborts, with no I/O). A wiped pool hands out no slot;
    - the stack canary, in test builds and with the `testing` feature: the outermost guard paints twice the scrub length below it before the operation, and measures the deepest byte the operation changed before the scrub runs;
    - `memory/testing.rs` (new, `testing` feature): what the regression harness needs: keys planted from a file straight into a slot, the guarded accessor, the pool's range, the canary's depth, a panic observer between the wipe and the abort, and the fork, signal and fault it inspects. `memory/tests.rs` (new): the unit tests of the Result.
  - `key.rs`, `derive.rs`, `wrapper.rs`: `Slot::zeroed()` became `Slot::new()?`, and `with_bytes` and `with_bytes_mut` became `with_key` and `with_key_mut`, as 4.1's open points planned; no public signature changed.
  - `error.rs`: `KeyMemoryError` (new, `#[non_exhaustive]`, `Copy`) and `CryptoError::KeyMemory`.
  - `lib.rs`: the "Key memory" section, the start order as a doc test; `harden_process`, `lock_key_memory`, `take_sigterm`, `install_panic_hook`, `PLANNED_SLOTS`, `STACK_SCRUB_LEN`, `STACK_SCRUB_MARGIN` and `KeyMemoryError` exported, `testing` behind its feature; a `compile_error!` off Linux.
  - `Cargo.toml`: `libc` (owner approval, the workspace's pin, no feature enabled: every call is in libc's `no_std` bindings); the `testing` feature; the `key_memory` example, which requires it.
  - `examples/key_memory/` (new): the regression harness (AC2, AC6, AC7, AC9, AC10), below.
- `crates/vilicus-core/Cargo.toml`: its `testing` feature enables `vilicus-crypto/testing`, so that the workspace's test builds, where the testbed enables it, compile and lint the harness.
- `ci/check_workspace.py`, `ci/crate_graph.toml`, `ci/test_check_workspace.py`: `[unsafe_code.modules]` names `src/memory` for `vilicus-crypto` and `src/ffi` for `vilicus-storage`; `check_unsafe_modules` fails on the `unsafe` keyword, comments and literals removed, in any other file of any workspace crate, tests and examples included (AC3).
- `ci/check_packaging.py`, `ci/test_check_packaging.py`: a feature named `testing` may enable another crate's `testing`; an artefact still fails when anything else enables either.
- `ci/key_memory.py` (new) and `ci/test_key_memory.py` (new): builds the harness on the release profile and runs its five groups, each in a container of the pinned image with only what it needs: `main` with `CAP_SYS_PTRACE` and an 8 MiB `RLIMIT_MEMLOCK`; `noptrace` with no capability and an unlimited `RLIMIT_CORE` for the dumpable control; `nomemlock` with `RLIMIT_MEMLOCK` 0; `ipclock` with `CAP_IPC_LOCK`; `swap` under a 256 MiB cgroup limit with 1 GiB of swap. On a host whose `core_pattern` pipes to `systemd-coredump`, it compares `coredumpctl`'s entries for the harness with the dumpable control crashes the `noptrace` group reports (AC7). Its Docker volumes are made for the run and removed at its end.
- `.github/workflows/ci.yml`: the `key-memory` job runs it. `e2e/run.sh` and `e2e/README.md`: the `key-memory` phase runs it, so that `e2e/vm/vm.sh e2e key-memory` replays it in the Debian 13 VM and on the reference host (AC5).

**The harness** (`examples/key_memory`, Story 1.10's inspection method on the product build). The harness writes fresh random secrets to a file. A subject process it starts sets itself up as the Core does (`harden_process`, `take_sigterm` for the SIGTERM case, `lock_key_memory`), reads each secret straight into a slot (`testing::key_from_file`), runs one path through `vilicus-crypto`, and stops at `LIVE` and at `DROPPED`. At each stop the harness reads every mapping of the subject through `/proc/<pid>/mem`, non-readable ones included, fails on any it cannot read, and searches 16-byte windows every 8 bytes (`scan.rs`, ported from the spike) for the secrets and the values recomputed from them: the derived key (computed by the crate in the harness's own pool), the HKDF PRK, and the GHASH key of each AES-256-GCM key, raw and in the POLYVAL form. The paths are `copies` (a key copied to the deep end of a 16 KiB frame inside the guarded closure), `derive`, `wrap`, `unwrap`, `unwrap-wrong` (another context, the open refused) and `thread` (a wrap and an unwrap on a spawned thread). Each runs in the product shape and in the default shape (`asis`: the same operation on aws-lc-rs directly, the keys in ordinary heap copies and the aws-lc-rs objects kept until the drop), whose residue after the drop is asserted as the control of the product shape's absence. Every guarded operation of the product shape reports its canary depth, checked against the scrub with its 8 KiB margin.

**Decisions and why** (drafted decision text under Open points)
- *Where D131's process rules live.* D140 places "the process hardening of D131 in `vilicus-core`", but those calls need `libc`, which the owner approved for `vilicus-crypto` only, and no Core process exists yet (Story 5.1). `vilicus-crypto` holds them beside the pool, in its unsafe module, as four public functions the Core calls in order before it reads the instance key: `harden_process`, `take_sigterm`, `lock_key_memory`, `install_panic_hook`. The hook takes the boundary mark as a function, `vilicus_core::boundary::in_module_code` in the Core (D151), so the crate needs nothing of the Core.
- *The order is enforced where it can be.* `lock_key_memory` refuses a process that is not non-dumpable with `RLIMIT_CORE` 0 soft and hard, so no key can exist in a dumpable process; `take_sigterm` refuses a process with more than one thread, one of which would still receive SIGTERM. That `harden_process` is the Core's first action, and that the Core never calls `execve` or changes credentials afterwards, stay the Core's to hold (Stories 5.1 and 5.4).
- *"Holds no `CAP_IPC_LOCK`"* (AC6) is read as a refusal: `lock_key_memory` reads `CapEff` and refuses the pool while the capability is effective. With it, `mlock` ignores `RLIMIT_MEMLOCK`, so the unit's `LimitMEMLOCK` would bound nothing, and a Core that holds it was not started by its unit.
- *Pool size.* Exactly `PLANNED_SLOTS` slots of `KEY_LEN` (32) bytes, the mapping rounded up to whole pages; the slot past the count is refused even where the page has room, so the count is the bound the tests hold. The spike used 64-byte slots, so that an AEAD open could run in place with its tag; 4.1's unwrap opens straight into a 32-byte slot (`open_separate_gather`), so no slot needs that room.
- *Nested guards.* A wrap lends two slots at once, so guarded calls nest; only the outermost one of the thread scrubs, and its canary measures the whole depth. Scrubbing at each level would also make the outer canary read the inner scrub as the operation's depth.
- *After a wipe.* The SIGTERM thread wipes the pool before the orderly shutdown runs, as D131 orders; the wiped pool then refuses every slot, so no generation, derivation, wrap or unwrap can start during the shutdown and run on zeroed keys. An operation already running races with the wipe (open point for 5.1).
- *The `testing` feature.* The harness must plant known keys and read the canary between the operation and the scrub; neither belongs in a release build. `vilicus-crypto`'s `testing` feature compiles them, only `vilicus-core`'s `testing` enables it, and `check_packaging.py` refuses both in a release artefact. The harness is an example, not a test, because `cargo test` runs without `CAP_SYS_PTRACE`: the workspace's test builds compile and lint it, and `ci/key_memory.py` runs it.
- *The default shape.* The spike's `asis` variant ran its own code without the scrub and the per-operation objects. The product crate has no such switch, and adding one under `testing` would make the tested build differ further from the release one. The control is instead the same operation on aws-lc-rs directly, the keys in heap copies and the objects kept, which leaves residue on the heap and on the stack after the drop.
- *`vzeroall`* is an `asm!` block behind `is_x86_feature_detected!("avx")`, without a `#[target_feature]` function, so the module holds no `unsafe fn`.

**Files**
- `crates/vilicus-crypto/`: `Cargo.toml`; `src/`: `memory.rs`, `memory/testing.rs`, `memory/tests.rs` (new), `lib.rs`, `key.rs`, `key/tests.rs`, `derive.rs`, `derive/tests.rs`, `wrapper.rs`, `wrapper/tests.rs`, `error.rs`, `test_support.rs`; `examples/key_memory/`: `main.rs`, `checks.rs`, `subject.rs`, `scan.rs`, `material.rs` (new)
- `crates/vilicus-core/Cargo.toml`
- `ci/check_workspace.py`, `ci/test_check_workspace.py`, `ci/crate_graph.toml`, `ci/check_packaging.py`, `ci/test_check_packaging.py`, `ci/key_memory.py` (new), `ci/test_key_memory.py` (new)
- `.github/workflows/ci.yml`, `e2e/run.sh`, `e2e/README.md`
- `Cargo.lock` (one dependency line of `vilicus-crypto`)

**Deviations**
- *"The Core starting"* (AC6, AC7): no Core process exists before Story 5.1, so nothing in the workspace starts as the Core yet. The four start functions are what the Core will call; the harness's subject calls them in the Core's order and is the process the checks inspect: "the Core refuses to start" is shown as the subject ending with status 3 and a typed error, no key created.
- *AC7, "never calls `execve` or changes credentials afterwards"*: a property of the Core's code and unit (5.1, 5.4), not of this crate; nothing here tests it. *"a test under the pipe `core_pattern` shows no `coredumpctl` entry for the hardened process"*: `ci/key_memory.py` runs that comparison on a host that pipes to `systemd-coredump` (the Debian 13 VM, the reference host); it passed in the Debian 13 VM, not run on Docker Desktop, whose pipe is not `systemd-coredump` (Result).
- *AC4* is not met: the workspace has no `tracing` (not in `Cargo.lock`, and no new dependency was approved for this story), and the passphrase (4.4), recovery secret (4.5) and capability token (10.2) paths do not exist. What holds today: no key type implements `Debug` or `Display` (4.1's `compile_fail` tests), and no `CryptoError` or `KeyMemoryError` variant carries key material.
- *AC5* waits for the reference host, as the criterion says ("when the reference host exists"); the `key-memory` phase of `e2e/run.sh` is the run it asks for.
- *AC8, "Argon2id ... HPKE"*: neither exists in the crate yet (4.4, 4.6); the guard covers every key operation that exists (generation, HKDF, AES-256-GCM seal and open), and the open points say how 4.4 and 4.6 use it. *"a stack canary measures each guarded operation"*: the canary is compiled in test builds and with the `testing` feature only, so the release build the harness measures carries the canary's paint and measure around each outermost guarded call, and nothing else of the feature in the code it measures.
- *AC9, "a module handler runs inside a boundary that marks its thread"*: the boundary and its mark are `vilicus-core`'s (D151, tested there); the harness, which cannot link `vilicus-core` (AD-3), marks its thread with a stand-in of the same shape. The composed path, the Core's hook given `in_module_code` and a panicking reference handler, is the release gate AD-9 already names.
- *AC10, "the passphrase through the Gateway and the Core's IPC framing, the async runtime, and the recovery and backup secrets"*: none of these paths exists yet (Gateway: Epic 7; async runtime: 5.1; recovery and backup secrets: 4.5, 4.8); the harness covers the paths that exist and a worker thread. The control residue is that of aws-lc-rs used directly, not of the spike's own code with its rules switched off (Decisions).
- *`core-file-excludes-locked-pool`* (Story 1.10) is not carried over: a pool now needs a non-dumpable process, so no process holding a pool writes a core file to scan. `MADV_DONTDUMP` is asserted on the mapping's flags (`dd`) instead.

**Open points**
- *Design documents* (coordinator; none edited here, `doc/architecture-spine.md` and `doc/prd.md` being published copies):
  - **Drafted D154**, "Key memory in `vilicus-crypto`, the start order of the Core, and the key memory regression test", amending D131, D140 and AD-4: "Context: story 4.2 builds the key memory rules of D131. D140 places the process hardening of D131 in `vilicus-core`, but its system calls need `libc`, which only `vilicus-crypto` takes, and no Core process exists before story 5.1; D131 does not say what the pool refuses besides a failed lock, how big a slot is, how nested key operations are scrubbed, what happens to key operations after the SIGTERM wipe, or how its regression test runs without the privileges `cargo test` has. Decision: `vilicus-crypto` holds, in its one unsafe module (`src/memory`, which `ci/crate_graph.toml` lists and the workspace check holds unsafe code to), the key pool, the process hardening, the SIGTERM thread and the panic hook, as four functions the Core calls, as its first action and in this order, before it reads the instance key: `harden_process` (`PR_SET_DUMPABLE` 0, then `RLIMIT_CORE` 0 soft and hard), `take_sigterm` (refused unless the process has one thread), `lock_key_memory`, and `install_panic_hook` given the mark of D151 (`vilicus_core::boundary::in_module_code`). `lock_key_memory` refuses a process that is still dumpable or may write a core, one whose effective capabilities hold `CAP_IPC_LOCK`, a second pool, and a pool `mlock` refuses, with an error naming `LimitMEMLOCK`; without a pool no key is created. The pool holds exactly `PLANNED_SLOTS` slots of 32 bytes, one key each. Only the outermost guarded key operation of a thread scrubs and measures the stack, the operation's closure running in a non-inlined frame below the guard. Once the panic hook or the SIGTERM thread has wiped the pool, the pool refuses every slot. The regression test of D131 is the `key_memory` example of `vilicus-crypto`, built on the release profile with the `testing` feature, which compiles the stack canary and the harness's hooks and which `ci/check_packaging.py` refuses in a release artefact; `ci/key_memory.py` runs its groups in containers given only the capabilities and limits each needs, as the CI job `key-memory` and the `e2e/run.sh` phase `key-memory`; its control is the residue of the same operation on aws-lc-rs directly with the keys in heap copies. Consequences: `vilicus-core` holds no unsafe code until the story that adds its first FFI module (the pidfd peer identity of D125) lists it in `[unsafe_code.modules]`; a key operation still running when SIGTERM arrives races with the wipe; a secret that is not a 32-byte key, such as a passphrase, needs a buffer of its own; the reference host run of FR-13 is that phase run there."
  - **D140**: "the process hardening of D131 in `vilicus-core`" becomes "the process hardening of D131 in `vilicus-crypto`, beside the key pool (D154)", and the decision gains: "each of these crates names its one unsafe module in `ci/crate_graph.toml`, outside which the `unsafe` keyword appears nowhere in the workspace".
  - **Spine AD-4**, after "slots reached only through a closure that scrubs the stack [ADOPTED, D131]": "; `vilicus-crypto` holds the pool, the process hardening, the SIGTERM thread and the panic hook, which the Core calls first, in that order (D154)". **Spine Consistency Conventions, Unsafe code**: after "allowed per block with a `// SAFETY:` comment", add "in the one module `ci/crate_graph.toml` names for the crate".
  - **D131's status** may read "Accepted, amended by D151 and D154".
  - No test reads text these amendments change.
- *Story 4.3* (key hierarchy): role-specific key types over `Slot`; the public closure accessor that keys a SQLCipher file goes through `Slot::with_key`, so it is guarded; the instance key's constructor reads its systemd credential straight into a slot, as `testing::key_from_file` does, after the start order above has run. Each role's live keys count against `PLANNED_SLOTS`; a type that needs more than 32 bytes needs a slot size decided there.
- *Story 4.4* (passphrase KEK): Argon2id runs on the blocking pool inside one guarded call, its working memory a buffer the Core owns and wipes, too large for the pool; the passphrase is not a 32-byte key, so its buffer is the story's to choose. The harness gains a `passphrase` path, with the Argon2id blocks among its patterns, as in the spike.
- *Story 4.5 and 4.8* (recovery and backup secrets): each secret's path joins the harness with its intermediates, as AC10 asks.
- *Story 4.6* (HPKE): every HPKE call runs inside a guarded call (usage rule U9 of `spikes/hpke-review`), the household key opened in place into a slot (U5); a guarded closure over the member private key's slot gives both. The spike measured 16 288 bytes for an HPKE open; the harness's `hpke-open` and `hpke-seal` paths check the depth against the scrub, with the spike's HPKE schedule patterns.
- *Story 5.1* (Core process): `main` calls the four start functions first, in order, and passes `boundary::in_module_code` to the hook; the orderly shutdown that `on_term` starts should stop new key work, since an operation running when the pool is wiped works on zeroes. AC4's `tracing` capture belongs where `tracing` enters, with the passphrase, recovery secret and capability token paths it seeds.
- *Story 5.4* (units): `LimitMEMLOCK` at least the pool (`PLANNED_SLOTS` times 32 bytes, rounded up to pages) plus a margin, `LimitCORE=0`, no `CAP_IPC_LOCK`, a static user that runs nothing else.
- *Reference host* (AC5, FR-13, gate E16-1): run `bash e2e/vm/vm.sh e2e key-memory` there, or `python3 ci/key_memory.py`, and record the result in the E16 row of `doc/research-notes.md`.

## Result

All commands ran on 2026-11-04 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows, WSL2 kernel), `rustc 1.99.0 (b940084d7 2026-09-28)`, on fresh clones of the branch, never on the working tree: the gates on a clone made inside a new Docker volume, the harness runs by `ci/key_memory.py` from a clone in a scratch directory, each run with its own volumes. Every volume created was removed afterwards.

Gates, as `.github/workflows/ci.yml` runs them, on each commit of the story checked out in turn (`8db3170`, `1156d56`, `2b2187a` and the closing commit, each on a fresh clone):
- `python3 -m unittest discover -s ci`: `Ran 239 tests` at `8db3170`, `243` at `1156d56`, `251` at the harness commit (238 before), `OK`.
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: the five primitive source lines, then `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0; the workspace's test build compiles the `key_memory` example, so clippy lints it.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 650 passed, none failed (639 before): `vilicus-crypto` 34 unit tests (25 before) and 15 doc tests (13 before).
- `python3 ci/key_memory.py` (the new `key-memory` job): `all key memory checks passed`, 51 `PASS` lines, no `FAIL`, details below.
- `Cargo.lock`: one added line, the `libc` dependency of `vilicus-crypto`; no package. `cargo tree -p vilicus-crypto -e normal --depth 1` is `aws-lc-rs`, `libc`, `vilicus-types`, `zeroize`.
- Not run here: `cargo deny`, `cargo vet` and `cargo audit` (the tools are not in the image and need the network; the package set is unchanged, which CI confirms); the `key-memory` job on a GitHub runner (the brief forbids pushing): the same script ran here, but the runner's kernel, its apport `core_pattern` and its swap are not Docker Desktop's, so the job's first run is its own evidence; the nightly `fuzz` job (no change to `vilicus-proto`), `hpke-review` and `sqlcipher-regenerate` (no change under their watched paths), and `vm-smoke`.

**The key memory regression**, `python3 ci/key_memory.py` on `2b2187a` (Docker Desktop, WSL2 kernel 6.18, `core_pattern` `|/wsl-capture-crash %t %E %p %s`, 12 GiB of swap). The subject's memory was about 4.9 MB, every mapping read. `name=N[kind:count]` counts distinct copies by mapping.

| Path | Product shape, live (asserted) | Product shape after drop (asserted) | Default shape after drop (asserted non-empty) |
|---|---|---|---|
| copies | key in the pool, and nowhere else | nothing | `key=2[heap:1,stack:1]` |
| derive | parent and child in the pool, nothing elsewhere | nothing (3 patterns) | `parent=1[heap:1]` |
| wrap | KEK and key in the pool, nothing elsewhere | nothing (4 patterns) | `kek=1[heap:1] kek-gcm-h-polyval=1[stack:1]` |
| unwrap | KEK and the opened key in the pool, nothing elsewhere | nothing (4 patterns) | `dek=2[heap:2] kek=1[heap:1]` |
| unwrap with another context | KEK in the pool, the key nowhere | nothing (4 patterns) | `kek=1[heap:1]` |
| wrap and unwrap on a spawned thread | (not scanned live) | nothing anywhere | 4 hits in that thread's stack mapping: `dek=1 kek=3 kek-gcm-h-polyval=1` |

- Stack depth of each guarded operation (canary, asserted at most 64 KiB minus 8 KiB): copies 16 408 bytes (the path's own 16 KiB frame), derive 2 632, wrap 1 232, unwrap 1 088, the same on the spawned thread. Without the scrub, the product's own unwrap leaves aws-lc-rs's GHASH key, in its POLYVAL form, on the stack of the main thread and of the spawned thread, live and after the drop (mutation `no-scrub` below): the scrub is what removes it.
- Patterns never found in any scan, so their absence has no positive control: the raw GHASH key H and the aws-lc-rs HKDF PRK, as in Story 1.10.
- Process state (`process-hygiene`, `pool-guard-pages`): `PR_GET_DUMPABLE` 0, `RLIMIT_CORE` 0 0, `VmLck` 8 kB for the 8 192-byte pool, no `CAP_IPC_LOCK`, pool `VmFlags` with `lo`, `dd` and `wf`, `---p` pages on both sides. `key-pool-capacity`: `CAPACITY 192 true`, `PLANNED_SLOTS` keys then `Exhausted`.
- Refusals at start, each subject ending with status 3, no key created afterwards (`a key: refused (no key pool is locked)`): `unhardened-process-refused` (`NotHardened`), `mlock-refused-fails-closed` (`RLIMIT_MEMLOCK` 0: `Lock { bytes: 8192, errno: 1 }`, the message naming `LimitMEMLOCK`), `cap-ipc-lock-refused` (`CapIpcLock`).
- AC9: `panic-inside-boundary-keeps-keys` (both keys in the pool before and after a panic caught at the stand-in boundary), `panic-outside-boundary-wipes` (none in the hook, after the wipe, before the abort), `panic-abort-no-core-dump` (SIGABRT, no dump), `sigterm-wipes-pool` (none after SIGTERM, exit 0), `kill-while-held` (a read of the pool after SIGKILL, before reaping, returns 0 bytes), `fork-wipes-pool` (`slot_zero=true control_kept=true`).
- AC2, AC7 (`noptrace`): `same-user-reads-dumpable-process` (control), `dumpable-off-blocks-same-user-reader` (`EACCES`), `core-dump-control` (the dumpable control dumps under this pipe), `no-core-dump-SIGABRT`, `no-core-dump-SIGSEGV-fault`, `no-core-dump-SIGQUIT` (hardened, a key held: no dump). `coredumpctl-check`: not run on Docker Desktop, whose `core_pattern` pipes to `wsl-capture-crash`, not `systemd-coredump`.
- Swap (`swap`): `swap-control-unlocked-page-swapped` and `swap-locked-pool-resident` (`pool_present=true pool_swapped=false plain_swapped=true`). The `SKIP` path, on a host without swap, ran in the VM below.

**Debian 13 VM run** (`e2e/vm` harness on this machine's KVM: Debian 13.7 cloud image, kernel `6.12.111+deb13-cloud-amd64`, systemd as PID 1, `systemd-coredump` behind the pipe `core_pattern` `|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F`, Docker 26.1.5, 4 vCPUs, 8 GiB, no swap), `bash e2e/vm/vm.sh sync` then `bash e2e/vm/vm.sh e2e key-memory` at `2b2187a`, results `e2e/results/vm-20261104T100522Z-2b2187a`: phase `PASS` in 95 s, 50 `PASS`, 0 `FAIL`, one `SKIP`. Every check above passed on Debian 13's kernel with the same depths, and: `core-dump-control` (the dumpable control's image piped to `systemd-coredump`); `no-core-dump-SIGABRT`, `no-core-dump-SIGSEGV-fault`, `no-core-dump-SIGQUIT` and `panic-abort-no-core-dump`; `coredumpctl-no-entry-for-hardened-subjects`: `coredumpctl` lists exactly one entry for the harness since the group started, the control (`signal 6 corefile present`), and none for any hardened subject (AC7, gate E16-2); `SKIP swap: the host has no swap (SwapTotal 0 kB)` (gate E16-5). It is still not the reference host: a KVM guest on a desktop CPU (gate E16-1 stays open).

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (FR-13, AD-4) | **Pass** | `the_pool_is_locked_advised_and_between_guard_pages`, `the_pool_holds_the_planned_slots_and_refuses_one_more`, `a_refused_lock_names_limit_memlock`; harness `process-hygiene`, `planted-key-in-pool`, `unhardened-process-refused`, `mlock-refused-fails-closed` (every key creation refused after the failed lock). |
| AC2 (FR-13, E16) | **Pass** (container) | Harness: every `*-core-dropped` and `thread-core-dropped` (nothing found after drop) with its `*-asis-residue-control`; `panic-outside-boundary-wipes`, `sigterm-wipes-pool`, `kill-while-held`; `no-core-dump-*` and `panic-abort-no-core-dump`, with `core-dump-control`. 4.1's `every_key_wipes_its_buffer_when_dropped` on pool slots. |
| AC3 (AD-4) | **Pass** | `check_unsafe_modules` (`test_unsafe_code_outside_the_unsafe_module_fails`, `test_unsafe_code_inside_the_unsafe_module_passes`, `test_the_word_unsafe_in_comments_literals_and_names_passes`, `test_an_unsafe_module_of_a_crate_outside_the_list_fails`); clippy's `undocumented_unsafe_blocks`, denied in the crate, on each block and `unsafe impl`. |
| AC4 (FR-13, NFR-2) | **Not met** (Deviations) | No `tracing` in the tree, and none of the passphrase, recovery secret and capability token paths exists. |
| AC5 (E16, FR-13, D131) | **Open** (no reference host) | The `key-memory` phase of `e2e/run.sh` is the run AC5 asks for; it passed in the Debian 13 VM (above), not on the reference host. |
| AC6 (D131, AD-4) | **Pass** (Deviations) | As AC1, plus `a_second_pool_is_refused`, `cap-ipc-lock-refused`, `key-pool-capacity`, `a_wiped_pool_is_zeroes_and_hands_out_no_slot`. |
| AC7 (D131, FR-13) | **Pass** (Deviations) | `lock_key_memory` refuses an unhardened process (`unhardened-process-refused`); `dumpable-off-blocks-same-user-reader`, `no-core-dump-*`; in the Debian 13 VM, `coredumpctl-no-entry-for-hardened-subjects` under the `systemd-coredump` pipe; mutation `rlimit-core-only` shows `RLIMIT_CORE` 0 alone is not the barrier: under the pipe, the hardened subjects then dump. |
| AC8 (D131) | **Pass** (Deviations) | `every_key_operation_is_within_the_scrub`, `the_canary_measures_each_guarded_call`, `nested_guarded_calls_are_measured_once`; harness `*-stack-depth` on the release build; `copies-core-dropped` against `copies-asis-residue-control`; `key_objects_live_for_one_operation` (4.1) still holds. |
| AC9 (D131, AD-9) | **Pass** (Deviations) | `panic-inside-boundary-keeps-keys`, `panic-outside-boundary-wipes`, `sigterm-wipes-pool`, `fork-wipes-pool`; `sigterm_is_not_blocked_while_other_threads_run`. |
| AC10 (E16, D131) | **Pass** for the paths that exist (Deviations) | The harness: every mapping read through `/proc/<pid>/mem` with `CAP_SYS_PTRACE`, a scan failing on any unreadable mapping, 16-byte windows every 8 bytes, each absence paired with the default shape's residue; the `swap` group's precondition and `SKIP`. |

Mutations, each applied alone to a clone of `2b2187a`, the named tests or check run, each run's output showing its tests ran or the check's failure; the unmutated clone passed (the baseline run above). 25 of 25 made the named tests fail:
- unit tests: a pool one slot larger (`the_pool_holds_the_planned_slots_and_refuses_one_more`); a second pool accepted (`a_second_pool_is_refused`); no `mlock` (`the_pool_is_locked_advised_and_between_guard_pages`); a wipe that keeps handing out slots (`a_wiped_pool_is_zeroes_and_hands_out_no_slot`); a canary that measures nothing (`the_canary_measures_each_guarded_call`); every guard taken for the outermost (`nested_guarded_calls_are_measured_once`); SIGTERM blocked with other threads running (`sigterm_is_not_blocked_while_other_threads_run`); a lock error without `LimitMEMLOCK` (`a_refused_lock_names_limit_memlock`); a slot not wiped on drop (`every_key_wipes_its_buffer_when_dropped`);
- the workspace check: an `unsafe` block in `derive.rs` (`check_workspace.py`: `derive.rs of vilicus-crypto uses unsafe code outside its unsafe module src/memory`); `check_unsafe_modules` left out of the run (the `UnsafeTest` tests);
- the harness: no scrub (`copies-core-dropped`, and `unwrap-core-dropped`, `unwrap-wrong-core-dropped`, `thread-core-dropped`, each finding the GHASH key on the stack); a slot not wiped (`wrap-core-dropped` and the other paths); a refused `mlock` ignored (`mlock-refused-fails-closed`); no guard pages (`pool-guard-pages`); no `MADV_DONTDUMP` (`process-hygiene`); no `MADV_WIPEONFORK` (`fork-wipes-pool`); a pool one slot smaller (`key-pool-capacity`: `CAPACITY 191`); an unhardened process accepted (`unhardened-process-refused`); `CAP_IPC_LOCK` accepted (`cap-ipc-lock-refused`); a panic hook that does not wipe (`panic-outside-boundary-wipes`); a panic hook that ignores the boundary (`panic-inside-boundary-keeps-keys`); a SIGTERM thread that does not wipe (`sigterm-wipes-pool`); `PR_SET_DUMPABLE` left out of the hardening and of its check, `RLIMIT_CORE` 0 only (`dumpable-off-blocks-same-user-reader`, `no-core-dump-SIGABRT`, `no-core-dump-SIGSEGV-fault`, `no-core-dump-SIGQUIT`: under the pipe the kernel dumps a dumpable process whatever its limit); a 16 KiB scrub (`copies-core-stack-depth`: 16 408 bytes against 16 384).
- Writing the panic boundary mutation showed that the harness, given a hook that took the boundary's panic for an outside one, waited for `CAUGHT` while the subject paused at `PANICKED`: the harness now accepts either and fails the check on the second; this was fixed before the mutations ran. Three first runs of harness mutations failed to build because Docker Desktop's file share refused reads of the mounted clone (`Cannot allocate memory`), not because of the mutation; they were run again, and the driver retries on that error.
- Not testable here: `vzeroall` (registers are not readable through `/proc/<pid>/mem`); the stack scrub's exact reach below the guarded frame beyond the canary's measure.
