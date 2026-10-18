---
title: 'Locked memory and key hygiene'
epic: 4
story: 2
status: draft
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
