---
title: 'E12: Argon2id parameters on the reference host'
epic: 1
story: 8
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E12, FR-11, AD-18, D113, NFR-4]
---

# Story 1.8: E12: Argon2id parameters on the reference host

As the owner,
I want Argon2id parameters measured on the reference host,
So that passphrase unlock stays under its latency target without dropping below the published memory floor.

**Acceptance Criteria:**

**AC1 (E12, FR-11, NFR-4, D113)**
**Given** the reference host (4 cores, 8 GB RAM, SSD, no GPU, Debian 13 amd64) and the `argon2` crate 0.6.0
**When** a benchmark under `spikes/e12-argon2id/` sweeps memory, iterations and parallelism at and above the published memory floor
**Then** it records one parameter set whose single unlock derivation completes under 2 seconds (PRD assumption)

**AC2 (E12, FR-11, AD-18)**
**Given** that parameter set and a global concurrency limit
**When** two unlocks are derived concurrently
**Then** the measured latency of each is recorded, and the concurrency limit is chosen so that neither exceeds the target or the limit's documented consequence is stated

**AC3 (E12, D113)**
**Given** no parameter set meets the target above the memory floor
**When** the result is recorded
**Then** the fallback is recorded in `doc/decisions.md`: lower the concurrency limit, keep the memory floor, accept a longer unlock

**Spike plan:**
- Question: which Argon2id parameters fit the reference host (E12)?
- Method: benchmark on the reference host, single and two concurrent derivations.
- Pass criterion: unlock under 2 seconds with memory above the published floor, under a global concurrency limit, on the reference host.
- Timebox: 2 working days.
- Fallback on failure: lower the concurrency limit, keep the memory floor, accept a longer unlock.
- Result record: parameters recorded in `doc/research-notes.md` (E12 status moved) as the values that become named constants for the wrapper header.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E12)
- `doc/prd.md` FR-11, section 7 (reference host), section 9
- `doc/decisions.md` D113
- `doc/architecture-spine.md` AD-18, AD-9
- `doc/key-management.md` section 3 (passphrase wrapping details)

## Implementation Notes

**Where.** The spike is the standalone crate `spikes/argon2id-params/` (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`). AC1 names `spikes/e12-argon2id/`; the directory follows the naming of the other V0.1 spikes instead, and the AC text is kept as written.

**Library.** `argon2` 0.6.0 (RustCrypto), the version the spine pins in its Stack table and the one AC1 names, built with `alloc`, `parallel` and `zeroize`. Without `parallel` every lane runs on the calling thread, so `p = 4` would cost four times its single-lane time. `parallel` pulls `rayon` (with `rayon-core`, `crossbeam-deque`, `crossbeam-epoch`, `crossbeam-utils`, `either`) into the dependency graph: these are new dependencies of the Core and need owner approval before the Core uses the feature (spine, Dependencies row). The spike also names `rayon` directly, to run Argon2id on a dedicated, size-capped pool instead of rayon's global one, and `zeroize` (in the spine stack) to wipe the derived KEK; neither adds a crate beyond those `argon2`'s features already pull.

**Memory wipe.** argon2 0.6.0 does not wipe its own block memory: `hash_password_into` allocates a `Blocks` buffer whose `Drop` only deallocates (`src/block.rs`, `impl Drop for Blocks`), and the `zeroize` feature only implements `Zeroize` for `Block` and wipes the initial hash. The spike therefore derives with `hash_password_into_with_memory` into a buffer it owns, wipes every block after the derivation, on success and on error, and then frees it (`Pool::derive_with_memory`); the test `derivation_memory_is_wiped` checks the buffer is all zeros afterwards. The measured times include the allocation and the wipe.

**Audit status, stated honestly.** I know of no published third-party audit of the `argon2` crate, and I did not search for one during this spike. AD-18 says primitives come from audited libraries only (D28), so this is a gap of the same kind as the `hpke` exception (D61); see "Proposed design document updates", item 4. The spike checks the crate against two known-answer vectors: the RFC 9106 section 5.3 Argon2id vector (with secret and associated data) on a 4-thread pool with `parallel`, and the reference implementation's Argon2id v0x13 vector without secret or associated data ("password", "somesalt", m = 64 MiB, t = 2, p = 1, as in the `argon2` crate's own `kat.rs`), through the spike's own derivation path.

**What is measured** (`src/main.rs`). Every measurement discards one warm-up derivation or round first.

- Sweep: m in {64, 128, 256, 512, 1024, 2048} MiB, t in {1, 2, 3, 4}, p in {1, 2, 4}, single derivation on a 4-thread pool, 3 samples each.
- The recommended set: single derivation on 1-, 2- and 4-thread pools (20 samples each), then 20 samples on the recommended pool.
- Two unlocks requested at the same instant (a barrier), 15 rounds, under a global limit of 1 and of 2, through `unlock` (header check, limiter, derivation). The faster and the slower latency of each pair are reported separately; each runs from the request to the derived KEK, so time queued behind the limit counts.
- Six candidate sets at p = 4 under the recommended pool and limit, and the selection rule's pick, checked against the constant (`selection_matches_constant`).
- Two bursts of 8 simultaneous requests in a fresh child process (so its peak resident memory, `VmHWM`, belongs to the burst alone): one under the 4 s wait bound, one under a bound of half a derivation.

**Floor** (`src/guidance.rs`). RFC 9106 section 4 recommends Argon2id with m = 2 GiB, t = 1, p = 4, or, when that much memory is not affordable, m = 64 MiB, t = 3, p = 4. The OWASP Password Storage Cheat Sheet gives a minimum of m = 19 MiB, t = 2, p = 1, with equivalent trade-offs 46 MiB/t1, 12 MiB/t3, 9 MiB/t4 and 7 MiB/t5 (all p = 1). These parameter sets are quoted from the published guidance as I know it; the sources were not re-opened during this spike. The floor rule is a project choice, not RFC text: a cost meets the floor when it is at least one RFC 9106 option in both memory and passes. Below 2 GiB that means m >= 64 MiB and t >= 3. OWASP's figures are sized for login hashing at server scale; a passphrase KEK protects a wrapper an attacker can copy and attack offline indefinitely, so no OWASP set meets the floor. Lanes are not part of the floor.

**Ceiling** (project choice). A wrapper header is on disk and attacker-writable, so the Core refuses a header outside [floor, ceiling] before it takes a slot of the limiter (`unlock`, test `unlock_refuses_a_bad_header_before_queuing`): m <= 1 GiB (the whole Argon2id memory budget), m x t <= 4 096 MiB, p <= 8. RFC 9106 option 1 (2 GiB) is above the ceiling on this host size.

**Selection rule** (`candidates` in `src/main.rs`, project choice). Among the candidates at p = 4 (one lane per reference-host core, as in both RFC 9106 options), all inside [floor, ceiling] and within the memory budget under the limit, keep those whose median slower-of-pair latency is within the host's margin, then pick the most work (m x t), then the most memory. The margin comes from `E12_HOST`: `emulation` (default) allows half the 2 s target, because the reference host is likely slower than the desktop; `reference` allows the whole target. The run prints which profile applied.

**Open decision tasks settled.** The story lists no explicit task; the spike had to settle these, each with the recommended answer:

1. Memory floor: at least one RFC 9106 option in memory and passes (m >= 64 MiB and t >= 3 below 2 GiB), not the OWASP minimum.
2. Parameters (named constants for the wrapper header, `recommended::COST`): Argon2id version 0x13, m = 384 MiB (393 216 KiB), t = 3, p = 4, 32-byte output (the AES-256-GCM KEK of AD-18), 16-byte random salt per wrapper. Provisional until the reference-host run below confirms them.
3. Global concurrency limit: 1 derivation at a time (`CONCURRENT_DERIVATIONS`). A limit of 2 gives a lower slower-of-pair latency (median 713 to 961 ms against 876 to 1 086 ms across the runs) but doubles Argon2id memory and makes the first request slower; limit 1 keeps memory at m and lets the first request finish in single-derivation time.
4. Queue: requests start in arrival order (a FIFO ticket queue, test `limiter_admits_in_arrival_order`); a request that cannot start within 4 s (`MAX_QUEUE_WAIT_MS`, two target lengths) is refused as retryable and leaves the queue (`doc/architecture.md` threat S9). The time waited is for measurement only and is never returned to a client.
5. Argon2id pool: a dedicated pool of 2 threads (`POOL_THREADS`, test `pool_caps_threads`), the Argon2id part of the bounded blocking pool of AD-9. The lane count is part of the hash; the thread count is not (test `kek_depends_on_lanes_not_on_pool_threads`). Two threads leave two of the reference host's four cores to the home rule engine and the writer threads; a 4-thread pool was about 30 % faster (medians 345 to 367 ms against 454 to 530 ms) at the cost of every core during an unlock.
6. Memory budget: Argon2id memory across the derivations the limiter admits is at most 1 GiB, a compile-time assertion over the constants and the ceiling. This holds only if every Argon2id call of the Core (passphrase, backup secret D106, admin recovery code D101) goes through the one limiter; the proposed record requires it.
7. Fallback of AC3: not taken (see Result).

**Review of 2026-10-16, dispositions.** All findings held when checked against the code and the argon2 0.6.0 source, and were fixed: the block memory wipe (above); `selection_matches_constant` added, with the median slower-of-pair over 15 rounds after a warm-up; the margin read from `E12_HOST`; the memory-budget runtime check replaced by compile-time assertions, `Checks::record` panics on a duplicate name, and `run.sh` runs the binary only when the build step passed; `ceiling_violation` added; the floor tested on memory alone (`Cost::new(63, 4, 4)`) and on passes alone; the floor rule restated as a project choice requiring the passes of an RFC option (which moved the recommendation from m = 512 MiB, t = 2, below the new floor, to m = 384 MiB, t = 3), with the tie-break on work; the burst check asserts served and refused counts; the limiter test asserts waiters wake well before the bound; the limiter is FIFO; fast and slow pair latencies are reported apart; the second known-answer vector and the pool-cap test added. Per-member limits, backoff and async acquisition are specified in the proposed decision record rather than built, since the spike has no members or async runtime.

## Result

Command, from the repository root on the Windows development host with Docker Desktop: `bash spikes/argon2id-params/run.sh`. It builds and runs everything in `rust:1.99-trixie` (Debian 13, rustc 1.99.1) under `--cpus=4 --memory=8g --memory-swap=8g`, with `E12_HOST=emulation`. Environment printed by the run: `available_parallelism=4`, cgroup `cpu.max=400000 100000`, `memory.max=8589934592`, a 24-core desktop CPU.

Four full runs after the review fixes. Exact outcomes:

- Run 1 and run 2 (before the burst expectation was corrected): 10 PASS, 1 FAIL each; the FAIL was `concurrency_limit_holds`, whose first version required 7 x p95 to be under 80 % of the bound, which the measurement did not meet (3 465 and 3 699 ms against 3 200) although all 8 requests were served. The check now asserts a served range derived from the measured single derivation.
- Run 3: 10 PASS, 1 FAIL (`selection_matches_constant` picked m=256 t=4 p=4). The whole run was about 15 to 30 % slower: other spike containers (E13, E22, E24) were running on the same Docker VM at the same time.
- Run 4 (final): exit code 0, 11 PASS, 0 FAIL: `toolchain_components`, `build`, `fmt`, `clippy` (`-D warnings`, all targets), `tests` (13 tests), `recommended_meets_published_floor`, `single_unlock_under_target`, `concurrent_pair_under_target`, `selection_matches_constant`, `concurrency_limit_holds`.

Ranges below are the spread over the four runs; "final" is run 4.

**This is an emulation, not the reference host.** It ran on a 24-core desktop CPU inside a container given a 4-CPU quota and 8 GB of memory, while other containers shared the machine. A CPU quota is not 4 physical cores, and the desktop's per-core speed and memory bandwidth are very likely above those of a small 4-core host. Argon2id is bound by memory bandwidth, so the reference host will be slower by a factor this run cannot measure.

Candidates, slower of two simultaneous unlocks, limit 1, 2-thread pool, median of 15 pairs (ms):

| Set | Run 1 | Run 2 | Run 3 (contended) | Run 4 (final) |
|---|---|---|---|---|
| m=256 t=3 p=4 | 551 | 566 | 772 | 654 |
| m=256 t=4 p=4 | 639 | 708 | 927 | 785 |
| m=384 t=3 p=4 | 824 | 893 | 1 095 | 945 |
| m=512 t=3 p=4 | 1 092 | 1 471 | 1 428 | 1 255 |
| m=768 t=3 p=4 | 1 842 | 2 036 | 2 197 | 1 901 |
| m=1024 t=3 p=4 | 2 500 | 2 581 | 3 022 | 2 592 |

The rule picked m=384 t=3 p=4 in runs 1, 2 and 4 and m=256 t=4 p=4 in the contended run 3. m=384 sits between 18 % below and 10 % above the 1 000 ms emulation margin, so on a loaded desktop the pick can flip; on the reference host the margin is the whole target and the pick is decided there.

**AC1: PASS on the emulation; not run on the reference host.** Recorded set: Argon2id v0x13, m = 384 MiB, t = 3, p = 4, meeting the floor (RFC 9106 option 2 in memory and passes) and under the ceiling. Single derivation on the 2-thread pool, n=20, allocation and wipe included: final median 515.9 ms, p95 584.1 ms, max 731.8 ms (four runs: median 454 to 530 ms, p95 495 to 589 ms); target 2 000 ms. On 1-, 2- and 4-thread pools, final medians 774.7, 510.1 and 361.2 ms.

**AC2: PASS on the emulation; not run on the reference host.** Two unlocks requested at the same instant, recommended set, 2-thread pool, 15 pairs after a warm-up:

- limit 1, final: faster median 524.1 ms, p95 608.3 ms; slower median 1 038.3 ms, p95 1 185.6 ms, max 1 185.6 ms (four runs: slower median 876 to 1 086 ms, max 936 to 1 601 ms). Argon2id memory at most 384 MiB.
- limit 2, final: faster median 776.5 ms; slower median 813.6 ms, max 871.6 ms (four runs: slower median 713 to 961 ms). Argon2id memory at most 768 MiB.

Limit 1 is chosen; neither unlock of a simultaneous pair exceeded the target in any run. Its documented consequence: the k-th of k simultaneous unlocks waits for the k-1 before it, so latency grows by about one derivation (about 500 ms here) per waiting request. Bursts of 8 simultaneous requests (final run): under the 4 s bound, 8 served (expected 6 to 8), 0 refused, at most 1 at once, peak resident memory 386 MiB (bound 448 MiB); under a 257 ms bound, 1 served and 7 refused (expected exactly that), the shortest refused wait 257 ms. So from about the fourth or fifth simultaneous unlock the target is exceeded on this machine, and past the 4 s bound a request is refused as retryable.

**AC3: not triggered.** A parameter set above the floor met the target on the emulation, so no fallback is recorded in `doc/decisions.md`. It may still be triggered by the reference-host run.

**Tests** (`tests/spike.rs`, 13): the RFC 9106 Argon2id vector on a parallel pool; the reference-implementation vector without secret or associated data through the spike's derivation; the block buffer is all zeros after a derivation; the pool caps the threads rayon reports inside it; the same KEK on 1, 2 and 4 threads and a different one with 2 lanes; each RFC option meets the floor and one pass less does not, 63 MiB fails whatever the passes, 1 GiB with 2 passes fails; only the RFC sets meet the floor; the ceiling refuses one MiB more, more work and more lanes; `unlock` refuses a header below the floor or above the ceiling while the only slot is held; the limiter never exceeds its limit and wakes waiters well before the bound; it admits in arrival order; it refuses after the wait bound and the abandoned ticket does not block the next request; nearest-rank percentiles.

**Not run here: the reference host.** E12's pass criterion is a measurement on the reference host (4 cores, 8 GB RAM, SSD, no GPU, Debian 13 amd64, D113). Procedure:

1. On the reference host, idle, install Docker, check out the branch, and run `E12_HOST=reference bash spikes/argon2id-params/run.sh` (the container limits match the host), or `E12_HOST=reference cargo run --release --locked` in `spikes/argon2id-params/` with Rust 1.99.
2. If every check passes, the constants stand; record the printed numbers in place of the emulated ones.
3. If `selection_matches_constant` fails, set `recommended::COST` to the set it picked, rerun until all checks pass, and record that set.
4. If the rule picks nothing, no candidate meets the target above the floor: AC3 applies. Keep the floor, keep the concurrency limit at its minimum of 1, take the smallest candidate (m = 256 MiB, t = 3), accept the longer unlock, and record the measured number in `doc/decisions.md`.

**Limits, not covered by this spike.**

- Home rule latency during unlocks is E32's measurement (D116). The 2-thread pool is chosen to leave two cores free; E32 should run with it.
- The Argon2id buffer (384 MiB) is far above a typical `RLIMIT_MEMLOCK` and is not locked; it is wiped after each derivation. E16 owns locked memory and should state this.
- The backup secret (D106) and the admin recovery code hash (D101) also use Argon2id; this spike does not set their parameters, only requires that they go through the same limiter.
- Rewrapping: when `COST` is raised later, a wrapper written with the old cost is unlocked with its header's cost and rewritten with the new one during the unlock (key-management.md section 9), so that unlock costs two derivations, one at each cost.
- Measurements are wall-clock on a shared desktop; run 3 shows what contention from other containers does to them.

### Debian 13 VM run (2026-10-17)

Host: the `e2e/vm` harness, a KVM guest (Debian 13.7, kernel `6.12.111+deb13-cloud-amd64`, systemd 257) with 4 vCPUs (`-cpu host` on the same 24-core desktop CPU, Intel Core Ultra 9 285K), 7 947 MiB, no swap, nothing else running in the guest. The spike's own container limits still apply inside it (`cpu.max=400000 100000`, `memory.max=8589934592`, `available_parallelism=4`, `E12_HOST=emulation`, so the 1 000 ms selection margin). Commit `5130fe96fc018337c5e359df305af4fca8642649`, clean tree. Image pinned through the spike's override: `E12_IMAGE=rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (the digest of `rust:1.99-trixie` the other spikes pin; `run.sh` defaults to the tag).

Commands: `E2E_TIMEOUT_SCALE=2 E12_IMAGE=<digest above> bash e2e/vm/vm.sh e2e sandbox locked-memory egress argon2id core-execution` (run A, results `e2e/results/vm-20261017T100711Z-5130fe9`) and `E12_IMAGE=<digest above> bash e2e/vm/vm.sh e2e argon2id` (run B, `vm-20261017T104405Z-5130fe9`).

Both runs: exit 1, 9 `PASS`, 1 `FAIL`. The failure is `selection_matches_constant`: the rule picked m = 512 MiB, t = 3, p = 4 against the constant m = 384 MiB. Every other check passed, including the floor, both latency targets and the burst limiter.

| Measure (ms) | Run A | Run B |
|---|---|---|
| Recommended set, single derivation, 2-thread pool, n=20: median / p95 / max | 340.2 / 351.3 / 352.3 | 291.9 / 295.4 / 296.1 |
| Same, 1-thread and 4-thread pool medians | 613.9 and 223.9 | 504.2 and 190.7 |
| Pair, limit 1: faster median; slower median / p95 / max | 349.9; 691.8 / 753.5 / 753.5 | 294.9; 587.2 / 598.3 / 598.3 |
| Pair, limit 2: slower median / max | 624.3 / 1 098.2 | 522.9 / 535.0 |
| Candidate m=256 t=3, slower of a pair, median | 462.2 | 384.7 |
| Candidate m=384 t=3 | 680.9 | 581.8 |
| Candidate m=512 t=3 | 907.7 | 784.5 |
| Candidate m=768 t=3 | 1 378.0 | 1 183.4 |
| Candidate m=1024 t=3 | 1 878.6 | 1 604.1 |

Bursts of 8: under the 4 s bound 8 served, 0 refused, at most 1 at once, peak RSS 386 MiB; under the short bound (170 and 145 ms) 1 served, 7 refused.

Reading: four dedicated vCPUs without a CFS quota over 24 cores are faster than the Docker Desktop emulation (single median 515.9 ms in the story's final run, 384.5 ms in the campaign), so m = 512 MiB falls under the emulation margin and the rule moves up one step. This is the sensitivity the story already names (m = 384 MiB sat 18 % below to 10 % above the margin); it says nothing about the reference host, which is slower per core and in memory bandwidth than this desktop CPU, and whose run decides the constant with the margin removed. The constant is not changed on the strength of a VM run. AC1 and AC2 stay "PASS on the emulation; not run on the reference host"; AC3 not triggered.

## Proposed design document updates

Not applied: this spike does not edit shared design documents.

1. `doc/research-notes.md`, section 3, E12 row, Pass criterion column: after "...Debian 13 amd64, D113)", add: "Measured on an emulation only (story 1.8, `spikes/argon2id-params/`, a 4-CPU, 8 GB container on a shared desktop CPU): Argon2id m = 384 MiB, t = 3, p = 4 derives in 454 to 530 ms median over four runs, and the slower of two simultaneous unlocks under a limit of one took at most 1 601 ms. The run on the reference host is still to do; the values are provisional until then (new decision record)." The E12 status does not move to verified until that run.
2. `doc/key-management.md`, section 3, "Passphrase wrapping details", after "...with a global concurrency limit.": add: "The passphrase is normalised to Unicode NFC and encoded as UTF-8 before derivation, so the same passphrase typed on two devices derives the same KEK. The floor is RFC 9106 section 4: the cost is at least one of its two options in both memory and passes (a project rule); the OWASP minimum is sized for login hashing and is not the floor for a KEK an attacker can attack offline. Version 1 wrappers use Argon2id version 0x13 with m = 384 MiB, t = 3, p = 4, a 16-byte random salt and a 32-byte output, provisional until E12 runs on the reference host. The Core refuses a header whose cost is below the floor or above the ceiling (m at most 1 GiB, m times t at most 4 GiB, p at most 8) before it queues the derivation. The Argon2id working memory is a buffer the Core owns and wipes after each derivation. When the cost is raised, a wrapper is rewritten at its next unlock, which then costs one derivation at the old cost and one at the new (new decision record)."
3. `doc/decisions.md`: add a new decision record, "Argon2id parameters and unlock concurrency", status Accepted: "Context: FR-11 needs Argon2id parameters above the published floor that unlock under 2 seconds on the reference host (D113), under a global concurrency limit; E12 measured them on an emulation of the reference host (story 1.8). Decision: a cost meets the floor when it is at least one RFC 9106 section 4 option in both memory and passes, and a header is refused above the ceiling of m 1 GiB, m times t 4 GiB, p 8, before it is queued. Version 1 passphrase wrappers use Argon2id version 0x13, m = 384 MiB, t = 3, p = 4, a 16-byte random salt and a 32-byte KEK, over the passphrase normalised to NFC and encoded as UTF-8, as named constants in `vilicus-types`. Every Argon2id derivation of the Core (passphrase, backup secret, admin recovery code) goes through one global limiter: one derivation at a time, admitted in arrival order, run on a dedicated two-thread pool, and acquired without blocking an async worker thread (on the blocking pool or through an async semaphore). A request that cannot start within 4 seconds is refused as retryable; the time it waited is never returned to the client, and the residual timing signal of a refusal is accepted. Each member has at most one derivation in flight or queued, and after a failed passphrase the member's next attempt is delayed with an exponential backoff, so one member cannot hold the queue. The Argon2id working memory is a buffer the Core owns and wipes after each derivation. Consequences: two simultaneous unlocks take about twice a single derivation; from about the fourth simultaneous unlock the target is exceeded, and past the wait bound requests are refused; Argon2id memory never exceeds 384 MiB. A wrapper rewritten after a cost change costs two derivations at its next unlock. The values are provisional until the reference-host run of E12 confirms or replaces them by the selection rule of story 1.8."
4. `doc/decisions.md`: add a new decision record, "Exception to D28 for the `argon2` crate", status Proposed (owner decision needed), aligned with D61: "Context: AD-18 takes primitives from audited libraries only, and the spine pins the RustCrypto `argon2` crate, for which no published third-party audit is known. Decision: an exception to D28 covering `argon2` and the `blake2` crate it depends on. Before the passphrase-wrapping code, an internal security review of both crates and of Vilicus's use of them, assisted by the most capable model available, with every finding closed or accepted and the review committed; in CI, the RFC 9106 Argon2id vectors, the reference implementation's Argon2id vectors without secret or associated data, and a cross-test against the reference implementation (phc-winner-argon2), used as a dev-dependency only, that agrees on 10 000 random cases of passphrase, salt and small parameter sets, run with the `parallel` feature enabled; an external review before V1. The `parallel` feature's dependencies (`rayon` and the crates it pulls) are new Core dependencies and are approved by the owner in the same record or the feature is not used. A defect is fixed upstream and the fix pinned. The documentation never calls the crate audited. Consequences: the passphrase path rests on vectors, a cross-test and reviews, like HPKE under D61."
5. `doc/architecture-spine.md`, AD-18 rule, after "AES-GCM and HKDF come from aws-lc-rs.": add: "Argon2id comes from the `argon2` crate under the exception of (new decision record), derived into a Core-owned buffer that is wiped after use, because the crate frees its own buffer without wiping it."
6. `doc/architecture-spine.md`, AD-9 rule, Execution model: replace "a bounded blocking pool for CPU-heavy work (Argon2id, HPKE, copies, migrations)" with "a bounded blocking pool for CPU-heavy work (HPKE, copies, migrations) and a separate two-thread Argon2id pool behind one global limiter that runs one derivation at a time (new decision record)"; and after "E32 measures rule latency during two concurrent unlocks and a backup", add "with the Argon2id parameters, pool and limiter of E12".
7. `doc/prd.md`, FR-11, first consequence: replace "under a global concurrency limit, with parameters stored in the wrapper header." with "under a global concurrency limit of one derivation at a time in arrival order, with at most one request per member, with parameters stored in the wrapper header and checked against a floor and a ceiling; a request that cannot start within 4 seconds is refused as retryable (new decision record)." The second consequence keeps its `[ASSUMPTION]` until the reference-host run.
8. `doc/prd.md`, section 9 spike table, E12 row: after "accept a longer unlock", add "Emulated result and provisional values in story 1.8; reference-host run outstanding."
9. `doc/architecture-spine.md`, Consistency Conventions table, Dependencies row: add "`rayon` (through the `argon2` `parallel` feature), pending the owner approval of (new decision record)" to the list of approved-and-still-to-choose items, or leave `parallel` off if it is refused (then p = 4 costs four single-lane passes on one thread, and the parameters must be measured again).

