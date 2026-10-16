---
title: 'E32: Core execution model'
epic: 1
story: 15
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E32, AD-9, NFR-4, D116]
---

# Story 1.15: E32: Core execution model

As the owner,
I want the Core's threading model measured with one action through the full pipeline under household load,
So that a dedicated rule thread stays responsive before the home milestone depends on it.

**Acceptance Criteria:**

**AC1 (E32, AD-9)**
**Given** a prototype under `spikes/e32-execution/` with an async runtime, one writer thread per open file, a bounded blocking pool running Argon2id, HPKE, file copies and migrations, and a dedicated rule thread running a synthetic rule loop
**When** one action runs through the full pipeline (policy, write, audit) under a simulated load of two active adults, including two concurrent unlocks and a backup copying the files, plus the testbed (reference module and test doubles, D102, simulated here because Story 2.6 comes later), on the reference host
**Then** the action's latency is recorded at p50, p99 and maximum, together with the rule thread's wake-to-dispatch latency

**AC2 (E32, NFR-4, D116)**
**Given** the pass criterion of D116: p99 under 100 ms for one action through the full pipeline on the reference host (4 cores, 8 GB, SSD, no GPU, Debian 13), under that load
**When** the measurements are compared with it
**Then** the spike passes or fails on that criterion only

**AC3 (E32, AD-9, D116)**
**Given** the criterion is missed
**When** the result is recorded
**Then** the execution model is revised and measured again before Epic 5 starts, first trying rule thread priority over the blocking pool, lower blocking pool concurrency and throttled backup copies
**And** the revision and its measurement are recorded in `doc/decisions.md`

**Spike plan:**
- Question: does the Core's threading model keep one action through the full pipeline, and a dedicated rule thread, responsive under household load (E32)?
- Method: prototype of the AD-9 execution model with a synthetic rule loop and a synthetic action pipeline (policy, write, audit), under a simulated load of two active adults plus the testbed, measured on the reference host.
- Pass criterion (D116): p99 under 100 ms for one action through the full pipeline on the reference host, under a simulated load of two active adults plus the testbed.
- Timebox: 3 working days.
- Fallback on failure (D116): the execution model is revised before Epic 5 starts; first candidates: give the rule thread priority over the blocking pool, lower the blocking pool's concurrency, and throttle backup copies.
- Result record: E32 status and measurements in `doc/research-notes.md`; tuned values reused by Story 5.1.

**Decision tasks:**
- [x] Settled by D116: p99 under 100 ms for one action through the full pipeline (policy, write, audit) on the reference host, under a simulated load of two active adults plus the testbed; on failure the execution model is revised before Epic 5. Written in `doc/research-notes.md` section 3.1.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3.1 (E32)
- `doc/architecture-spine.md` AD-9, AD-31
- `doc/prd.md` section 7 (performance), section 9, DC-71
- `doc/decisions.md` D102, D116

## Implementation Notes

**What was built.** A standalone crate, `spikes/core-execution/` (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`), and `spikes/core-execution/run.sh`. The script builds and runs everything in a Debian 13 Rust container pinned by digest (`rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a`, the `rust:1-trixie` tag as pulled on 2026-10-16, rustc 1.99.1), constrained with `--cpus=4 --memory=8g --memory-swap=8g`. It prints:
- the source revision (`git rev-parse HEAD` and the count of uncommitted paths under the crate and its path dependency);
- the storage under the work directory and an fsync microbenchmark;
- one `PASS` or `FAIL` line per step, test and check, and the measured tables.

It fails if a test is ignored or the test count differs from the expected count, and exits non-zero on any failure.

**The model measured (spine AD-9).**
- A tokio multi-thread runtime (4 workers, from `available_parallelism` under the cgroup quota) runs the pipeline and the load.
- One writer thread per open file owns that file's only write connection and runs jobs in order. A panicking job is caught there with `catch_unwind` and its transaction rolls back (tested).
- The bounded blocking pool is a semaphore over `spawn_blocking`, with 3 permits in the gate run. It runs Argon2id, the HPKE-shaped unlock and backup sealing, file copies and SHA-256. The permits held are counted and gated to never exceed the pool.
- A dedicated `home-rules` thread runs a synthetic loop of 200 rules over 64 devices. It wakes on each adapter event and dispatches the matching rule's action to the runtime. It ticks a watchdog counter at least every 100 ms, and the longest gap between ticks is recorded and gated at 150 ms.

**The pipeline per action (`doc/architecture.md` section 9.2, steps 1 to 4, 7 and 8).**
1. Schema validation.
2. The principal check: a capability token with scope, expiry and a 50-call budget for `AiTask` and `Plugin`; the partition owner for `Member`; the validated rule for `Rule`; the grant for `Adapter`.
3. Tier lookup and a per-principal cap.
4. Taint for token principals.
5. A SHA-256 parameter hash.
6. On the file's writer thread, one transaction:
   - the Core-stamped envelope and the `rev` check and bump;
   - the `_journal` row with before and after images, the call's input record ids, and (principal, `call_id`) unique;
   - an `_outbox` row for the change event (AD-10).

   The transaction runs on SQLCipher in WAL with `secure_delete` on and `synchronous = FULL`. Adapter reports are not journaled (AD-26). A replayed `call_id` rolls back the whole transaction: `rev` unchanged, one journal row, one outbox row (tested).
7. The audit append over the audit writer's socket, awaited before the response. The acknowledged sequence number advances by one per call and matches the verified chain, and a delayed audit commit shows up in the measured audit stage (both tested).

Connections come from the story 1.7 crate itself, reused as a path dependency (`spikes/sqlite-authorizer`): `open`, `apply_migration` and the `Write` and `Read` policies. Writer and audit connections read back `synchronous = 2`, `secure_delete = 1` and `journal_mode = wal` before the write policy is installed, and fail to open on a mismatch (tested). The TRUNCATE checkpoint is the story 1.11 C API call, `sqlite3_wal_checkpoint_v2`.

**Audit writer.** A separate process (the same executable, `audit-writer`) owns a SQLCipher `audit.db` and appends each entry received on its append socket to an HMAC-SHA-256 chain, committing before it acknowledges. Its second (admin) socket serves the backup: a flush checkpoints `audit.db` in TRUNCATE mode and holds appends until the backup closes the connection. Framing is a length prefix rather than CBOR.

**Load (D116), all of it running during the whole measured window.**
- **Member probe:** one `Member` `tasks.update` on the household file every 100 ms, alternating between the two adults.
- **Token probe:** one `AiTask` `tasks.update` on the household file every 100 ms, under a capability token renewed every 50 calls, sent as a request over a Unix socket to an in-process listener and timed to the response read by the client.

  Both probes are timed from their scheduled tick, so runtime and ingress delay count. Every sample whose operation started inside the window is kept, whenever it completes. The sample count of each probe is gated against the ticks in the window, and a test injects a 300 ms writer pause and checks that the member probe's maximum reaches it with no tick missing.
- **Two active adults:** each does a mix of personal creates and updates and household task and calendar updates, at a Poisson mean of one action per 2 s.
- **Each adult's assistant:** token-principal updates at a mean of one per 3 s, with the token renewed when its budget is spent, and three input record ids per call.
- **The testbed (D102)**, simulated because Story 2.6 comes later: a reference-module plugin writing under a token at a mean of one per 1 s, and a device adapter double emitting events at a mean of one per 250 ms. Each event is sent to the rule thread and reported through the pipeline.
- **Two unlock loops:** one per adult, back to back with a 500 ms gap. Each unlock runs Argon2id at m=256 MiB, t=3, p=4 with the lanes on the pool thread, then the AES-256-GCM DEK unwrap, the HPKE-shaped open of the household key, the HKDF file keys, and a read-only open and `_meta` check of every file the member can open.
- **A backup loop** with a 2 s gap (AD-31):
  - every file except the home file is paused, checkpointed in TRUNCATE mode, copied with SHA-256 and `fsync`, then resumed;
  - the home file goes through the online backup API on its writer thread, 64 pages per step, with queued jobs run between steps;
  - the audit writer is flushed on its admin socket and `audit.db` is copied while appends are held;
  - the instance key is sealed to a backup public key.

  A pause whose checkpoint meets a reader holding the WAL fails fast (20 ms busy timeout), leaves the writer in service and is retried.
- **The home journal retention:** a batch of up to 500 entries older than 24 hours is deleted every 10 s on the home writer, under `secure_delete`, from 20,000 expired entries seeded at the start.
- **A long reader:** a 300 ms read transaction on the household tasks file every 5 s, as a digest render would hold one, so some backup pauses meet a reader.
- **Seed data:** 20,000 records in each personal file, 50,000 in each household tasks and calendar file, 10,000 in the reference file and 20,000 in the home file, about 400-byte bodies. The module files total 113 MiB at the end, each at most about 30 MiB.

**Choices made (recommended answers, for Story 5.1).**
- **Blocking pool permits:** the number of cores minus one, so 3 on the reference host. Two unlocks and a backup then run at the same time, as D116's load requires, and one core stays for the runtime, writers and rule thread. This bound holds only because Argon2id computes its lanes on the pool thread, without the `argon2` crate's `parallel` feature. With parallel lanes, one derivation would take p cores and the permit count would no longer bound the cores.
- **Backup pauses:** one file at a time, each writer paused only for its own checkpoint and copy, and only for files small enough (measured bound below); larger files go through the online backup API. A pause that meets a long reader is retried, never waited out.
- **Audit acknowledgement:** inside the measured latency for every tier, not only tier 2.
- **Durability:** writer connections use `synchronous = FULL`, read back at open.
- **Not needed:** rule thread priority and throttled backup copies, the AC3 fallbacks; AC3 is not triggered.

**Not modelled** (each one qualifies the PASS below):
- the alignment controller and the human steps (no elevated, tier 2 or H call in the load);
- the AD-12 handshake, CBOR framing, MCP and persistent MCP sessions: the ingress is an in-process listener with a fixed binary request, one connection per request, and no `SO_PEERPIDFD` peer identity check (AD-24);
- outbox delivery and `_consumed` (rows are written, never delivered);
- the audit key sealed to the backup public key: the flush and copy are modelled, the sealed key is not;
- the egress upload of the backup;
- systemd units and sandboxing;
- the real `hpke` crate: HPKE is HPKE-shaped (X25519, HKDF-SHA-256, AES-256-GCM from aws-lc-rs), standing in for its cost only;
- the Argon2id parameters, which E12 has not fixed yet: the run uses a heavier-than-floor candidate (256 MiB, t=3, p=4, 445 ms p50 here);
- the reference host itself.

**Deviations and limits.**
- **Location:** AC1 names `spikes/e32-execution/`. The spike is in `spikes/core-execution/`, as the epic's spike dispatch asked. Nothing depends on the path.
- **Dependencies:**
  - tokio 1.53.3, the AD-9 runtime.
  - aws-lc-rs 1.18.2 (aws-lc-sys 0.46.0) for HMAC, SHA-256, AES-GCM, HKDF and X25519.
  - argon2 =0.6.0, the spine's pin, needed because the unlock load has to be the real memory-hard derivation.
  - rusqlite stays =0.40.2 with bundled SQLCipher, adding its `backup` feature.
  - The path dependency on `spikes/sqlite-authorizer` is pinned by the revision printed by `run.sh`.
- **CPU emulation:** Docker on a 24-core Windows desktop, limited by a CFS quota of 4 CPUs and 8 GB. A quota over many cores is not 4 physical cores. The gate run recorded 0 throttled periods out of 6,167; the saturated sensitivity run recorded 175 out of 3,169 (719 ms).
- **Storage emulation:** the work directory is on overlayfs in the Docker Desktop WSL2 virtual machine, whose disk is a virtual disk file on the desktop's SSD. A 4 KiB write plus `fdatasync` measured 4.1 ms p50, 11.0 ms p99 and 18.1 ms max over 2,000 samples in the recorded run, which shared the host with the containers of other spikes running at the same time (E12, E13, E22, E24). The pipeline is fsync-bound: each action commits twice with `synchronous = FULL`, once in the module file and once in `audit.db`. Latencies are therefore sensitive to the storage, and an earlier run of the same model on a quieter host measured a member probe p99 of 24.69 ms instead of 28.01 ms.

## Result

Command, from the repository root on the Windows development host with Docker Desktop: `bash spikes/core-execution/run.sh`. It accepts `E32_DURATION`, `E32_SENSITIVITY_DURATION` and `E32_PAUSE_SIZES` (defaults 600 s, 300 s and `64,256,512`).

The recorded run of 2026-10-16 built from git `HEAD` `6142074dadc0b70adfbd31be7d92cf4dbbe0becd`, with 1 uncommitted path reported: the spike crate itself, untracked; `spikes/sqlite-authorizer` was clean. It exited 0 and printed `RESULT PASS`, with 41 `PASS` and 0 `FAIL` lines:
- `toolchain_components`, `build`, `fmt`, `clippy` (`-D warnings`, all targets);
- 15 test lines and `tests` (15 passed, 0 ignored, 15 expected);
- `fsync_bench`;
- 10 checks for each of the two runs;
- 3 `pause_bound` lines.

An earlier run of the reviewed code failed `no_pipeline_or_background_errors` once per run. The token probe's last request, issued after the window, met an ingress listener that had just closed. That shutdown race is fixed: the listener now waits for the probe to finish.

**AC1: met in emulation; not run on the reference host.** Gate run `ad9`: 600 s measured after a 15 s warm-up, 3 pool permits. Over the window:
- 1,300 unlocks, at most 2 at once;
- 271 backup cycles, each flushing the audit writer and copying `audit.db`, with 646 file copies started while an unlock ran;
- 217 jobs run between home online backup steps, and 157 pause attempts retried behind the long reader (115 long reads);
- 20,000 expired home journal entries deleted;
- at most 3 permits held;
- a longest watchdog gap of 100.5 ms over 7,480 ticks;
- 0 errors, and the audit chain verified all 18,335 entries.

| Measure | Samples | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| Member probe: one member action through the full pipeline | 6,000 | 7.58 | 14.22 | 28.01 | 69.61 |
| Token probe: one token action, socket request to response | 6,000 | 10.54 | 18.24 | 34.72 | 105.02 |
| All pipeline actions, pooled | 23,917 | 8.73 | 16.35 | 31.73 | 105.02 |
| All actions, file idle | 17,380 | 8.02 | 14.31 | 26.00 | 88.00 |
| All actions, file paused for a backup copy | 271 | 19.80 | 45.65 | 69.61 | 103.60 |
| All actions, home file under online backup | 266 | 8.57 | 28.23 | 48.44 | 67.83 |
| Member probe stage: policy | 6,000 | 0.01 | 0.01 | 0.01 | 0.11 |
| Member probe stage: write (queue and transaction) | 6,000 | 3.21 | 7.40 | 20.76 | 66.46 |
| Member probe stage: audit (socket round trip and commit) | 6,000 | 2.70 | 6.26 | 11.24 | 58.36 |
| Rule thread: wake to dispatch | 1,862 | 0.01 | 0.01 | 0.02 | 0.04 |
| Rule thread: event to dispatch | 1,862 | 0.05 | 0.18 | 0.26 | 0.47 |
| Rule: event to action done | 1,862 | 8.93 | 17.33 | 32.60 | 88.07 |
| Background: unlock | 1,268 | 444.66 | 478.64 | 502.16 | 527.92 |
| Background: writer pause per file, from request to resume | 1,320 | 15.25 | 41.28 | 291.60 | 367.33 |
| Background: audit flush and copy | 264 | 9.85 | 13.73 | 15.91 | 25.80 |
| Background: home online backup | 264 | 139.76 | 160.82 | 185.12 | 199.39 |

`run.sh` prints the stage times of every label and the ten slowest actions with their stages and backup state.
- **Where the tail comes from:** the write stage, as the stage rows show.
- **Paused files:** the 103.60 ms maximum was an action waiting 89.85 ms for its file's copy.
- **Idle files:** the 88.00 ms maximum is a `rule: home.set_state` on the home file, with no backup activity on the file when the write was queued or done, and 78.60 ms in the write stage. The tail on an idle file is therefore not explained by backups. The likely causes, queueing behind other home jobs (retention batches up to 26 ms) and fsync stalls on the shared storage (fsync max 18.1 ms), were not isolated.
- **Correction:** this corrects the earlier note, which attributed the whole tail to backup pauses.
- **Writer pause row:** its p99 (291.60 ms) includes the time spent retrying behind the 300 ms long reader. During that time the writer stays in service: a test checks that a write issued during the retries completes in under 100 ms.

**AD-31 pause against file size** (`pause-bound`, one pause per size, with a WAL holding 20,000 single-row commits made with automatic checkpoints off):

| File MiB | WAL MiB | Checkpoint ms | Copy ms | Pause ms |
|---|---|---|---|---|
| 70 | 78.6 | 99.3 | 78.0 | 177.4 |
| 280 | 78.6 | 123.8 | 272.5 | 396.3 |
| 559 | 78.6 | 157.9 | 470.2 | 628.1 |

The copy fits 32.3 ms plus 0.80 ms per MiB of file, so the copy alone reaches 100 ms at about 85 MiB. The checkpoint costs 1.26 to 2.01 ms per MiB of WAL. A 500 MiB file, or a WAL left unchecked for a long day, cannot be paused within 100 ms on this storage. A file of at most 32 MiB whose WAL is held near the default automatic checkpoint (1,000 pages, about 4 MiB) stays near 60 ms (32.3 + 0.80 × 32 + 2.01 × 4).

**AC2: passes D116 in emulation, qualified.**
- **Gate:** member probe p99 28.01 ms, token probe p99 34.72 ms, all actions p99 31.73 ms, against a criterion of under 100 ms.
- **Maxima:** 69.61 ms, 105.02 ms and 105.02 ms. They are reported but are not the criterion.
- **Qualifications:** the PASS holds for the model as built: the "Not modelled" list above, a CPU quota on a larger host, and storage shared with other spikes' containers.
- **Ingress:** the token probe includes ingress over a Unix socket but not the AD-12 handshake, CBOR or MCP, nor peer identity.
- **Sensitivity run** `saturated-pool4` (300 s, 4 permits, 4 unlock loops; informational, not the gate): member probe p99 45.49 ms (max 95.44) over 3,000 samples, token probe p99 61.65 ms (max 114.14), all actions p99 58.16 ms, and rule wake to dispatch p99 0.017 ms.

**Not run here:** the reference host itself (4 physical cores, 8 GB, SSD, Debian 13 amd64). Procedure:
1. Install Docker on that host.
2. Run `bash spikes/core-execution/run.sh` from the repository root.
3. Record the `fsync_bench` line, the three `d116_*` lines, the `ad9` table and the `pause_bound` table.

To remove the container from the measurement, build in it and copy `/target/release/core-execution`, then run `core-execution fsync-bench`, `core-execution run --name ad9 --pool 3 --duration 600` and `core-execution pause-bound` directly.

**AC3: not triggered.** The criterion is met, so no revision is due and nothing is recorded in `doc/decisions.md` under AC3. If the reference host run misses it, the fallbacks to try are already parameters: `--pool 2` lowers the pool's concurrency and `--throttle <bytes per second>` throttles the backup copies. Rule thread priority would be a new `setpriority` call on the pool threads.

**Decision task:** already settled by D116, and applied as written.

## Proposed design document updates

1. `doc/research-notes.md`, section 3, E32 row, Pass criterion column: after "...under a simulated load of two active adults plus the testbed", add: "Met in emulation on 2026-10-16 (story 1.15, `spikes/core-execution/`, Docker `--cpus=4 --memory=8g` on a larger desktop, storage shared with other workloads): one member action through policy, write and audit had a p99 of 28.01 ms over 6,000 samples, one token action sent over a Unix socket a p99 of 34.72 ms, with two unlocks, a backup, journal retention and a long reader running throughout, and rule thread wake to dispatch a p99 of 0.02 ms; the run on the reference host itself is still to do." The status stays "To test" until that run.
2. `doc/architecture-spine.md`, AD-9, Execution model: after "a bounded blocking pool for CPU-heavy work (Argon2id, HPKE, copies, migrations)", add: "with one permit fewer than the host's cores (3 on the reference host); Argon2id computes its lanes on the pool thread, so one derivation holds one core". Record it in a new decision record that cites story 1.15.
3. `doc/architecture-spine.md`, AD-31: after "asks the Core over the admin socket to checkpoint and pause writers", add: "one file at a time, each writer paused only while its own file is checkpointed and copied, and only for files of at most 32 MiB; a larger file, like the home partition's, is copied with SQLite's online backup API in bounded steps; a checkpoint that meets a reader fails fast and the pause is retried, so no writer waits on a reader". Record it in the same new decision record.
4. `doc/decisions.md`: a new decision record, "E32 result and execution model parameters".
   - Context: D116's criterion, met in emulation by story 1.15.
   - Decision:
     - blocking pool permits are cores minus one, valid only with Argon2id lanes computed on the pool thread;
     - backup pauses are per file, for files of at most 32 MiB (measured copy 32.3 ms plus 0.80 ms per MiB, checkpoint up to 2.01 ms per MiB of WAL), with the online backup API above that size;
     - a pause's checkpoint uses a short busy timeout and is retried;
     - the audit acknowledgement counts in every action's latency;
     - writer connections use `synchronous = FULL`, read back at open;
     - Story 5.1 reuses these values.
   - Consequences: the reference host run confirms or reopens it; the tail on idle files (88 ms maximum here) is not explained by backups and is to be watched in that run; the AC3 fallbacks stay available as parameters of the spike.
