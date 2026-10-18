---
title: 'Core process and execution model'
epic: 5
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-9, AD-2, AD-22, E32, D1, D116, D128, D136]
---

# Story 5.1: Core process and execution model

As an operator,
I want one `vilicus` executable whose subcommands run the Core and each first-party process, with the Core's threading model fixed,
So that the services start the same way everywhere and module work never stalls the kernel.

**Acceptance Criteria:**

**AC1 (AD-2, D1)**
**Given** the `vilicus` binary
**When** it is started with the subcommand of the Core, the Gateway, the audit writer or the egress proxy
**Then** it runs that process role only, in its own process
**And** an unknown subcommand exits with a non-zero status and a usage message in English

**AC2 (AD-9, E32)**
**Given** the Core process
**When** it starts
**Then** it runs an async runtime for I/O, one writer thread per open file, and a bounded blocking pool for CPU-heavy work (Argon2id, HPKE, copies, migrations), with the pool size of AC5 (D136); E32 met D116 in emulation without its fallback, and the reference-host run of AC7 confirms or reopens the values
**And** module handlers run as synchronous functions on the file's writer thread, never on the async runtime (test: a handler that blocks does not delay an unrelated async request beyond a bound)

**AC3 (AD-9)**
**Given** the Core unit started by systemd
**When** the Core is ready to serve
**Then** it reports readiness through `sd-notify`
**And** it sends a `WatchdogSec=` keep-alive from its main loop, so a hung Core is restarted by systemd (test: block the loop, observe the restart)

**AC4 (AD-22)**
**Given** a host configuration
**When** the Core reads it
**Then** non-secret configuration comes from `/etc/vilicus/vilicus.toml`, where only the backup schedule, the certificate alert lead time and the audit spool size are tunable
**And** the Core never reads a secret from an environment variable or a command-line argument (test: a secret-shaped environment variable is ignored and a key option on the command line is rejected)

**AC5 (D136, D128, E32)**
**Given** the blocking pool
**When** the Core sizes it
**Then** it has the host's cores minus one permits (3 on the reference host), counted and gated so the permits held never exceed it, a bound valid only because Argon2id computes its lanes on the pool thread without the `argon2` `parallel` feature, so one derivation holds one core
**And** Argon2id holds at most two of these permits, through the FIFO limiter of Story 4.4 AC6, acquired before the pool permit; the conflict between a separate two-thread Argon2id pool (the first D128 proposal) and this model is settled by D128, D129 and D136, so there is one execution model.

**AC6 (D136, E32)**
**Given** an action through the pipeline (policy, write, audit)
**When** its latency is measured and reported
**Then** writer connections use `synchronous = FULL`, read back at open (Story 3.1 AC6), and the audit acknowledgement is awaited before the response and counts in every action's latency, whatever the tier
**And** the Core records per-commit fsync time next to the write stage, so a storage stall can be told from queueing (gate E32-4: the tail on idle files reached 88 ms in emulation and 329.78 ms on the Debian 13 VM, all in the write stage).

**AC7 (D116, D136, E32)**
**Given** the D116 criterion, p99 under 100 ms for one action through the full pipeline under two active adults plus the testbed, on the reference host
**When** the reference host exists, and again as the real pipeline pieces the spike did not model land (the AD-12 handshake, CBOR framing, MCP, peer identity, outbox delivery, systemd units, the real `hpke` crate, the final Argon2id parameters; gate E32-3)
**Then** `bash spikes/core-execution/run.sh` runs on the reference host with the adopted limiter and E12's final m, in the same session as E12 (Story 4.4 AC9), and records the `fsync_bench` line, the three `d116_*` lines, the `ad9` table and the `pause_bound` table (procedure of Story 1.15, Result, "Not run here"; gates E32-1, E32-2)
**And** if the criterion is missed, the execution model is revised before the Core is built further on it (D116), first with the fallbacks D116 keeps as spike parameters (`--pool 2`, `--throttle <bytes per second>`, rule thread priority by `setpriority` on the pool threads), and the revision is recorded in `doc/decisions.md`.

**Dependencies:**
- Story 3.9 (fault isolation on the writer thread)
- Story 1.15 (E32 result in emulation; D136)
- Story 4.4 (Argon2id limiter)

**References:**
- `doc/architecture-spine.md` AD-2, AD-9, AD-22
- `doc/decisions.md` D1, D113, D116, D128, D129, D136
- `doc/research-notes.md` E32
- `spikes/core-execution/` (`run.sh`, the `ad9` and `saturated-pool4` runs)
- `doc/qa/gates/1.15-e32-core-execution-model.yml` (E32-1 to E32-4)
