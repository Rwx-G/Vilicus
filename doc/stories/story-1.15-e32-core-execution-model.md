---
title: 'E32: Core execution model'
epic: 1
story: 15
status: draft
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
