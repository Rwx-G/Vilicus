---
title: 'E12: Argon2id parameters on the reference host'
epic: 1
story: 8
status: draft
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
