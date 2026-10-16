---
title: 'E16: locked memory and zeroization'
epic: 1
story: 10
status: draft
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
