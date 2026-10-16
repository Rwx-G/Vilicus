---
title: 'Core journal tables and caller idempotency'
epic: 3
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-26, AD-28, FR-29, FR-24, D113, E17, NFR-3]
---

# Story 3.6: Core journal tables and caller idempotency

As a project maintainer,
I want the Core to own the journal, outbox and consumption tables of every module file and to deduplicate writes by caller call id,
So that every write is undoable, retries never apply twice and outbound effects are never retried blindly.

**Acceptance Criteria:**

**AC1 (AD-26)**
**Given** a newly registered module file
**When** the registry creates it
**Then** it contains the Core tables `_meta`, `_journal`, `_outbox`, `_consumed` and `_dead_letter`
**And** the file has two migration tracks, Core first then module.

**AC2 (AD-26, FR-29)**
**Given** a write through the typed record API
**When** it commits
**Then** the same transaction records in `_journal` the before and after images, the `rev` before and after, the principal and the declared input record ids.

**AC3 (AD-28, AD-26)**
**Given** two calls with the same principal and the same `call_id` against one file
**When** the second arrives
**Then** it is deduplicated and returns the first call's result
**And** a call that writes nothing is not deduplicated.

**AC4 (AD-28, NFR-3)**
**Given** a handler needing an outbound effect
**When** it runs
**Then** it writes an effect intent row with a business idempotency key to `_outbox`, the outcome is recorded after commit as `done`, `failed` or `unknown`
**And** an `unknown` outcome is reported to the member and never retried blindly; only the Core retries, with the same key.

**AC5 (FR-24, AD-26)**
**Given** a consumer's effect on an event
**When** it commits
**Then** the event id is recorded in `_consumed` in the same transaction.

**AC6 (FR-29, D113, E17)**
**Given** journal entries in a personal or household partition older than 30 days
**When** retention runs
**Then** they are deleted under `secure_delete`, applying the E17 result (and its fallback if taken)
**And** a file inspection test finds no plaintext of the deleted before-images in the file or its WAL.

**Dependencies:**
- Story 3.5 (typed record API)
- Story 1.11 (E17 secure_delete and WAL result)

**References:**
- `doc/architecture-spine.md` AD-26, AD-28
- `doc/prd.md` FR-24, FR-29
- `doc/decisions.md` D113
- `doc/research-notes.md` E17
