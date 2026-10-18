---
title: 'Core journal tables and caller idempotency'
epic: 3
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-26, AD-28, FR-29, FR-24, D113, E17, NFR-3, D132, DC-75]
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

**AC6 (FR-29, D113, E17, D132)**
**Given** journal entries in a personal or household partition older than 30 days
**When** retention runs
**Then** they are deleted under `secure_delete` = ON in one `DELETE FROM _journal WHERE created_at < cutoff`, followed in the same maintenance step by a TRUNCATE checkpoint through `sqlite3_wal_checkpoint_v2` (Story 3.1 AC10), retried until it reports not busy and the WAL is empty; E17 took no fallback (D132)
**And** a file inspection test, reusing the procedure of Story 1.11 (`spikes/secure-delete-wal/src/pages.rs` decrypts every page of the file and every frame present in the WAL, `src/scan.rs` searches 16- and 8-byte windows), finds no run of 8 bytes or more of any deleted before-image, after-image or `call_id` in the file, the WAL or the shm, with the live rows found as the control.

**AC7 (D132, E17)**
**Given** a record shredded by destroying its wrapped record key
**When** the deletion completes
**Then** the wrapped key row is deleted under `secure_delete` = ON and followed by a TRUNCATE checkpoint, and no run of 8 bytes or more of the destroyed wrapped key remains in the file or the WAL, `_journal` included, while the record's ciphertext and the kept keys remain
**And** the test includes the negative control of Story 1.11 (`journaled_shredding_keeps_keys_until_journal_rows_go_*`): a journaled delete of the key row leaves the key readable in `_journal` until those journal rows go.

**AC8 (E17, D132)**
**Given** a reader holding an old snapshot on the file
**When** the retention purge's TRUNCATE checkpoint runs
**Then** the checkpoint reports busy and is retried, and the WAL is empty and no deleted value remains once the reader ends (gate E17-2, not exercised by the spike).

**Decision tasks:**
- [ ] Decide how a wrapped record key stays out of `_journal` (D132, Story 1.11 settled task 4). Recommended: never journal it, the typed record API excluding the wrapped record key from before- and after-images, because it keeps the key out of the journal entirely. Gives up: an undo of a shredding cannot restore the key, which is the intent of shredding; the alternative, deleting the journal rows that hold the key in the same step, keeps the undo image but adds a second delete to every shredding.

**Dependencies:**
- Story 3.5 (typed record API)
- Story 3.1 (connection setup and the C API checkpoint)
- Story 1.11 (E17 secure_delete and WAL result)

**References:**
- `doc/architecture-spine.md` AD-26, AD-28
- `doc/prd.md` FR-24, FR-29, DC-75
- `doc/decisions.md` D113, D132
- `doc/research-notes.md` E17
- `doc/stories/story-1.11-e17-secure-delete-and-wal-behaviour.md` (Open decision tasks settled, items 1 to 4 and 6)
- `doc/qa/gates/1.11-e17-secure-delete-and-wal-behaviour.yml` (E17-1, E17-2)
