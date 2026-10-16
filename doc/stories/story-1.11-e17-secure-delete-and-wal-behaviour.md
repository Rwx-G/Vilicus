---
title: 'E17: secure_delete and WAL behaviour'
epic: 1
story: 11
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E17, FR-29, D113, D2]
---

# Story 1.11: E17: secure_delete and WAL behaviour

As the owner,
I want deleted records checked in the database file and its WAL under `secure_delete`,
So that the V0.1 claim that expired undo journal entries are deleted holds.

**Acceptance Criteria:**

**AC1 (E17, FR-29, D113)**
**Given** a SQLCipher file in WAL mode with `secure_delete` on, under `spikes/e17-secure-delete/`, holding journal rows with before-images of known plaintext
**When** the rows are deleted, the WAL is checkpointed with `TRUNCATE`, and the file and WAL are decrypted and inspected
**Then** no plaintext of the deleted rows is found in the file or the WAL

**AC2 (E17, D2)**
**Given** the same file
**When** deletion happens without a checkpoint and the WAL is inspected before the next one
**Then** the record states whether plaintext remains in the WAL and for how long

**AC3 (E17)**
**Given** plaintext of deleted rows remains after AC1
**When** the result is recorded
**Then** the fallback is recorded in `doc/decisions.md`: vacuum after shredding, and the backup caveat documented

**Spike plan:**
- Question: does `secure_delete` plus WAL behaviour match the deletion claim for expired journal entries (E17)?
- Method: delete records, checkpoint, inspect the decrypted file and WAL.
- Pass criterion: no plaintext of deleted records in the file or WAL.
- Timebox: 2 working days.
- Fallback on failure: vacuum after shredding; document the backup caveat.
- Result record: E17 status in `doc/research-notes.md`; the procedure reused by Story 3.6.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E17)
- `doc/prd.md` FR-29, section 9
- `doc/decisions.md` D2, D113
- `doc/architecture-spine.md` AD-26, AD-23
