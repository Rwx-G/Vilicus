---
title: 'Journal undo for members'
epic: 10
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-29, FR-50, AD-26, I9]
---

# Story 10.7: Journal undo for members

As a member,
I want to undo any tier 1 write made in my scope for 30 days,
So that a mistaken or unwanted change, by me or by the assistant, can be reversed cleanly.

**Acceptance Criteria:**

**AC1 (FR-29, AD-26)**
**Given** a tier 1 write journaled within the last 30 days
**When** the member calls `core.undo_write` on it
**Then** every record the write changed returns to its previous state
**And** the undo is itself journaled and audited

**AC2 (FR-29, AD-26)**
**Given** a write whose record `rev` has moved since, because a later write changed the same record
**When** the member asks to undo it
**Then** the undo is refused with an explanation naming the later write, and undoing the later write first is possible

**AC3 (FR-29)**
**Given** a journal entry older than 30 days
**When** the member looks for it
**Then** it is no longer offered for undo, consistent with its deletion under `secure_delete`

**AC4 (AD-26, I9)**
**Given** an undo that restores a before-image
**When** it is written
**Then** the restored record keeps the taint and data types computed by the Core from the journaled inputs, never a lower label

**AC5 (FR-29, FR-50)**
**Given** a member in an authenticated session of the member web
**When** the member undoes a tier 1 write, or an earlier undo, from the digest
**Then** it runs as AC1 with no further confirmation, and undoing an undo restores the state that the first undo reverted

**Decision tasks:**
- [x] Settled by FR-50: a member undoes a tier 1 write, an undo included, in the member web with an authenticated session, offered from the digest.

**Dependencies:**
- Story 10.6 (elevated queue, member web screens for requests)

**References:**
- `doc/prd.md` FR-29, FR-50
- `doc/architecture-spine.md` AD-26
- `doc/ai-safety.md` I9
- `doc/decisions.md` D113
