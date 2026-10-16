---
title: 'Audit verify from the host'
epic: 6
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-31, FR-3]
---

# Story 6.4: Audit verify from the host

As an operator,
I want to verify the audit chain from the host and learn where it was broken,
So that tampering by anything short of root is found and located.

**Acceptance Criteria:**

**AC1 (FR-31, FR-3)**
**Given** an intact chain
**When** root runs `vilicus audit verify`
**Then** the command reports the chain intact with its entry count and head hash, needs no member passphrase and unlocks nothing
**And** it talks to the audit writer through its root-only admin socket

**AC2 (FR-31)**
**Given** a chain where one entry's content was modified, a hash was replaced, or an entry was deleted (three separate tests)
**When** `vilicus audit verify` runs
**Then** it reports the earliest broken entry by sequence number and exits with a non-zero status

**AC3 (FR-31)**
**Given** a verification run
**When** it finishes
**Then** its result (intact, or the earliest broken entry) is stored so the Core can report the audit chain state
**And** the run itself is audited

**Dependencies:**
- Story 6.2 (append path and CLI audit)

**References:**
- `doc/prd.md` FR-3, FR-31
- `doc/architecture-spine.md` AD-17, AD-55
- `doc/architecture.md` section 14
