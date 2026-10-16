---
title: 'Member audit view and head hash'
epic: 11
story: 10
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-31, FR-50, FR-32, NFR-2]
---

# Story 11.10: Member audit view and head hash

As a member,
I want to read the audit log entries in my own scope,
So that I can see after the fact what was done on my behalf and on the household partition.

**Acceptance Criteria:**

**AC1 (FR-31, FR-50)**
**Given** an unlocked member with audit entries for their unlock, a CLI command and a refused tool call
**When** they open the audit view in the member web
**Then** those entries are listed with time, principal, action, tier and outcome

**AC2 (FR-31)**
**Given** entries in another member's scope
**When** the member opens the audit view
**Then** none of those entries is listed

**AC3 (NFR-2)**
**Given** the audit view response
**When** a seeded-secret test inspects it
**Then** no sensitive parameter appears; parameters are shown only as their canonical hash

**AC4 (FR-32)**
**Given** a running instance
**When** the member opens the audit view
**Then** the current head hash is shown for information only

**Dependencies:**
- Story 6.2 (Core audit append path)
- Story 9.3 (member web session and unlock)

**References:**
- `doc/prd.md` FR-31, FR-32, FR-50
- `doc/capability-matrix.md` section 1 (read audit log, own scope)
- `doc/architecture.md` section 14
