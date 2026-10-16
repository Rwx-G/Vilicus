---
title: 'Post-restore security state acknowledgement'
epic: 12
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-53, FR-32, FR-50, D52]
---

# Story 12.5: Post-restore security state acknowledgement

As an adult,
I want to see and acknowledge the security state a restore brought back,
So that an older state, or a chain that does not match the remote sink, never goes unnoticed.

**Acceptance Criteria:**

**AC1 (FR-53, FR-50)**
**Given** a restored instance
**When** an adult logs in to the member web
**Then** they are shown the restored security state: wrapper generations, household key version, safety-relevant marks and grants (empty in V0.1)
**And** they acknowledge it in an authenticated session, and the acknowledgement is audited

**AC2 (FR-53)**
**Given** two adults
**When** only one has acknowledged
**Then** the other is still shown the restored state at their next login

**AC3 (FR-32, FR-53)**
**Given** a configured remote sink whose last recorded head hash is absent from the restored chain, or present at a different sequence number
**When** the restore completes
**Then** a mismatch is reported to every adult and in `vilicus status`

**AC4 (FR-32)**
**Given** a restored chain that contains the sink's last head hash at its recorded sequence number
**When** the restore completes
**Then** no mismatch is reported

**Decision tasks:**
- [ ] Decide the confirmation level for acknowledging the restored security state. Recommended: an authenticated session, as FR-50 states, because the acknowledgement reads state and grants nothing. Gives up: nothing material.

**Dependencies:**
- Story 12.4 (restore)
- Story 11.6 (remote audit sink)

**References:**
- `doc/prd.md` FR-53, FR-32, FR-50
- `doc/architecture.md` sections 17, 18
- `doc/decisions.md` D52
