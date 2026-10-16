---
title: 'Member list for the instance admin'
epic: 11
story: 8
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-50, D5]
---

# Story 11.8: Member list for the instance admin

As an instance admin,
I want to see the members with their locked or suspended state,
So that I can manage the system without any access to member data.

**Acceptance Criteria:**

**AC1 (FR-50)**
**Given** two members, one unlocked and one suspended
**When** the instance admin opens the member list in the instance admin web
**Then** each member is shown with locked or unlocked and suspended or active state

**AC2 (D5)**
**Given** the member list response
**When** a test inspects every field returned
**Then** it contains no partition data, no record and no key material

**AC3 (FR-50)**
**Given** the member list page
**When** the instance admin triggers the kill switch from the instance admin web
**Then** the kill switch runs as for any human web session

**AC4 (FR-50)**
**Given** a member web session
**When** it requests the instance admin member list route
**Then** the request is refused

**Dependencies:**
- Story 9.10 (suspension state)

**References:**
- `doc/prd.md` FR-50, FR-30
- `doc/decisions.md` D5
