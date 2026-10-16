---
title: 'List and remove devices'
epic: 9
story: 8
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-16, FR-50, D52, D59]
---

# Story 9.8: List and remove devices

As a member,
I want to list my paired devices and remove one,
So that a lost or retired browser loses its access at once.

**Acceptance Criteria:**

**AC1 (FR-16, FR-50)**
**Given** a member in an authenticated session
**When** the member opens the device list in the member web
**Then** it shows every paired device of that member with its pairing date and last use, and no device of another member

**AC2 (FR-16)**
**Given** the device list
**When** the member removes a device
**Then** its device key is revoked and every web session bound to it is rejected by the Core on its next request
**And** the removal is audited

**AC3 (FR-16, D59)**
**Given** the audit writer is down
**When** the member removes a device
**Then** the removal proceeds as part of the emergency set and its entry goes to the sealed spool

**AC4 (FR-50)**
**Given** a device removed from its own session
**When** that browser sends its next request
**Then** it is treated as unpaired and must pair again with FR-16

**Decision tasks:**
- [x] Settled by FR-50: removing a device needs an authenticated session; the `doc/capability-matrix.md` row is aligned.

**Dependencies:**
- Story 9.7 (devices beyond the enrollment browser)

**References:**
- `doc/prd.md` FR-16, FR-50
- `doc/capability-matrix.md` section 1
- `doc/architecture.md` section 17
- `doc/decisions.md` D52, D59
