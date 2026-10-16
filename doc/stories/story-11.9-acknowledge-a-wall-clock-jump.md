---
title: 'Acknowledge a wall-clock jump'
epic: 11
story: 9
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-30, D59, FR-50]
---

# Story 11.9: Acknowledge a wall-clock jump

As an adult,
I want to acknowledge a detected wall-clock jump,
So that suspended security delays resume only after a human has seen the jump.

**Acceptance Criteria:**

**AC1 (AD-30)**
**Given** a pending member addition delay and a recovery wait, and a wall-clock jump of several hours detected against the monotonic clock
**When** the Core detects it
**Then** completion of every pending delay is suspended
**And** every adult is alerted and the member web shows the pending acknowledgement

**AC2 (AD-30, FR-50)**
**Given** a suspended state
**When** an adult acknowledges in the member web with a step-up bound to that acknowledgement
**Then** pending delays resume, each completing only when wall clock and accumulated uptime agree
**And** every adult is notified and an audit entry records the acknowledgement

**AC3 (AD-30)**
**Given** no jump is pending
**When** an acknowledgement is requested
**Then** it is refused

**Decision tasks:**
- [x] Settled by FR-50: an adult acknowledges in the member web with a step-up bound to the acknowledgement, every adult notified, audited.

**Dependencies:**
- Story 5.2 (durable deadlines and clock-jump detection)
- Story 7.6 (action-bound step-up)
- Story 8.1 (out-of-browser notification stage)

**References:**
- `doc/architecture-spine.md` AD-30
- `doc/architecture.md` section 17 (host clock wrong or jumps)
- `doc/decisions.md` D59
- `doc/prd.md` FR-50
