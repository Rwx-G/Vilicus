---
title: 'Kill switch and resume'
epic: 10
story: 9
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-30, FR-12, FR-3, I10, I12, AD-11, D31, D86, D101]
---

# Story 10.9: Kill switch and resume

As an adult,
I want a kill switch I can pull from any web session or from the host,
So that I can stop every assistant and plugin activity at once when something looks wrong.

**Acceptance Criteria:**

**AC1 (FR-30, D101)**
**Given** an authenticated member web session, an instance admin web session, or root at the host
**When** the human triggers the kill switch, or root runs `vilicus killswitch`
**Then** the kill switch takes effect without a passphrase
**And** it is audited and every adult is notified

**AC2 (I10, D31)**
**Given** a tainted AI session
**When** it tries to trigger the kill switch through any path
**Then** it is refused, and only a human can trigger it (tested per trigger source)

**AC3 (I12, AD-11)**
**Given** outstanding capability tokens on the reference host
**When** the kill switch is triggered from the web and, separately, from `vilicus killswitch`
**Then** every outstanding token fails within 5 seconds on both paths (timing test)

**AC4 (FR-30, AD-11, FR-12)**
**Given** the kill switch has fired
**When** the Core applies it
**Then** pending elevated requests from token principals are cancelled, AI processes and plugins that declare a network effect are suspended, and unlock windows end (`doc/architecture.md` section 9.6)
**And** approving a request whose task no longer exists is refused

**AC5 (FR-30)**
**Given** the kill switch is active
**When** an adult resumes
**Then** resuming requires a passkey step-up bound to the resume action, and it is audited

**AC6 (D86)**
**Given** a Core detector suspending a task
**When** it fires
**Then** it does not trigger the kill switch

**Dependencies:**
- Story 10.8 (caps and detectors)

**References:**
- `doc/prd.md` FR-3, FR-12, FR-30
- `doc/architecture-spine.md` AD-11
- `doc/architecture.md` section 9.6
- `doc/ai-safety.md` P8, I10, I12
- `doc/capability-matrix.md` section 1 (trigger the kill switch, resume)
- `doc/decisions.md` D31, D86, D101
