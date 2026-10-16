---
title: 'Lift a suspension in the app'
epic: 9
story: 11
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-107, D87, D71, FR-8, AD-30, R40]
---

# Story 9.11: Lift a suspension in the app

As an adult,
I want to request that another member's suspension be lifted, with a step-up, a delay and a veto,
So that a suspended member comes back only with the agreement of the household and in plain view of every adult.

**Acceptance Criteria:**

**AC1 (FR-107, D87, D71)**
**Given** a suspended member
**When** an adult other than the suspended member requests the lift in the member web
**Then** the Core creates the pending action and accepts only a step-up bound to its canonical hash
**And** the suspended member cannot request or approve their own lift, and no passphrase is asked

**AC2 (FR-107, FR-8, AD-30)**
**Given** an approved lift request
**When** the delay of FR-8 runs as a durable deadline
**Then** any other adult can veto it with a step-up or `vilicus member veto`, which cancels the lift
**And** the delay runs to its maximum while an adult has had no working destination for 24 hours

**AC3 (FR-107)**
**Given** a lift request
**When** it is made and when it takes effect
**Then** every adult receives an out-of-browser alert at both moments, and both are audited

**AC4 (FR-107)**
**Given** a lift that took effect
**When** the member logs in again
**Then** login works, but every revoked session, device, binding and token stays revoked; the member pairs again or re-enrolls as needed

**AC5 (FR-107, R40)**
**Given** the residual risk that a compromised Gateway can redirect this browser step-up
**When** the lift screen is shown
**Then** it states that the lift takes effect only after the delay and that any other adult can veto it until then
**And** the in-app view of those alerts names the suspended member and the requesting adult, while the push payload stays content-free

**Dependencies:**
- Story 9.10 (suspension)
- Story 9.6 (delay and veto machinery)

**References:**
- `doc/prd.md` FR-8, FR-50, FR-107, section 8.2
- `doc/architecture.md` sections 6 and 20
- `doc/decisions.md` D71, D87
