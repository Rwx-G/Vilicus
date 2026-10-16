---
title: 'Passkey authentication and action-bound step-up'
epic: 7
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-10, FR-50, D71, D33, D117, I33, AD-8, E2, E24]
---

# Story 7.6: Passkey authentication and action-bound step-up

As a member,
I want to log in with a passkey and confirm sensitive actions with a step-up bound to exactly that action,
So that one assertion can never be spent on a different action, a second execution or a time window.

**Acceptance Criteria:**

**AC1 (FR-10, E2, E24)**
**Given** an instance name with a valid certificate
**When** a member registers and later asserts a passkey through `webauthn-rs`
**Then** registration and login succeed on the instance name on every supported browser
**And** every login, success or failure, is audited

**AC2 (D71, AD-8, I33)**
**Given** an H action that needs a step-up
**When** the member requests it
**Then** the Core first creates a pending action and derives the WebAuthn challenge from its canonical hash (AD-13)
**And** the assertion authorizes that pending action only

**AC3 (I33)**
**Given** a valid assertion for pending action A
**When** it is presented for action B, for A a second time, after A expired or completed, or against a challenge not derived from a pending action's hash
**Then** each is refused, verified by a property test

**AC4 (FR-10, D33)**
**Given** any step-up, pairing or recovery request
**When** a TOTP code is offered as the factor
**Then** it is refused

**AC5 (FR-10, FR-50, D117)**
**Given** the FR-50 surface table
**When** the routes are enumerated
**Then** no V0.1 route enrolls a TOTP factor, unless the E2 login fallback of D117 has been taken, which adds the enrolment surface with its FR-50 row

**Decision tasks:**
- [x] Settled by FR-50: TOTP enrolment is not reachable in V0.1, and the refusal tests stay; only the E2 login fallback of D117, where TOTP temporarily becomes the primary second factor, adds its surface.

**Dependencies:**
- Story 7.2 (client API types)
- Story 5.2 (Core state for pending actions)
- Story 1.5 (E2 login half result)
- Story 1.4 (E24 result)

**References:**
- `doc/prd.md` FR-10, FR-50
- `doc/architecture-spine.md` AD-8, AD-13
- `doc/ai-safety.md` I33
- `doc/decisions.md` D33, D71, D117
- `doc/research-notes.md` E2, E24
