---
title: 'Passkey authentication and action-bound step-up'
epic: 7
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-10, FR-50, D71, D33, D117, I33, AD-8, E2, E24, D124, D138, DC-79]
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

**AC6 (D124, D71, AD-13)**
**Given** an H action that needs a step-up
**When** the Core prepares the step-up
**Then** the pending request carries a 128-bit identifier from the Core's CSPRNG, the Core stores its canonical bytes and executes only those after approval, and the challenge is `SHA-256("vilicus/v1/step-up" || session handle || request hash)`, the session handle being `SHA-256("vilicus/v1/session-handle" || session identifier)`, so the bearer secret of the cookie never enters a challenge, a log or an audit record
**And** at approval the Core checks, in order, a logged-in session, a request of this session (another session's request reads as unknown), the presented hash, single use (checked and set atomically under one lock), expiry, the challenge recomputed for the presenting session against the stored one, the assertion, and the signature counter; two identical actions never share a challenge, so an audit check recomputes from the stored request and the session handle.

**AC7 (D124)**
**Given** `webauthn-rs` 0.5.5, which draws every challenge itself and has no API to set one
**When** the Core sets the derived challenge
**Then** it does so through the authentication state serialized under the `danger-allow-state-serialisation` feature, in one function (`bind_challenge` in `spikes/passkey-stepup/src/stepup.rs`) that refuses unless the original state round-trips through its serialization unchanged, refuses a state without a string at `/ast/challenge`, and refuses unless the rewritten state round-trips unchanged and differs from the original at the challenge only; the state never leaves the Core
**And** a `webauthn-rs` upgrade is gated by the tests of that function, and a caller-supplied challenge is proposed upstream, the workaround being removed when it lands (gate E2L-2).

**AC8 (D124)**
**Given** a credential used in several ceremonies
**When** an assertion arrives
**Then** the Core refuses a signature counter that does not exceed the last one it saw for that credential across every ceremony (both zero means no counter), because `webauthn-rs` compares it only with a copy taken when each authentication state starts, so two step-ups started together would accept the same value
**And** the browser's prompt timeout is a named constant, every ceremony (registration, login, step-up) expires on the Core at that timeout plus a named slack, and the server's refusal of an assertion without user verification (`UserNotVerified`) stays covered by a ceremony test, since browsers refused first in every run (gate E2L-3).

**AC9 (D138, FR-4, DC-79)**
**Given** the Core's WebAuthn relying party
**When** a registration or an assertion arrives
**Then** it accepts only the instance name as RP ID and `https://<instance name>` as origin (WebAuthn Level 3), so a credential or an assertion made on `localhost` or on an IP address is refused server side, whatever the browser did (Story 1.4: on `localhost` both Chrome and Firefox run the ceremony over the temporary certificate)
**And** a test presents a ceremony from a `localhost` origin and from an IP origin and finds both refused.

**Decision tasks:**
- [x] Settled by FR-50: TOTP enrolment is not reachable in V0.1, and the refusal tests stay; only the E2 login fallback of D117, where TOTP temporarily becomes the primary second factor, adds its surface.
- [ ] Settle whether Firefox with a real authenticator accepts an allow list of two credentials: its WebDriver virtual authenticator refused every such list, immediately, while Chrome's accepted them (Story 1.4, settled task 8; gate E24-2). `doc/research-notes.md` section 4 holds it as **open**, blocking the E24 gate of V0.1; step 5 of Story 1.4's manual procedure (a second passkey for the same user on another authenticator, then a login naming both) is the test.

**Dependencies:**
- Story 7.2 (client API types)
- Story 5.2 (Core state for pending actions)
- Story 1.5 (E2 login half result; D124)
- Story 1.4 (E24 result; D138)

**References:**
- `doc/prd.md` FR-4, FR-10, FR-50, DC-79
- `doc/architecture-spine.md` AD-8, AD-13, Stack (webauthn-rs)
- `doc/ai-safety.md` I33
- `doc/decisions.md` D33, D71, D117, D124, D138
- `doc/research-notes.md` E2, E24, section 4
- `spikes/passkey-stepup/` (`src/rp.rs`, `src/stepup.rs`, `src/action.rs`, `tests/ceremonies.rs`)
- `doc/qa/gates/1.5-e2-passkey-login-and-action-bound-step-up.yml` (E2L-1 to E2L-3)
