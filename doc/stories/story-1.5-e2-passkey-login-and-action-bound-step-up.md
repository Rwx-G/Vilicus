---
title: 'E2 login half: passkey login and action-bound step-up'
epic: 1
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E2, D71, D107, D117, FR-10, NFR-9]
---

# Story 1.5: E2 login half: passkey login and action-bound step-up

As the owner,
I want passkey login and a step-up whose challenge derives from an action hash proven with `webauthn-rs` on every supported browser,
So that the authentication epic starts on a library that can carry the one-action binding of D71.

**Acceptance Criteria:**

**AC1 (E2, FR-10, NFR-9)**
**Given** a minimal server on `webauthn-rs` 0.5.5 and a page under `spikes/e2-login/`
**When** passkey registration and login run on current and previous Chrome and Firefox, desktop and Android (Safari best effort)
**Then** every supported browser completes registration and login

**AC2 (E2, D71, FR-10)**
**Given** a pending action whose canonical hash the server computes before the prompt
**When** the server derives the WebAuthn challenge from that hash and the browser completes the assertion
**Then** the server verifies the assertion against that action, and refuses the same assertion presented for a different action hash

**AC3 (E2, D107, D117)**
**Given** AC1 or AC2 fails on a supported browser
**When** the result is recorded
**Then** the failing browser and the library behaviour are recorded in `doc/research-notes.md`, and that browser leaves the supported list before Epic 7 authentication work starts
**And** if every supported browser fails, TOTP (D33) temporarily becomes the primary second factor, and the fallback taken is recorded in `doc/decisions.md`

**Spike plan:**
- Question: does `webauthn-rs` 0.5.5 support passkey login and a step-up whose challenge derives from an action hash on every supported browser (E2, login half)?
- Method: minimal server and page; browser matrix; challenge derivation and cross-action refusal test.
- Pass criterion: passkey login and a step-up whose challenge derives from an action hash (D71) succeed on every supported browser (D107).
- Timebox: 3 working days.
- Fallback on failure (D117): a browser that fails leaves the supported list; if every supported browser fails, TOTP (D33) temporarily becomes the primary second factor, until a supported browser passes.
- Result record: E2 login half status in `doc/research-notes.md` per its section 5, with a link to the test result.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E2) and section 1.1 (WebAuthn library)
- `doc/prd.md` FR-10, section 9 (E2 login half)
- `doc/decisions.md` D33, D71, D107, D117
- `doc/architecture-spine.md` AD-8, AD-13, Stack
