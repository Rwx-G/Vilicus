---
title: 'E22: browser device key, PAKE pairing and signed confirmations'
epic: 1
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E22, AD-21, D35, D38, D107, FR-15, FR-16, FR-28, NFR-9]
---

# Story 1.3: E22: browser device key, PAKE pairing and signed confirmations

As the owner,
I want to know whether a non-extractable browser key, OPAQUE-bound pairing codes and device-signed light confirmations work on every supported browser,
So that browser pairing, session binding and the elevated queue are built on a proven mechanism or on the fallbacks of D107.

**Acceptance Criteria:**

**AC1 (E22, AD-21, FR-15, NFR-9)**
**Given** a prototype page and a Rust verifier under `spikes/e22-device-key/`, on current and previous Chrome and Firefox, desktop and Android (Safari best effort)
**When** the page creates an ECDSA P-256 key with WebCrypto as non-extractable, reloads, and tries to export it
**Then** the key survives the reload, export is refused, and a per-request signature over the AD-21 byte string (SHA-256 of `vilicus/v1/req`, session id, increasing counter, method, path, SHA-256 of the raw body) verifies in Rust

**AC2 (E22, AD-21, D35, FR-16)**
**Given** `opaque-ke` 4.0.1 in the verifier and `@serenity-kit/opaque` 1.1.0 in the page
**When** a pairing code is used by the new browser, and separately observed or relayed by a third party
**Then** the legitimate run binds the code to the new browser's key registration, and the observed or relayed code fails

**AC3 (E22, D38, FR-28)**
**Given** a light confirmation whose canonical bytes are produced by the verifier
**When** the browser signs those bytes with its device key
**Then** the verifier accepts the signature for that request only, and rejects it for any other request bytes

**AC4 (D107)**
**Given** any part of AC1 to AC3 fails on a supported browser
**When** the result is recorded
**Then** the matching D107 fallback is recorded in `doc/decisions.md` and named in the results table

**Spike plan:**
- Question: do a non-extractable device key, PAKE-bound code pairing and signed light confirmations work on every supported browser (E22)?
- Method: prototype page plus Rust verifier; a browser matrix per AC; a relay and an observation test for the code.
- Pass criterion: AC1 to AC3 hold on current and previous Chrome and Firefox, desktop and Android.
- Timebox: 5 working days.
- Fallback on failure: the three fallbacks of D107: sessions re-proven by a passkey assertion every 15 minutes of activity, stated to the user; pairing codes issued only by `vilicus device pair`; approvals made by a step-up bound to the request hash.
- Result record: results table per browser in `doc/research-notes.md` (E22 status moved per its section 5); each fallback taken recorded as a decision record.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3.1 (E22)
- `doc/architecture-spine.md` AD-21, AD-13, AD-19
- `doc/decisions.md` D35, D38, D107
- `doc/prd.md` FR-15, FR-16, FR-28, section 9
- `doc/architecture.md` section 6
