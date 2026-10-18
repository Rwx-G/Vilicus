---
title: 'Elevated tier 1 queue and light confirmation'
epic: 10
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-28, FR-50, D38, D104, AD-21, AD-13, I35, E22, SM-4, UX-DR5, D122, D130]
---

# Story 10.6: Elevated tier 1 queue and light confirmation

As a member,
I want an elevated request from a tainted session to wait in my app until I approve or refuse it with one tap,
So that the assistant cannot write on my behalf from tainted context without me seeing exactly what it will do.

**Acceptance Criteria:**

**AC1 (FR-28, D38, FR-50)**
**Given** a tier 1 call from a tainted AI session on a record kind that is not exempt
**When** the pipeline elevates it
**Then** a pending request appears in the member web, approved or refused with one tap
**And** the task receives a pending status, not a result

**AC2 (FR-28, AD-21, AD-13, UX-DR5)**
**Given** a pending request
**When** the member approves it
**Then** the approval is signed by the browser's device key over the canonical bytes of the request, rendered on the screen with `cbor2` 2.4.0 (D130) behind the profile layer of `spikes/canonical-cbor/ts/src/profile.ts`: the same head scan as the Core (depth bound of 32, tags counted, trailing bytes refused), `cbor2`'s dCBOR options with `convertUnsafeIntsToFloat: false`, `rejectFloats`, `rejectBigInts`, `ignoreGlobalTags` and `preferMap`, then the round-trip comparison, so an integer above 2^53 is shown exactly, as a `bigint`; the web client's tests replay the vectors of `spikes/canonical-cbor/vectors/`
**And** a batch shows every line and its canonical hash covers all lines, and no model-written justification is shown

**AC3 (FR-28)**
**Given** a pending request
**When** 24 hours pass (PRD assumption) without a decision, or the state it depended on changes before approval
**Then** the request expires and the task is told, or the approval is refused at re-verification and the call is aborted
**And** three consecutive refusals on the same task suspend the task

**AC4 (FR-28, D104)**
**Given** a record kind declared exempt by its module
**When** an AI principal writes to it in a tainted session
**Then** a write with only structured fields proceeds without elevation, and a write carrying any free-text field is elevated

**AC5 (I35)**
**Given** an approved request that carries structured fields and model-drafted free text from a tainted session
**When** it is written
**Then** the structured fields are stored `trusted` with the approving member as author, the drafted free text stays `external`, and a refused or unapproved request keeps the session's taint

**AC6 (E22, SM-4)**
**Given** E22 took its third fallback (its desktop part passed without one, D122; Android is still to run)
**When** a member approves
**Then** the approval is a step-up bound to the request hash instead of a device-key signature
**And** in every case the number of elevated requests per member per day is recorded (SM-4)

**AC7 (FR-28, AD-21)**
**Given** a signed approval for request A
**When** it is replayed for A a second time, presented for request B, or sent from another paired device
**Then** each is refused and audited

**AC8 (D122, AD-21)**
**Given** a pending request awaiting a light confirmation
**When** the Core issues the challenge and the browser signs it
**Then** the challenge is a canonical map of `kind` (`vilicus/v1/light-confirmation`), `decision`, `request_id`, `request_hash` (the canonical hash of the request), `device_id`, a single-use 16-byte `nonce` and `expires_at` (300 seconds ahead in the spike); before signing, the browser decodes it under the profile layer of AC2, refuses it unless it re-encodes to itself, `kind` is `vilicus/v1/light-confirmation`, `decision` is `approve`, and `request_id` and `device_id` name the request the member is looking at and this device, then signs the bytes exactly as received
**And** the Core keeps the bytes it issued per nonce and verifies against them; a nonce approves only its request, from its device, once; a decided request takes no new challenge; a device gets no challenge for another device's request; lifetimes are checked on a monotonic clock (tests as `ac3.*` and `a_light_confirmation_approves_its_request_only` in `spikes/browser-device-key/`).

**AC9 (D130)**
**Given** a confirmation holding text with code points new to the Core's pinned Unicode version
**When** a browser on newer Unicode tables decodes it
**Then** it may refuse the bytes as not NFC, which fails closed: the client signs nothing, never re-normalizes, and never hashes other bytes than it received (Story 1.9, finding 5; gate E19-3).

**Dependencies:**
- Story 10.5 (taint)
- Story 7.8 (change stream for the pending list)
- Story 7.7 (device key)
- Story 2.5 (canonical encoding and vectors)

**References:**
- `doc/prd.md` FR-28, FR-50, SM-4
- `doc/architecture-spine.md` AD-13, AD-21, Stack (cbor2)
- `doc/ai-safety.md` P4, P12, I35
- `doc/capability-matrix.md` legend (light, elevate, exempt), section 11
- `doc/decisions.md` D38, D104, D122, D130
- `doc/research-notes.md` E22, E19
- `spikes/browser-device-key/` (`src/confirm.rs`, `web/static/confirm.js`), `spikes/canonical-cbor/ts/`
