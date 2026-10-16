---
title: 'Elevated tier 1 queue and light confirmation'
epic: 10
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-28, FR-50, D38, D104, AD-21, AD-13, I35, E22, SM-4, UX-DR5]
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
**Then** the approval is signed by the browser's device key over the canonical bytes of the request, rendered on the screen with the TypeScript CBOR decoder chosen in Story 1.9 and pinned in the Stack
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
**Given** E22 took its third fallback
**When** a member approves
**Then** the approval is a step-up bound to the request hash instead of a device-key signature
**And** in every case the number of elevated requests per member per day is recorded (SM-4)

**AC7 (FR-28, AD-21)**
**Given** a signed approval for request A
**When** it is replayed for A a second time, presented for request B, or sent from another paired device
**Then** each is refused and audited

**Dependencies:**
- Story 10.5 (taint)
- Story 7.8 (change stream for the pending list)

**References:**
- `doc/prd.md` FR-28, FR-50, SM-4
- `doc/architecture-spine.md` AD-13, AD-21
- `doc/ai-safety.md` P4, P12, I35
- `doc/capability-matrix.md` legend (light, elevate, exempt), section 11
- `doc/decisions.md` D38, D104
- `doc/research-notes.md` E22
