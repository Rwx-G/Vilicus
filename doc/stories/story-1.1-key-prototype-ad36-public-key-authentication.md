---
title: 'Key prototype: AD-36 public-key authentication'
epic: 1
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-36, DC-40, DC-72, D74, D107, D117, FR-7, FR-8, T23]
---

# Story 1.1: Key prototype: AD-36 public-key authentication

As the owner,
I want the exact construction that authenticates a member public key from `vilicus member add` to the household key wrap prototyped and written down,
So that no FR-8 code is written on a construction that an attacker with disk write access could defeat.

**Acceptance Criteria:**

**AC1 (AD-36, DC-40, D74)**
**Given** the principle of AD-36 (a member authentication key derived from the enrollment token, wrapped under a key derived from the authorizing adult's household key, and a MAC over the new public key)
**When** the key prototype is written in Rust under `spikes/ad36-key-prototype/`
**Then** it fixes the HKDF labels, the MAC algorithm, the exact MAC inputs and the wrapper layout for every value it stores
**And** it covers the first member's case, where no authorizing adult and no household key exist before enrollment

**AC2 (AD-36, T23, FR-8)**
**Given** a prototype `wrappers.db` and an attacker who can write the data directory but does not hold any household key
**When** the attacker substitutes a member public key before the next adult unlock
**Then** the prototype refuses to wrap the household key to the substituted key because its MAC does not verify
**And** a correctly enrolled key verifies and receives the wrap

**AC3 (FR-7, D107)**
**Given** the prototype passes AC1 and AC2
**When** the result is recorded
**Then** the construction is written into `doc/key-management.md` and recorded as a decision record in `doc/decisions.md`
**And** Story 1.2 and this story are both done before any FR-8 code starts (PRD section 6.1)

**Spike plan:**
- Question: what exact construction authenticates each member public key from `member add` (or the first enrollment) until the household key is wrapped to it (AD-36, DC-40)?
- Method: Rust prototype using the AD-18 primitives (HKDF-SHA-256 and AES-256-GCM from aws-lc-rs, HPKE from the `hpke` crate); attack test with a substituted public key and no household key; first-member flow included.
- Pass criterion: a written construction (labels, MAC, inputs, first member's case) prototyped in Rust, and a test where a disk-write attacker without the household key substitutes a public key and the wrap is refused.
- Timebox: 5 working days.
- Fallback on failure (D117): if the construction does not hold, V0.1 exits with a single member, as under the HPKE fallback of D107, and member addition (FR-8) ships in V0.1.x; FR-8 code does not start until the construction holds.
- Result record: construction in `doc/key-management.md`, decision record in `doc/decisions.md`, status of the AD-36 item updated in `doc/research-notes.md` with a link to the test result.

**Dependencies:**
- None. First in the V0.1 spike order, run alongside the HPKE review and cross-test spike.

**References:**
- `doc/architecture-spine.md` AD-36, AD-18, Deferred section
- `doc/prd.md` section 6.1 exit criteria, section 9, FR-7, FR-8, DC-40
- `doc/decisions.md` D74, D107, D117
- `doc/key-management.md` sections 2, 3 and 5
- `doc/threat-model.md` T23
