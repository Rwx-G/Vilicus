---
title: 'E19: canonical CBOR in Rust and TypeScript'
epic: 1
story: 9
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E19, AD-13, D113, D19]
---

# Story 1.9: E19: canonical CBOR in Rust and TypeScript

As the owner,
I want canonical CBOR hashing proven identical between the Rust Core and the TypeScript decoder that renders light confirmations,
So that what a member approves in the browser is bound to the same bytes the Core hashes.

**Acceptance Criteria:**

**AC1 (E19, AD-13)**
**Given** the AD-13 profile (deterministic CBOR per RFC 8949 section 4.2.1, no floating-point value, no indefinite-length item, listed tags only) and a large generated corpus of hashed and signed types, under `spikes/e19-cbor/`
**When** the Rust encoder produces the bytes and the TypeScript decoder decodes and the Rust side hashes them with SHA-256
**Then** bytes and hashes are identical across both implementations for every item of the corpus

**AC2 (E19, AD-13)**
**Given** a fuzzed set of non-canonical inputs (unsorted map keys, non-minimal integer lengths, indefinite lengths, floats, unlisted tags)
**When** each decoder receives them
**Then** every decoder rejects exactly the same inputs

**AC3 (E19, D19)**
**Given** the corpus passes
**When** the spike ends
**Then** the test vectors are committed for reuse by Story 2.5 and later decoders (the Kotlin part runs before the native app milestone)
**And** if bytes or rejections differ, the fallback (switch the canonical form) is recorded in `doc/decisions.md`

**Spike plan:**
- Question: is canonical CBOR hashing identical between the Rust Core and the TypeScript decoder (E19, Rust and TypeScript part)?
- Method: cross-language test vectors and fuzzing under the AD-13 profile.
- Pass criterion: identical bytes and hashes on a large corpus; every decoder rejects the same non-canonical inputs.
- Timebox: 4 working days.
- Fallback on failure: switch the canonical form.
- Result record: E19 status in `doc/research-notes.md` (Rust and TypeScript part), vectors committed, both crate and package choices added to the spine Stack with pinned versions.

**Decision tasks:**
- [ ] Decide the Rust CBOR crate between `cbor4ii` and `dcbor` (spine Deferred). Recommended: `dcbor`, because it enforces the deterministic profile and rejects non-canonical input natively, which is the property AD-13 relies on. Gives up: `cbor4ii` speed and serde integration, so closed-type mapping takes more code in `vilicus-proto`.
- [ ] Decide the TypeScript CBOR decoder package (approved by D113). Recommended: `cbor2`. Gives up: a smaller decoder that would need its own canonical checks.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E19)
- `doc/architecture-spine.md` AD-12, AD-13, Deferred section (CBOR crate)
- `doc/decisions.md` D19, D113
- `doc/prd.md` FR-28
