---
title: 'Wire framing and canonical encoding in vilicus-proto'
epic: 2
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-12, AD-13, D19, E19]
---

# Story 2.5: Wire framing and canonical encoding in vilicus-proto

As a project maintainer,
I want one framing layer and one canonical encoding for every internal socket and every hashed or signed value,
So that no adapter invents its own codec and every signer hashes exactly the bytes the Core hashed.

**Acceptance Criteria:**

**AC1 (AD-12, D19)**
**Given** a socket kind declared as control or data
**When** a frame is read
**Then** it is a 4-byte big-endian length followed by one CBOR message, and a length above the declared maximum (1 MiB for control, 16 MiB for data, spine assumption) is refused before any byte of the message is decoded.

**AC2 (AD-12)**
**Given** a new connection
**When** the first frame arrives
**Then** it must be `Hello` carrying protocol, supported versions, unit and build, answered with the chosen version or a refusal
**And** every request carries a `request_id`, writing requests a `call_id`, and `Cancel` (by `request_id`) and `Ping` are defined.

**AC3 (AD-12)**
**Given** a message with a field not declared in its closed type
**When** it is decoded
**Then** it is rejected, never ignored or repaired, through one closed-type check implemented once in `vilicus-proto`.

**AC4 (AD-13)**
**Given** a value of a hashed or signed type
**When** it is encoded for hashing
**Then** it is encoded as deterministic CBOR (RFC 8949 section 4.2.1) and hashed with SHA-256
**And** hashed and signed types contain no floating-point value, no indefinite-length item and no tag outside the listed set, enforced by a test over every such type.

**AC5 (AD-13, E19)**
**Given** a non-canonical encoding of a valid value
**When** the decoder receives it
**Then** it is rejected
**And** the shared E19 test vectors from Story 1.9 run in CI against the Rust encoder and decoder, using the CBOR crate chosen in that story; if E19 took its fallback, the canonical form recorded by that story is the one implemented.

**Dependencies:**
- Story 1.9 (CBOR crate chosen, vectors committed)
- Story 2.4 (shared types)

**References:**
- `doc/architecture-spine.md` AD-12, AD-13, Deferred (CBOR crate)
- `doc/decisions.md` D19
- `doc/research-notes.md` E19
