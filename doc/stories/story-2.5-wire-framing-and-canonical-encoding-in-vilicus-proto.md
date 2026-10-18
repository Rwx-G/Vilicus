---
title: 'Wire framing and canonical encoding in vilicus-proto'
epic: 2
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-12, AD-13, D19, E19, D130]
---

# Story 2.5: Wire framing and canonical encoding in vilicus-proto

As a project maintainer,
I want one framing layer and one canonical encoding for every internal socket and every hashed or signed value,
So that no adapter invents its own codec and every signer hashes exactly the bytes the Core hashed.

**Acceptance Criteria:**

**AC1 (AD-12, D19)**
**Given** a socket kind declared as control or data
**When** a frame is read
**Then** it is a 4-byte big-endian length followed by one CBOR message, and a length above the declared maximum (1 MiB for control, 16 MiB for data, spine assumption) is refused before any byte of the message is decoded
**And** a message nested deeper than the profile bound (32 arrays, maps or tags, D130) is refused before recursive decoding, since a 1 MiB control frame can hold a million levels and `dcbor` recurses without a bound (Story 1.9, finding 2).

**AC2 (AD-12)**
**Given** a new connection
**When** the first frame arrives
**Then** it must be `Hello` carrying protocol, supported versions, unit and build, answered with the chosen version or a refusal
**And** every request carries a `request_id`, writing requests a `call_id`, and `Cancel` (by `request_id`) and `Ping` are defined.

**AC3 (AD-12)**
**Given** a message with a field not declared in its closed type
**When** it is decoded
**Then** it is rejected, never ignored or repaired, through one closed-type check implemented once in `vilicus-proto`.

**AC4 (AD-13, D130)**
**Given** a value of a hashed or signed type
**When** it is encoded for hashing
**Then** it is encoded as dCBOR restricted by the D130 profile and hashed with SHA-256: no floating-point value, no indefinite-length item, no tag (the listed tag set is empty), integers within [-2^63, 2^64 - 1], simple values false, true and null only, at most 32 nested arrays, maps or tags, and text in NFC under the Core's pinned Unicode version
**And** hashed and signed types respect these limits, enforced by a test over every such type.

**AC5 (AD-13, E19, D130)**
**Given** a non-canonical encoding of a valid value
**When** the decoder receives it
**Then** it is rejected
**And** the shared E19 test vectors run in CI against the Rust encoder and decoder, on `dcbor` 0.25.2 behind the profile layer of `spikes/canonical-cbor/src/profile.rs` (a head walk without recursion before decoding, trailing bytes refused, the value check, the round-trip comparison, NFC text and unique keys on encode), with the vectors of `spikes/canonical-cbor/vectors/` and their generator (`gen_vectors`) moved into the test data of `vilicus-proto`, and the `unicode_version` header of the vectors checked against the pinned `unicode-normalization`; E19 took no fallback (D130).

**AC6 (D130, E19)**
**Given** the three `dcbor` 0.25.2 defects E19 found (gate E19-1)
**When** the profile layer's tests run
**Then** the integral float `fb43e0000000000001`, which raw `dcbor` decodes to the integer 2^63 + 2048, is refused; 10 000 nested arrays are refused without a stack overflow; a map built with the keys `caf\u{e9}` and `cafe\u{301}` is refused on construction instead of collapsing to one entry; and non-NFC text is refused on encode, never normalized
**And** closed types are mapped to and from `dcbor` values by hand in `vilicus-proto`, through the same profile layer.

**AC7 (D130)**
**Given** the Core's normalization tables
**When** the workspace builds
**Then** `unicode-normalization` is pinned exactly (`=0.1.25`, Unicode 17.0.0), because the Unicode version is part of the canonical form
**And** a stored hash is only ever checked against the stored canonical bytes it was computed from, never against a re-encoding of the stored value (test); a change of the Unicode version needs its own decision record, a new protocol version (AD-12) and regenerated vectors stating the new `unicode_version`.

**AC8 (D130, D28)**
**Given** `dcbor` in the Core's dependency tree
**When** `cargo audit` and `cargo deny` run (Story 2.2)
**Then** `deny.toml` lists RUSTSEC-2024-0436 (`paste`, unmaintained, a build-time proc-macro of `dcbor`, no known vulnerability) as an advisory exception with that reason and a review date of 2027-04-16, when `dcbor` is checked for a release without `paste` or the exception is renewed (Story 1.9, proposed update 8; gate E19-2).

**Dependencies:**
- Story 1.9 (dcbor and its profile layer, vectors in `spikes/canonical-cbor/vectors/`; settled by D130)
- Story 2.2 (`deny.toml` and the supply-chain gates)
- Story 2.4 (shared types)

**References:**
- `doc/architecture-spine.md` AD-12, AD-13, Stack (dcbor, unicode-normalization)
- `doc/decisions.md` D19, D130
- `doc/research-notes.md` E19
- `doc/stories/story-1.9-e19-canonical-cbor-in-rust-and-typescript.md` (Implementation Notes, Findings 1 to 7)
- `doc/qa/gates/1.9-e19-canonical-cbor-in-rust-and-typescript.yml` (E19-1, E19-2)
