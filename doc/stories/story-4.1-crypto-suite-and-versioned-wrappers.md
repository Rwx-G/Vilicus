---
title: 'Crypto suite and versioned wrappers'
epic: 4
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-18, AD-4, D28, FR-13, NFR-7, D120, D123, D129, D131]
---

# Story 4.1: Crypto suite and versioned wrappers

As a project maintainer,
I want one crypto suite in `vilicus-crypto` with versioned wrappers and key types that cannot leak,
So that every key the Core holds is wrapped with audited primitives and stays inside the kernel.

**Acceptance Criteria:**

**AC1 (AD-18, D28)**
**Given** the `vilicus-crypto` crate
**When** a key is wrapped or a key is derived
**Then** wrapping uses AES-256-GCM with a random 96-bit nonce and derivation uses HKDF-SHA-256, both from aws-lc-rs
**And** no cryptographic primitive is implemented in Vilicus code (a review checklist item and a dependency check list the only primitive sources)

**AC2 (AD-18)**
**Given** any wrapper produced by the crate
**When** it is serialized
**Then** it carries a format version, the algorithm identifiers (KDF, KEK derivation, AEAD), its parameters, salt or credential reference, nonce, ciphertext, tag, creation time and wrapper id, as `doc/key-management.md` section 9 lists
**And** a wrapper with an unknown version or algorithm identifier, or a lower version than the Core accepts, is refused instead of being downgraded

**AC3 (AD-4, FR-13)**
**Given** the key types defined in `vilicus-crypto`
**When** the crate is compiled
**Then** no key type implements `Clone` or `Debug`, and every key type zeroizes its buffer on drop (unit test inspects the buffer after drop through a test-only hook)
**And** every key type is defined in `vilicus-crypto` and nowhere else

**AC4 (FR-13, AD-4)**
**Given** a module crate that tries to name a `vilicus-crypto` key type
**When** the workspace builds
**Then** a compile-fail test shows the type is unreachable, because `vilicus-crypto` is a dependency of `vilicus-core` only (crate graph of AD-3)

**AC5 (NFR-7, AD-18)**
**Given** the crate's documentation
**When** it describes the suite
**Then** it names aws-lc-rs as the source of AES-GCM and HKDF and states the version 1 identifiers, and claims nothing about the transport beyond D27

**AC6 (D28, D120, D123, D129)**
**Given** the primitive source list of AC1
**When** the dependency check runs
**Then** it lists aws-lc-rs, `hpke` 0.13.0 with the primitive crates it depends on (D120), `argon2` 0.6.0 and `blake2` without the `parallel` feature (D129), and `opaque-ke` 4.0.1 (D123), each with its recorded exception to D28
**And** the crate documentation states that inside HPKE the `hpke` crate brings its own primitive crates, and never calls `hpke`, `argon2` or `opaque-ke` audited at its pinned version.

**AC7 (D131, AD-4)**
**Given** an AEAD or HKDF operation with a key held by the crate
**When** it runs
**Then** the aws-lc-rs objects (`LessSafeKey`, `Prk`) are built from the key slot for that one operation and dropped before it returns, because a live object keeps the key, the HKDF input and the GHASH key on the unlocked heap (Story 1.10, `*-asis-key-object-on-unlocked-heap`)
**And** key bytes are never held in heap memory the Core does not wipe or lock.

**Dependencies:**
- Story 2.1 (workspace and crate graph check)
- Story 2.2 (supply-chain gates that vet aws-lc-rs)

**References:**
- `doc/architecture-spine.md` AD-4, AD-18
- `doc/key-management.md` sections 2, 9, 10
- `doc/decisions.md` D28, D120, D123, D129, D131
- `doc/prd.md` FR-13
