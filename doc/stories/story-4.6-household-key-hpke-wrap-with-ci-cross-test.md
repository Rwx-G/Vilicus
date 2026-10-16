---
title: 'Household key HPKE wrap with CI cross-test'
epic: 4
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-18, D61, D107, FR-7, DC-40, NFR-7]
---

# Story 4.6: Household key HPKE wrap with CI cross-test

As an adult,
I want the household key wrapped to each adult's public key with HPKE, checked in CI against an independent implementation,
So that any unlocked adult can share the household partition with a locked adult, on a construction whose correctness is tested on every merge.

**Acceptance Criteria:**

**AC1 (AD-18, FR-7)**
**Given** a new household
**When** the Core creates the household key
**Then** it is 256 random bits with a version number, held only in locked memory and in HPKE wrappers
**And** it is wrapped to an adult's public key with HPKE base mode, DHKEM(X25519, HKDF-SHA256) and AES-256-GCM from the `hpke` crate, in a versioned public-key wrapper of `doc/key-management.md` section 9

**AC2 (D61, D107)**
**Given** the workspace CI
**When** `vilicus-crypto` tests run
**Then** the RFC 9180 test vectors for the suite pass
**And** the cross-test moved from Story 1.2 runs against the independent implementation, declared as a dev-dependency only, and agrees on 10 000 random cases

**AC3 (D61)**
**Given** the shipped `vilicus` binary
**When** the crate graph check runs
**Then** the independent HPKE implementation is not a dependency of any shipped crate

**AC4 (NFR-7, D61)**
**Given** the code comments, crate documentation and any document the story touches
**When** they describe the `hpke` crate
**Then** they state the D28 exception of D61 and the internal review, and never call the crate audited (a CI grep fails on that wording next to `hpke`)

**AC5 (DC-40, AD-18)**
**Given** a household key wrapper
**When** an unwrap is attempted with another member's private key or a modified encapsulated key
**Then** it fails with a typed error and no partial plaintext

**Decision tasks:**
- [ ] Decide the independent HPKE implementation (carried from Story 1.2). Recommended: `hpke-rs`, as a dev-dependency only. Gives up: a second Rust implementation shares the language and ecosystem, so a C implementation would be more independent but costs FFI in the test harness.

**Dependencies:**
- Story 1.2 (HPKE review done state and the cross-test)
- Story 4.3 (key hierarchy and `wrappers.db`)

**References:**
- `doc/architecture-spine.md` AD-18, AD-3
- `doc/decisions.md` D28, D61, D107
- `doc/key-management.md` sections 2, 5 and 9
- `doc/prd.md` FR-7, section 9
