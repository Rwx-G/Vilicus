---
title: 'Household key HPKE wrap with CI cross-test'
epic: 4
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-18, D61, D107, FR-7, DC-40, NFR-7, D120, D131]
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

**AC2 (D61, D107, D120)**
**Given** the workspace CI
**When** `vilicus-crypto` tests run
**Then** the RFC 9180 test vector for the suite passes: the suite's entry (mode 0, KEM 0x0020, KDF 0x0001, AEAD 0x0002) of the CFRG HPKE test-vector file that RFC 9180 references, since Appendix A prints none for this suite, kept as the subset of `spikes/hpke-review/vectors/` with its `SHA256SUMS` and source record
**And** the cross-test moved from Story 1.2 (`spikes/hpke-review/tests/cross_test.rs`) runs against `hpke-rs` 0.8.0, declared as a dev-dependency only, once with its RustCrypto provider and once with its libcrux provider, and agrees on 10 000 random cases in both directions with byte-identical seals under queued randomness, from the fixed seed `0x56494c4943555331`

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

**AC6 (D120, AD-18)**
**Given** the Core's HPKE code
**When** it is reviewed against the usage rules U1 to U10 of `spikes/hpke-review/REVIEW.md` section 7
**Then** each rule holds and has its test: `hpke` pinned `=0.13.0` (any version change reopens the review) with the `zeroize` features of `x25519-dalek`, `aes`, `aes-gcm`, `ghash` and `polyval` enabled and the resolved features checked in CI (U1); the AD-18 suite in base mode only, fixed in the types (U2); single-shot seals with a fresh ephemeral key from an OS-generator adapter that aborts on failure (U3); an `info` that binds a value unique to each seal (U3b); `DeriveKeyPair` with at least 32 bytes of input (U4); wrapped keys opened in place into the locked pool, never through the `Vec`-returning `single_shot_open` (U5); one refusal for every HPKE error (U6); private keys never compared (U7); recipient keys used only after their authentication (U8, Story 4.7); `info` = `vilicus/v1/hk/wrap/` with the member identifier and the HK version, and the permanent MAC as additional data (U9, D119); every opened key confirmed before use (U10, D121 in Story 4.7)
**And** every HPKE call runs under the stack scrub guard of Story 4.2 AC8 and keeps no RustCrypto AES-GCM object on the heap, because an HPKE call leaves its key schedule and the GHASH key on the stack, which `polyval`'s x86_64 backend never wipes (D131; REVIEW.md F1 and F2 measured by Story 1.10).

**Decision tasks:**
- [ ] The owner approves the dispositions of `spikes/hpke-review/REVIEW.md` (13 findings, none High, each closed or accepted by the author) before FR-8 code, as D120 requires (gate HPKE-2); FR-8 code then implements D121.

The independent HPKE implementation is settled by D120: `hpke-rs` 0.8.0 with its RustCrypto and libcrux providers, a dev-dependency only (the libcrux provider shares no primitive code with `hpke`, REVIEW.md F11).

**Dependencies:**
- Story 1.2 (HPKE review done state and the cross-test)
- Story 2.2 (the spike's CI job, whose first green run completes the D120 gate)
- Story 4.2 (locked pool and stack scrub guard)
- Story 4.3 (key hierarchy and `wrappers.db`)

**References:**
- `doc/architecture-spine.md` AD-18, AD-3
- `doc/decisions.md` D28, D61, D107, D119, D120, D121, D131
- `doc/key-management.md` sections 2, 5, 9 and 10
- `doc/prd.md` FR-7, section 9
- `spikes/hpke-review/` (`REVIEW.md`, `src/lib.rs` as the reference shape, `tests/`)
- `doc/qa/gates/1.2-hpke-internal-review-and-cross-test.yml` (HPKE-1, HPKE-2)
