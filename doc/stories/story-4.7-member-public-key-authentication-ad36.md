---
title: 'Member public key authentication (AD-36)'
epic: 4
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-36, D74, DC-40, FR-7, FR-8, T23, D119, D121, T68]
---

# Story 4.7: Member public key authentication (AD-36)

As an adult,
I want the household key wrapped only to a member public key the Core has authenticated,
So that someone who can write the data directory, or a compromised Gateway at enrollment, cannot receive the household key at the next adult unlock.

**Acceptance Criteria:**

**AC1 (AD-36, D74, FR-8)**
**Given** an unlocked authorizing adult and a new enrollment token at `member add`
**When** the Core prepares the enrollment
**Then** it derives the enrollment authentication key from the token with the label settled by Story 1.1 and stores it in `wrappers.db` wrapped under a key derived from the household key
**And** only a hash of the token, under a different label, is kept to check the token

**AC2 (AD-36, D74)**
**Given** a member completing enrollment with that token
**When** the Core generates the member key pair
**Then** it stores, next to the public key, a tag computed with the enrollment authentication key over the fields fixed by Story 1.1, then discards the token and the derived key

**AC3 (AD-36, T23)**
**Given** a pending public key and an adult unlock after the delay
**When** the Core verifies the tag and writes the permanent MAC under the household-key-derived key
**Then** only then is the household key wrapped to that public key, and every later wrap first checks the permanent MAC
**And** a tag or MAC that fails verification refuses the wrap and returns a typed alert for every adult

**AC4 (T23, AD-36)**
**Given** an attacker with write access to `wrappers.db` and no household key
**When** the test substitutes a member public key (with and without recomputing a tag under a guessed key)
**Then** the wrap is refused

**AC5 (FR-7, D74)**
**Given** the first member of a household
**When** the household key is created in the same ceremony as the member key pair
**Then** the Core writes the permanent MAC at once, as the first-member case settled by Story 1.1

**AC6 (D119, AD-36)**
**Given** the encodings fixed by D119 in `doc/key-management.md` section 2, with the byte layouts of `spikes/ad36-key-prototype/README.md`
**When** the Core's key code implements them
**Then** derivations are HKDF-SHA-256 with no salt; the token check hash has its own label `vilicus/v1/enroll-token-check/`; the enrollment key is wrapped with AES-256-GCM under a key and additional data that bind the member identifier and the HK version, so a wrap from another HK version is refused as stale, not as tampering; the MAC input is one canonical, length-prefixed concatenation of the member identifier and both public keys in their stored encoding; the HK wrap's HPKE `info` is `vilicus/v1/hk/wrap/` with the member identifier and the HK version, its additional data the permanent MAC; every stored value carries a version and an algorithm identifier
**And** member identifiers bound into the construction are the Core's binary 16-byte UUIDv7, never a display name, and known-answer tests pin the byte layouts against the README, as `readme_layouts.rs` of the spike does
**And** the refusals of the spike's I/O matrix hold on the product code, each the failing check of its own test: a substituted member or inbox public key, an edited tag or enrollment key wrap, a permanent MAC edited after the first wrap, a wrong or reused token.

**AC7 (D121, T68)**
**Given** a member enrolled after the first, whose HK wrap HPKE base mode does not authenticate (REVIEW.md F12)
**When** the enrollment reaches step 3, before the enrollment key is discarded
**Then** the Core derives `K_conf = HKDF(enrollment key, info = "vilicus/v1/hk/confirm-key/" || member_id)` and stores it wrapped under a key derived from the new member's DEK; at step 4, after unwrapping the enrollment key with HK, it writes next to the HK wrap the tag `HMAC(K_conf, "vilicus/v1/hk/confirm/" || member_id || hk_version || C(HK))`, `C(HK)` being an HKDF commitment to HK under its own label
**And** at the member's first unlock the Core opens the HPKE wrap, unwraps `K_conf` with the DEK and verifies the tag against `C(opened HK)` before HK is used; a mismatch is refused and alerted to every adult; once it verifies, the Core writes a commitment to HK and its version under a key derived from the member's DEK, erases `K_conf` and the tag, and at every later unlock refuses an opened HK that does not match the commitment, with an alert
**And** for the first member the commitment is written at once in the enrollment ceremony; HPKE stays in single-shot base mode (U10); a test in the shape of `spikes/hpke-review/tests/sender_substitution.rs` shows a disk writer that seals an HK' to the member and recomputes the permanent MAC under HK' refused at first receipt and at a later unlock.

**Decision tasks:**
- [ ] Settle how every remaining member confirms a new HK version after a rotation (PRD FR-9), which is a new first receipt that D121 does not cover (R55, T68): `doc/research-notes.md` section 4 holds it as **open**, to be decided before FR-9 code. Candidate: a signature by adults whose public keys are pinned under each member's DEK, as MLS does for GroupInfo (RFC 9420). FR-9 comes after V0.1, so this does not block this story; D119 already fixes that a rotation re-MACs every member under the new HK before any wrap under it and refuses pending enrollments made under the old version as stale.

**Dependencies:**
- Story 1.1 (the settled construction and encodings)
- Story 1.2 (sender substitution test, usage rule U10)
- Story 4.6 (household key and HPKE wrap)

**References:**
- `doc/architecture-spine.md` AD-36
- `doc/key-management.md` section 2 (construction, steps 1 to 5)
- `doc/decisions.md` D74, D119, D121
- `doc/threat-model.md` T23, T68
- `doc/architecture.md` section 20 (R55)
- `doc/prd.md` FR-7, FR-8
- `spikes/ad36-key-prototype/` (README byte layouts, `tests/`)
- `doc/qa/gates/1.1-key-prototype-ad36-public-key-authentication.yml` (AD36-2)
