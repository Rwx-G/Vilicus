---
title: 'Member public key authentication (AD-36)'
epic: 4
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-36, D74, DC-40, FR-7, FR-8, T23]
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

**Dependencies:**
- Story 1.1 (the settled construction and encodings)
- Story 4.6 (household key and HPKE wrap)

**References:**
- `doc/architecture-spine.md` AD-36
- `doc/key-management.md` section 2 (construction, steps 1 to 5)
- `doc/decisions.md` D74
- `doc/threat-model.md` T23
- `doc/prd.md` FR-7, FR-8
