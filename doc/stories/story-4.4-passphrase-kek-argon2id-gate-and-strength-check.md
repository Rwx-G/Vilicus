---
title: 'Passphrase KEK, Argon2id gate and strength check'
epic: 4
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-11, FR-7, FR-110, E12, AD-9, AD-18]
---

# Story 4.4: Passphrase KEK, Argon2id gate and strength check

As a member,
I want my passphrase to unwrap my data key through Argon2id only after I have proven my first factor, and to be refused when it is weak,
So that unlock is costly to guess offline and cannot be used to exhaust the host.

**Acceptance Criteria:**

**AC1 (FR-11, AD-18, E12)**
**Given** a member's passphrase
**When** the passphrase KEK is derived
**Then** Argon2id runs with the parameters set by E12, and those parameters are stored in the wrapper header
**And** a wrapper whose header parameters fall below the memory floor recorded by E12 is refused

**AC2 (FR-11, AD-9)**
**Given** an unlock request
**When** no successful first factor (passkey login, or the host CLI path) is attached to it
**Then** Argon2id is never started
**And** derivations run on the Core's bounded blocking pool under a global concurrency limit, so a burst of requests beyond the limit waits or fails with a retryable error instead of starting more derivations (test with more concurrent requests than the limit)

**AC3 (FR-11, E12)**
**Given** the reference host (4 cores, 8 GB RAM, SSD, no GPU, Debian 13 amd64)
**When** a single unlock runs with the E12 parameters
**Then** key derivation completes within the 2-second unlock target (PRD assumption), measured by a benchmark kept in the repository
**And** if E12 took its fallback, the lower concurrency limit and the longer unlock it recorded are the named constants, with the memory floor unchanged

**AC4 (FR-7, FR-110)**
**Given** a candidate passphrase at enrollment or at a passphrase change
**When** the Core checks its strength
**Then** the check uses French and English dictionaries and refuses a passphrase below the threshold with a message key, in the Core, never only in the browser
**And** the candidate passphrase is never logged or stored outside the derivation

**Decision tasks:**
- [ ] Decide the passphrase strength library (approved by D113). Recommended: the `zxcvbn` crate, run in the Core with an added French dictionary; verify first that the crate accepts additional dictionaries, and if it cannot, stop and report before choosing another library. Gives up: a JavaScript estimator would give feedback in the browser, but the passphrase reaches the Core anyway and one check in one place is simpler.

**Dependencies:**
- Story 4.3 (wrappers and key hierarchy)
- Story 1.8 (E12 parameters)

**References:**
- `doc/prd.md` FR-7, FR-11, FR-110
- `doc/architecture-spine.md` AD-9, AD-18
- `doc/key-management.md` sections 3 and 4
- `doc/research-notes.md` E12
- `doc/decisions.md` D113
