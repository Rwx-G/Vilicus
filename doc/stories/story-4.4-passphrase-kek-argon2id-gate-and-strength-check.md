---
title: 'Passphrase KEK, Argon2id gate and strength check'
epic: 4
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-11, FR-7, FR-110, E12, AD-9, AD-18, D128, D129, D131, DC-80]
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

**AC5 (D128, FR-11, E12)**
**Given** a version 1 passphrase wrapper
**When** it is written
**Then** it uses Argon2id version 0x13, t = 3, p = 4, m = 384 MiB, a 16-byte random salt and a 32-byte KEK, over the passphrase normalised to NFC and encoded as UTF-8, as named constants in `vilicus-types`; m is provisional until the reference-host run of E12 replaces it
**And** a header is refused before it is queued when its cost is below the floor (at least one RFC 9106 section 4 option in both memory and passes, so m >= 64 MiB and t >= 3 below 2 GiB) or above the ceiling (m 1 GiB, m times t 4 GiB, p 8), as the test `unlock_refuses_a_bad_header_before_queuing` of Story 1.8 does while the only slot is held
**And** a wrapper written with an older cost is unlocked with its header's cost and rewritten with the current one at that unlock, which then costs two derivations.

**AC6 (D128, AD-9, DC-80)**
**Given** every Argon2id derivation of the Core (passphrase, backup secret, admin recovery code)
**When** it is requested
**Then** it goes through one limiter: at most two derivations at once, through a FIFO tokio `Semaphore` acquired before the blocking-pool permit so no async worker thread blocks; a request that cannot start within 4 seconds is refused as retryable and the time it waited is never returned to the client; one request in flight per member; after a failed passphrase the member's next attempt is delayed with an exponential backoff
**And** the Argon2id working memory never exceeds the limit times m, at most 1 GiB, checked at compile time over the constants and the ceiling (test with a burst of more simultaneous requests than the limit: arrival order kept, refusals after 4 seconds, peak memory bounded).

**AC7 (D128, D129, D131)**
**Given** the `argon2` crate
**When** a derivation runs
**Then** it is `argon2` `=0.6.0` without its `parallel` feature, so `rayon` is not in the Core's tree (a dependency check fails if it appears): the four lanes run in order on one blocking-pool thread, under the key-operation guard of Story 4.2 AC8
**And** it derives with `hash_password_into_with_memory` into a buffer the Core owns and wipes after each derivation, on success and on error, because `hash_password_into` frees its blocks without wiping them (Story 1.8, "Memory wipe"); a test checks the buffer is all zeros afterwards.

**AC8 (D129, D28)**
**Given** the exception to D28 for `argon2` and `blake2`
**When** the passphrase-wrapping code is written
**Then** an internal security review of both crates and of Vilicus's use of them, assisted by the most capable model available, is committed first, with every finding closed or accepted
**And** CI runs the RFC 9106 Argon2id vectors, the reference implementation's Argon2id vectors without secret or associated data ("password", "somesalt", m = 64 MiB, t = 2, p = 1), a cross-test against the reference implementation phc-winner-argon2, a dev-dependency only, that agrees on 10 000 random cases over p in {1, 2, 4, 8}, and OpenSSL 3.5's `EVP_KDF-ARGON2` as a second oracle; no document calls the crate audited (gate E12-3).

**AC9 (E12, D128)**
**Given** the reference host
**When** E12 runs there with the adopted model, by the procedure of Story 1.8 (Result, "Not run here"): `E12_HOST=reference bash spikes/argon2id-params/run.sh`, idle, in the same session as E32 (Story 5.1 AC7)
**Then** m is picked from {256, 384, 512} MiB under the serial, limit-2 model with the limit times m at most 1 GiB, and the picked value replaces the provisional constant (gates E12-1, E12-2)
**And** the constant is not changed on the strength of a VM or emulation run (gate E12-5).

**Decision tasks:**
- [ ] Decide the passphrase strength library (approved by D113). Recommended: the `zxcvbn` crate, run in the Core with an added French dictionary; verify first that the crate accepts additional dictionaries, and if it cannot, stop and report before choosing another library. Gives up: a JavaScript estimator would give feedback in the browser, but the passphrase reaches the Core anyway and one check in one place is simpler.

**Dependencies:**
- Story 4.3 (wrappers and key hierarchy)
- Story 4.2 (key-operation guard and wiped memory)
- Story 1.8 (E12 emulated result; D128, D129)

**References:**
- `doc/prd.md` FR-7, FR-11, FR-110, DC-80
- `doc/architecture-spine.md` AD-9, AD-18, Stack (argon2)
- `doc/key-management.md` sections 3 and 4
- `doc/research-notes.md` E12
- `doc/decisions.md` D113, D128, D129, D131
- `spikes/argon2id-params/` (`src/guidance.rs` floor and ceiling, `tests/spike.rs`)
- `doc/qa/gates/1.8-e12-argon2id-parameters-on-the-reference-host.yml` (E12-1 to E12-5)
