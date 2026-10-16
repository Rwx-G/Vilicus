---
title: 'HPKE internal review and cross-test'
epic: 1
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [D61, D107, AD-18, DC-40, DC-62, R33, D28]
---

# Story 1.2: HPKE internal review and cross-test

As the owner,
I want the `hpke` crate reviewed internally and cross-tested against an independent implementation before the household key is wrapped with it,
So that the one recorded exception to the audited-libraries rule (D28) reaches the done state of D107 before FR-8 code.

**Acceptance Criteria:**

**AC1 (D61, D107, AD-18)**
**Given** the `hpke` crate in base mode with DHKEM(X25519, HKDF-SHA256) and AES-256-GCM
**When** the RFC 9180 test vectors for that suite run in a CI job of the spike package `spikes/hpke-cross-test/`
**Then** every vector passes

**AC2 (D61, D107, DC-62)**
**Given** the independent implementation named in the decision task below, used as a dev-dependency only
**When** the cross-test seals with one implementation and opens with the other, in both directions, on 10 000 random cases (keys, info, associated data and plaintext lengths)
**Then** every case agrees, and the job runs in CI on every change to the spike package

**AC3 (D61, AD-18, R33, D28)**
**Given** the crate source at the pinned version and Vilicus's intended use of it (household key wrap, backup key sealing, inbox sealing later)
**When** the internal security review is done, assisted by the most capable model available (AD-18)
**Then** a written review is committed with every finding closed or accepted
**And** neither the review nor any other document calls the crate audited

**AC4 (D107, DC-40)**
**Given** the review finds a defect
**When** the defect cannot be fixed upstream and pinned within the timebox
**Then** the fallback is recorded in `doc/decisions.md`: V0.1 exits with UJ-2 limited to the first member and FR-8 ships in V0.1.x

**Spike plan:**
- Question: does the `hpke` crate agree with RFC 9180 and an independent implementation, and does an internal review find no open defect (D61)?
- Method: RFC 9180 vectors, a 10 000-case two-way cross-test in CI, a written review of the crate and of Vilicus's use of it.
- Pass criterion: the D107 done state: vectors pass, the cross-test agrees on 10 000 random cases in CI, the review is committed with every finding closed or accepted.
- Timebox: 8 working days.
- Fallback on failure: a defect is fixed upstream and the fix pinned; failing that, V0.1 exits with UJ-2 limited to the first member and FR-8 ships in V0.1.x (D107).
- Result record: the review file, the open question of `doc/research-notes.md` section 4 on the independent implementation closed with a link to the CI run, a decision record if the fallback is taken.

**Decision tasks:**
- [ ] Decide which independent HPKE implementation the cross-test uses, before the review starts. Recommended: `hpke-rs` with its RustCrypto provider, as a dev-dependency only. Gives up: a second Rust implementation shares the language and ecosystem, so a C implementation would be more independent but costs FFI in the test harness.
- [ ] Decide where the written review is committed. Recommended: `doc/reviews/hpke-review.md`. Gives up: nothing material; the path only needs to be stable for later links.

**Dependencies:**
- None. Runs together with Story 1.1, first in the V0.1 spike order.

**References:**
- `doc/decisions.md` D28, D61, D107
- `doc/architecture-spine.md` AD-18, Deferred section
- `doc/prd.md` section 6.1, section 9 (HPKE review and cross-test), DC-40, DC-62
- `doc/research-notes.md` section 3 and section 4
- `doc/architecture.md` section 16, section 20 (R33)
