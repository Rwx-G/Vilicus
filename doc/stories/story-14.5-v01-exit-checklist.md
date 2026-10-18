---
title: 'V0.1 exit checklist'
epic: 14
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-61, FR-53, FR-109, D107, D117, E3, FR-32, D119, D120, D134]
---

# Story 14.5: V0.1 exit checklist

As the owner,
I want a checklist that verifies every PRD section 6.1 exit criterion with evidence,
So that V0.1 ships only when it meets what was decided, or under its documented fallback.

**Acceptance Criteria:**

**AC1 (FR-109)**
**Given** the release candidate
**When** the checklist is filled
**Then** it links the automated and manual runs showing UJ-1 and UJ-3 working on a clean Debian 13 system and UJ-2 completing with its delay, public key check and household key wrap at the next unlock

**AC2 (D107, D117)**
**Given** the key prototype (Story 1.1) and the HPKE gate (Story 1.2)
**When** the checklist is filled
**Then** it shows the AD-36 construction settled and the HPKE gate done (vectors, 10 000-case cross-test, committed review) before the first FR-8 commit, with commit references
**And** if the HPKE gate could not be closed, or the AD-36 construction did not hold, it records that V0.1 exits under the fallback of D107 or D117, with UJ-2 limited to the first member and FR-8 moved to V0.1.x

**AC3 (FR-61, FR-53)**
**Given** the release job
**When** the checklist is filled
**Then** it links a run where every FR-61 gate passes and the CI restore drill passes

**AC4 (FR-61)**
**Given** the gating spikes of Epic 1
**When** the checklist is filled
**Then** each has its result recorded in `doc/research-notes.md`, or its fallback recorded as a decision in `doc/decisions.md`

**AC5 (E3, FR-32)**
**Given** the README
**When** the checklist is filled
**Then** the transport wording matches the E3 result within D27, and the audit claim reads as FR-32 states: tampering detected against an attacker without root, and against root only when a remote sink is configured

**AC6 (FR-61, D119, D120, D134)**
**Given** the Epic 1 gates left open at the end of that epic (`doc/qa/epic-1-report.md` sections 11 and 15)
**When** the checklist is filled
**Then** it links, for each, the evidence that closes it or the decision that records its fallback: the 7-day E13 measurement on the household's phones (Story 1.13, gate E13-1); E12, E16 and E32 on the reference host, in one session for E12 and E32 (Stories 4.4 AC9, 4.2 AC5 and 5.1 AC7), and E10's `checks.sh` rerun there (gate E10-1); the device session of Story 14.4 AC5 for E22, E24 (two passkeys on Firefox included), the E2 login half and E26; the first green run of the HPKE CI job (Story 2.2 AC6) and the owner's approval of `spikes/hpke-review/REVIEW.md` (Story 4.6) before the first FR-8 commit
**And** it states that gate 1.12 stays FAIL against E14's own criterion with Host-header fronting accepted as R54 (D134), and that the AD-36 construction (D119) and the HPKE gate (D120) are the records AC2 cites.

**Dependencies:**
- Story 14.4 (manual run and release notes)

**References:**
- `doc/prd.md` section 6.1, section 9, FR-32, FR-53, FR-61, FR-109
- `doc/research-notes.md` section 3
- `doc/decisions.md` D27, D61, D74, D107, D117, D119, D120, D134
- `doc/qa/epic-1-report.md`, `doc/qa/gates/1.*.yml`
