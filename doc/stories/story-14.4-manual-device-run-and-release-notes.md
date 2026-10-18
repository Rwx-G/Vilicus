---
title: 'Manual device run and release notes'
epic: 14
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-109, FR-60, FR-112, E2, E3, E22, E24, E26]
---

# Story 14.4: Manual device run and release notes

As the project maintainer,
I want UJ-1 to UJ-3 run by hand once per release on real devices, with the result in the release notes,
So that what the virtual authenticator cannot show is checked before a household relies on it.

**Acceptance Criteria:**

**AC1 (FR-109)**
**Given** a release candidate that passed the automated journeys
**When** the maintainer runs UJ-1, UJ-2 and UJ-3 by hand on one Android phone and one desktop browser from the supported list
**Then** each journey step is checked against a written checklist kept with the release procedure

**AC2 (FR-109, FR-112)**
**Given** the manual run is complete
**When** the release notes are written
**Then** they record the result per journey, the browser family and version, and nothing else about the devices: no device model, no personal detail, no host name, no address

**AC3 (FR-60)**
**Given** the release notes
**When** they are published
**Then** they also list the actions removed by FR-60 (moving data from a personal partition to the household partition, promotion through the web, purge)

**AC4 (FR-109)**
**Given** a manual journey fails
**When** the maintainer records the result
**Then** the release is not published until a fix passes both the automated and the manual run

**AC5 (E22, E24, E2, E26, E3, D107, D117)**
**Given** the first V0.1 release candidate, while E22, E24, the E2 login half and E26 have passed on desktop only and E3 has no Apple or Android row (`doc/qa/epic-1-report.md` section 11)
**When** the manual device session runs on one Android phone (Chrome and Firefox, current and previous) and, best effort, Safari on macOS or iOS, with real authenticators and, for E24, a real DNS-01 certificate from a public CA (gate E24-4)
**Then** it follows the manual procedures the spikes recorded: Story 1.3 (Implementation Notes, "Manual procedure for Android"), Story 1.4 (Result, "Not run here", steps 1 to 6, including a second passkey for the same user and a login naming both, on Firefox with a real authenticator), Story 1.5 ("Manual procedure for the devices not run here"), Story 1.14 (Implementation Notes, "Not run here") and Story 1.16 ("Manual procedure for the clients not run here")
**And** each outcome is recorded in the matching experiment entry of `doc/research-notes.md` without device model, real name or address; a part that fails applies its fallback (D107 for E22, D117 for the E2 login half, removal of the option for E24, sanitized plain text for E26) as a decision before the release, and E3 changes only the README wording (gates E22-1, E24-1, E24-2, E2L-1, E26-1, E3-1).

**Dependencies:**
- Story 14.3 (automated journeys)

**References:**
- `doc/prd.md` FR-60, FR-109, FR-112
- `doc/decisions.md` D102, D107 (supported browsers), D117, D122, D124, D138, D139
- `doc/research-notes.md` E2, E3, E22, E24, E26
- `doc/qa/epic-1-report.md` section 14, recommendation 3
