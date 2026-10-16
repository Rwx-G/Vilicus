---
title: 'Manual device run and release notes'
epic: 14
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-109, FR-60, FR-112]
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

**Dependencies:**
- Story 14.3 (automated journeys)

**References:**
- `doc/prd.md` FR-60, FR-109, FR-112
- `doc/decisions.md` D102, D107 (supported browsers)
