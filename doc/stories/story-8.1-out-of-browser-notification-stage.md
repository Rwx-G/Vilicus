---
title: 'Out-of-browser notification stage'
epic: 8
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-56, AD-32, D47, D75, D105, I11, FR-110, NFR-2, UX-DR4, E13]
---

# Story 8.1: Out-of-browser notification stage

As an adult,
I want security alerts pushed to a destination that does not depend on an open browser, without content,
So that I learn of recoveries, additions and new ways in even when the app is closed, and the push server learns nothing.

**Acceptance Criteria:**

**AC1 (FR-56, AD-32, NFR-2)**
**Given** a member or instance admin destination on an ntfy-style push server
**When** the Core sends an alert through the egress proxy
**Then** the payload names no alert kind and carries one generic text per severity from a static template, with no title, sender, amount or model text
**And** a topic on a public server uses an access token or a random name of at least 128 bits

**AC2 (AD-32, FR-110)**
**Given** the Core alert queue holding alerts raised earlier
**When** the stage runs
**Then** it delivers each alert to its recipients from static French and English templates parameterized only by Core-resolved values
**And** each alert is also listed in the member web with its kind when the member opens it

**AC3 (D75, AD-32)**
**Given** an alert with its one-time acknowledgement token of 128 random bits
**When** the member opens the action link on a device they control
**Then** the Core redeems the token once; a second redemption is refused and redemption attempts are rate limited

**AC4 (D105, FR-56)**
**Given** a destination to confirm
**When** the Core sends a test notification and the member redeems its token
**Then** the destination is recorded as working, and this flow is callable by enrollment, re-enrollment and bootstrap

**AC5 (FR-56, E13)**
**Given** a delivery failure
**When** the push server is unreachable or rejects the call
**Then** the failure is stored and shown in the primary channel and made available to `vilicus status`
**And** if E13 took its fallback, each destination can hold a second push distributor within the same webhook transport, tried when the first fails; polling is never the only path

**AC6 (I11)**
**Given** the cap of 10 system notifications per member per hour
**When** it is exceeded
**Then** an instance admin alert is raised and an audit entry is written

**AC7 (D105, UX-DR4)**
**Given** an adult who has had no working destination for 24 hours
**When** any page loads
**Then** a blocking banner is shown
**And** the waits of FR-8 and FR-14 are marked to run to their maximum until a destination is confirmed again by a redeemed test token

**AC8 (FR-56)**
**Given** an alert of one of the kinds of FR-56 that add a way in or widen access
**When** it is shown in a Vilicus client
**Then** it states how many passkeys and paired devices the member now has

**Dependencies:**
- Story 5.2 (Core alert queue)
- Story 5.5 (egress proxy)
- Story 6.2 (audit append path)
- Story 7.4 (catalogs)
- Story 7.7 (signed requests for the member web)
- Story 1.13 (E13 result)

**References:**
- `doc/prd.md` FR-56, FR-110
- `doc/architecture-spine.md` AD-32
- `doc/capability-matrix.md` section 11
- `doc/ai-safety.md` I11
- `doc/decisions.md` D47, D75, D105
