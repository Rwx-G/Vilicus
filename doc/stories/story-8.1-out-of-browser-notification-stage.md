---
title: 'Out-of-browser notification stage'
epic: 8
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-56, AD-32, D47, D75, D105, I11, FR-110, NFR-2, UX-DR4, E13, D118, D135, DC-81]
---

# Story 8.1: Out-of-browser notification stage

As an adult,
I want security alerts pushed to a destination that does not depend on an open browser, without content,
So that I learn of recoveries, additions and new ways in even when the app is closed, and the push server learns only a generic text and the delivery timing (D118, D135).

**Acceptance Criteria:**

**AC1 (FR-56, AD-32, NFR-2)**
**Given** a member or instance admin destination on an ntfy-style push server
**When** the Core sends an alert through the egress proxy
**Then** the payload names no alert kind and carries one generic text per severity from a static template, with no title, sender, amount or model text
**And** a topic on a public server uses an access token or a random name of at least 128 bits
**And** on any server the payload is that generic text plus an opaque reference that redeems nothing, and never carries a one-time token, because an ntfy-type server stores and serves the body without end-to-end encryption and the ntfy Android app also writes it to logcat and its database (D135; Story 1.13, findings 5 and 6); payload encryption (RFC 8291) waits until a Vilicus app is the UnifiedPush receiver

**AC2 (AD-32, FR-110)**
**Given** the Core alert queue holding alerts raised earlier
**When** the stage runs
**Then** it delivers each alert to its recipients from static French and English templates parameterized only by Core-resolved values
**And** each alert is also listed in the member web with its kind when the member opens it

**AC3 (D75, AD-32, D135)**
**Given** an alert with its one-time acknowledgement token of 128 random bits
**When** the member opens the alert in a signed-in Vilicus client on a device they control
**Then** the token is shown and redeemed there, never in the push payload; the Core redeems it once, a second redemption is refused and redemption attempts are rate limited, so acknowledging an alert needs a signed-in Vilicus client (D135)

**AC4 (D105, FR-56, D135)**
**Given** a destination to confirm
**When** the Core sends a test notification and its receipt is confirmed by the check the decision task below settles
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
**And** the waits of FR-8 and FR-14 are marked to run to their maximum until a destination is confirmed again by the test notification flow of AC4

**AC8 (FR-56)**
**Given** an alert of one of the kinds of FR-56 that add a way in or widen access
**When** it is shown in a Vilicus client
**Then** it states how many passkeys and paired devices the member now has

**AC9 (D135, E13)**
**Given** a push server destination
**When** a test of the stage reads back every message the server stored for the topic (as `push-delivery audit-cache` of `spikes/push-delivery/` does)
**Then** every stored message is exactly the generic text and one opaque reference, with no field beyond id, times, event, topic and body, and the count matches the alerts published
**And** the publish request sets no title, tags, priority, click URL, icon, actions or attachment (Story 1.13, "Payload and acknowledgement").

**Decision tasks:**
- [ ] Settle how the test notification of D105 proves receipt now that the push payload carries no token (D135): `doc/research-notes.md` section 4 holds it as **open**, to be settled before this story is built; the candidate it names is confirming the payload's opaque reference in the member's signed-in client, which alone acknowledges nothing (gate E13-2). AC4 and every enrollment, re-enrollment, recovery and destination-change story that requires a confirmed test notification (8.4, 9.1, 9.2, 9.5, 9.9, 9.12, 9.14) use the check settled here.

**Dependencies:**
- Story 5.2 (Core alert queue)
- Story 5.5 (egress proxy)
- Story 6.2 (audit append path)
- Story 7.4 (catalogs)
- Story 7.7 (signed requests for the member web)
- Story 1.13 (E13 tooling and D135; its 7-day household measurement, still to run, decides AC5's fallback, gate E13-1)

**References:**
- `doc/prd.md` FR-56, FR-110, DC-81
- `doc/architecture-spine.md` AD-32
- `doc/architecture.md` section 13.4
- `doc/capability-matrix.md` section 11
- `doc/ai-safety.md` I11
- `doc/decisions.md` D47, D75, D105, D118, D135
- `doc/research-notes.md` E13, section 4
- `spikes/push-delivery/` (`RUNBOOK.md`, `android/README.md`)
- `doc/qa/gates/1.13-e13-push-delivery-reliability.yml` (E13-1 to E13-4)
