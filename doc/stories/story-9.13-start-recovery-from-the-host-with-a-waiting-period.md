---
title: 'Start recovery from the host with a waiting period'
epic: 9
story: 13
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-14, D39, D75, AD-30, FR-56]
---

# Story 9.13: Start recovery from the host with a waiting period

As a member who lost my passkeys and my passphrase,
I want to start a recovery with my printed recovery secret on the host, followed by a waiting period with alerts,
So that I get my partition back while a thief of my secret is slowed down and seen by every adult.

**Acceptance Criteria:**

**AC1 (FR-14, D39)**
**Given** root at the host
**When** `vilicus member recover <member>` runs and the recovery secret is typed at the prompt
**Then** a correct secret starts the recovery and a wrong one is refused, rate limited and audited
**And** no web route can start a recovery

**AC2 (FR-14, AD-30)**
**Given** a started recovery
**When** the waiting period begins
**Then** it is a durable deadline of 48 hours (PRD assumption) that runs on to a cap of 7 days (PRD assumption) until the member redeems an acknowledgement token, and runs to its cap while an adult has had no working destination for 24 hours

**AC3 (FR-14, FR-56, D75)**
**Given** a started recovery
**When** the alerts are sent
**Then** the member and every other adult receive a content-free alert on the out-of-browser notification channel and in the primary channel, and the host journal records it
**And** each alert carries a one-time acknowledgement token of 128 random bits, single use, redeemed at the Core with rate limiting

**AC4 (FR-14, D75)**
**Given** a pending recovery without a redeemed token
**When** each day passes
**Then** every adult receives a reminder
**And** an acknowledgement by another adult never shortens the wait

**AC5 (FR-14, FR-50)**
**Given** a pending recovery
**When** the member cancels from any authenticated session of the member web
**Then** the recovery stops, every adult is notified and the cancel is audited, including while the audit writer is down (emergency set)

**Decision tasks:**
- [x] Settled by FR-50: the member concerned cancels a pending recovery in the member web with an authenticated session.

**Dependencies:**
- Story 9.12 (re-enrollment flow and revocation machinery)
- Story 4.5 (recovery secret and recovery KEK)

**References:**
- `doc/prd.md` FR-14, FR-50, FR-56
- `doc/key-management.md` section 6
- `doc/architecture-spine.md` AD-30, AD-32
- `doc/decisions.md` D39, D75, D105
