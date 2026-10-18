---
title: 'First member enrollment in the wizard'
epic: 9
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-7, FR-15, FR-110, FR-56, D105, AD-36, UJ-1, D121, D135]
---

# Story 9.1: First member enrollment in the wizard

As a member,
I want to enroll as the first member right after the instance admin is created, with a passkey, a passphrase, a printed recovery secret and a confirmed out-of-browser destination,
So that my personal partition and the household partition exist from day one and I land unlocked in a paired browser.

**Acceptance Criteria:**

**AC1 (FR-7, FR-110)**
**Given** the wizard has created the instance admin on the instance name and offers the first member enrollment
**When** the person running the wizard enrolls a passkey and chooses a passphrase
**Then** the Core accepts the passphrase only if it passes the strength check with French and English dictionaries
**And** the enrollment accepts exactly one passkey; a second passkey is refused during enrollment and can only be added later with a step-up

**AC2 (FR-7, FR-110)**
**Given** a passkey and an accepted passphrase
**When** the Core generates the recovery secret
**Then** it is shown once as grouped characters with a checksum, and the member must re-type the groups the Core asks for before the enrollment can continue
**And** a wrong re-typed group blocks completion without revealing the secret again in a log or an API response

**AC3 (FR-7, FR-56, D105, D135)**
**Given** the member configures an out-of-browser destination
**When** the Core sends a test notification, whose push payload carries no token (D135)
**Then** the enrollment completes only after its receipt is confirmed by the check of Story 8.1 AC4 (open until settled there)
**And** an enrollment abandoned before redemption leaves no member account, no partition and no wrapper behind

**AC4 (FR-7, AD-36)**
**Given** the passkey, the confirmed recovery secret and a confirmed test notification
**When** the enrollment completes
**Then** the Core has generated the member DEK and key pair (no browser or Gateway supplies them), wrapped the DEK under the passphrase KEK and the recovery KEK, created the household key, wrapped it for this member, and authenticated the member public key by the first-member case of Story 4.7
**And** the Core has written at once the commitment to the household key and its version under a key derived from the member's DEK, which every later unlock checks (D121, Story 4.7 AC7)
**And** the member personal partition and the household partition are usable at once

**AC5 (FR-15, UJ-1)**
**Given** the enrollment completed in a browser
**When** the member lands on the home screen
**Then** that browser is a paired device holding a non-extractable device key, every request of the session is signed by it, and the member's keys are derived so the session is usable
**And** the enrollment, the pairing and the unlock each produce an audit entry, and the FR-56 alert for a completed enrollment states one passkey and one paired device

**Dependencies:**
- Story 8.4 (the wizard offers the first member enrollment after the instance admin exists)
- Story 4.5 (recovery secret format and recovery KEK)
- Story 4.7 (member public key authentication, first-member case)
- Story 7.7 (device key and signed requests)

**References:**
- `doc/prd.md` FR-7, FR-15, FR-56, FR-110, UJ-1
- `doc/key-management.md` section 3
- `doc/architecture-spine.md` AD-36, AD-52
- `doc/decisions.md` D74, D105, D121, D135
