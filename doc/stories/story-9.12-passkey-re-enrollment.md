---
title: 'Passkey re-enrollment'
epic: 9
story: 12
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-108, D77, D105, FR-3, FR-56, D135]
---

# Story 9.12: Passkey re-enrollment

As a member who lost every passkey but kept my passphrase,
I want to enroll a new passkey with a token printed by `vilicus member reenroll`,
So that I regain access without the waiting period of a recovery.

**Acceptance Criteria:**

**AC1 (FR-108, FR-3, D77)**
**Given** root at the host
**When** `vilicus member reenroll <member>` runs
**Then** it succeeds only with that member's own passphrase at the prompt and prints a token of 128 random bits, single use, valid 15 minutes
**And** another adult's passphrase is refused and every failure is audited

**AC2 (FR-108)**
**Given** a valid token
**When** the member opens it in a browser and types their passphrase
**Then** the member enrolls a new passkey and that browser becomes a paired device

**AC3 (FR-108, D105, D135)**
**Given** the new passkey
**When** the member tries to complete the re-enrollment
**Then** it completes only after a test notification sent to their out-of-browser destination is confirmed by the receipt check of Story 8.1 AC4 (the push payload carries no token, D135)

**AC4 (FR-108)**
**Given** the completion screen
**When** the re-enrollment completes
**Then** the member unlock window ends and every other passkey, paired device and web session of that member is revoked, except those the member explicitly kept on that screen

**AC5 (FR-108, FR-56)**
**Given** a completed re-enrollment
**When** the alerts are sent
**Then** the member is notified on every remaining paired device and on the out-of-browser notification channel, and the alert lists what was revoked

**AC6 (FR-108)**
**Given** the instance admin
**When** they try `vilicus member reenroll` for the admin role
**Then** it is refused; the instance admin re-enrolls with the admin recovery code (FR-5)

**Dependencies:**
- Story 9.9 (passkey management and destination)

**References:**
- `doc/prd.md` FR-3, FR-56, FR-108
- `doc/key-management.md` section 3
- `doc/capability-matrix.md` section 1
- `doc/decisions.md` D77, D105, D135
