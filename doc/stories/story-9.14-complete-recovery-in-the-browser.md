---
title: 'Complete recovery in the browser'
epic: 9
story: 14
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-14, D106, D39, FR-56, FR-110]
---

# Story 9.14: Complete recovery in the browser

As a member at the end of my recovery waiting period,
I want to finish recovery in the browser with an enrollment token and my recovery secret,
So that I get a new passphrase, passkey and recovery secret, and older wrappers open nothing I write afterwards.

**Acceptance Criteria:**

**AC1 (FR-14, D39)**
**Given** a recovery whose waiting period ended without a cancel
**When** root runs `vilicus member recover` for that member again
**Then** the CLI prints an enrollment token of 128 random bits, single use, valid 15 minutes, and a token is never printed before the period ends

**AC2 (FR-14, FR-110)**
**Given** the token and the recovery secret in the browser
**When** the member completes the flow
**Then** the member sets a new strength-checked passphrase, enrolls a passkey, redeems a test notification, and receives a new recovery secret shown once and partially re-typed
**And** the old recovery secret no longer works

**AC3 (FR-14, D106)**
**Given** a completed recovery
**When** the Core finalizes it
**Then** the member DEK is rotated, so a wrapper of the old DEK left in an older backup opens no data written after the recovery

**AC4 (FR-14)**
**Given** the completion screen
**When** the recovery completes
**Then** the member unlock window ends and every other passkey, paired device and web session of that member is revoked, except those the member explicitly kept on that screen

**AC5 (FR-14, FR-56)**
**Given** a completed recovery
**When** the alerts are sent
**Then** the member and every adult receive an out-of-browser alert listing what was revoked and the new passkey and device counts, and completion is audited

**Dependencies:**
- Story 9.13 (recovery start and waiting period)

**References:**
- `doc/prd.md` FR-14, FR-56, FR-110
- `doc/key-management.md` sections 6 and 8
- `doc/decisions.md` D39, D106
