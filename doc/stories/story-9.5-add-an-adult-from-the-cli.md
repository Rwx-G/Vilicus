---
title: 'Add an adult from the CLI'
epic: 9
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-8, FR-3, AD-36, D34, D74, FR-56, UJ-2]
---

# Story 9.5: Add an adult from the CLI

As an adult,
I want to authorize a new adult with `vilicus member add` and my passphrase,
So that the new adult enrolls with a personal partition of their own from the first day.

**Acceptance Criteria:**

**AC1 (FR-8, FR-3, UJ-2)**
**Given** root at the host
**When** `vilicus member add` runs without a valid passphrase of an existing adult member
**Then** it fails, prints no token, and the failed attempt is audited

**AC2 (FR-8, AD-36, D74)**
**Given** a valid passphrase of an existing adult
**When** the command runs
**Then** it prints an enrollment token of 128 random bits, single use, valid 15 minutes
**And** the Core derives from the token the member authentication key and wraps it under a key derived from the authorizing adult household key, per Story 4.7

**AC3 (FR-8, D74)**
**Given** a valid enrollment token
**When** the new adult opens the enrollment page and enrolls a passkey, a strength-checked passphrase, a re-typed recovery secret and a destination confirmed by a redeemed test notification
**Then** the Core generates the new member DEK and key pair, MACs the new public key under the authentication key, and the new personal partition is usable at once
**And** no browser or Gateway input can replace the public key that the Core generated

**AC4 (FR-8, FR-56)**
**Given** a completed enrollment of a new adult
**When** it completes
**Then** every other adult is notified in the primary channel and on the out-of-browser notification channel, and the addition is recorded as pending with its start time
**And** the new member does not yet hold a household key wrapper

**AC5 (FR-8, D34)**
**Given** the instance admin credentials alone
**When** they are used at any step of the flow (command, token, enrollment)
**Then** no step completes without an adult passphrase or the new member own enrollment

**Dependencies:**
- Story 9.1 (an existing adult member)
- Story 4.7 (member public key authentication)

**References:**
- `doc/prd.md` FR-8, FR-3, UJ-2
- `doc/key-management.md` sections 3 and 5
- `doc/architecture-spine.md` AD-36
- `doc/decisions.md` D34, D74
