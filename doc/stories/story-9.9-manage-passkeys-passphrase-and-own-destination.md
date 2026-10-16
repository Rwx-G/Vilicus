---
title: 'Manage passkeys, passphrase and own destination'
epic: 9
story: 9
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-10, FR-56, D71, D33, D106, FR-50]
---

# Story 9.9: Manage passkeys, passphrase and own destination

As a member,
I want to add or remove a passkey, change my passphrase and change my out-of-browser destination, each with a step-up bound to that one action,
So that I keep control of my authenticators and my alerts without opening a time window an attacker could reuse.

**Acceptance Criteria:**

**AC1 (FR-10, D71)**
**Given** a member in an authenticated session
**When** the member adds or removes a passkey
**Then** the Core creates the pending action first and accepts only a step-up assertion whose challenge derives from that action's canonical hash
**And** removing the last remaining passkey is refused

**AC2 (FR-10, D106)**
**Given** an unlocked member
**When** the member changes the passphrase with a step-up
**Then** the passphrase KEK wrapper is replaced, the new passphrase passes the strength check, and the old passphrase no longer unlocks
**And** a change declared as a suspected exposure offers a DEK rotation

**AC3 (FR-10, FR-56)**
**Given** a passkey added or removed or a passphrase changed
**When** the change completes
**Then** an out-of-browser alert is sent stating how many passkeys and paired devices the member now has, and the change is audited

**AC4 (FR-10, D33)**
**Given** any of these actions
**When** a TOTP code is offered in place of the step-up
**Then** it is refused

**AC5 (FR-56, FR-50)**
**Given** a member changing their own out-of-browser destination
**When** the member submits the new destination
**Then** a step-up bound to that change is required, then a test notification token sent to the new destination must be redeemed before it replaces the old one
**And** the old destination receives an alert that the destination changed

**Decision tasks:**
- [ ] Confirm the FR-50 level for changing one's own destination. Recommended: step-up then test notification token, as FR-50 states, because the destination is where recovery and veto alerts go. Gives up: a member must have a working passkey to fix a broken destination, which recovery covers.

**Dependencies:**
- Story 9.3 (unlock, for the passphrase change)
- Story 7.6 (action-bound step-up)
- Story 8.1 (notification stage and test notifications)

**References:**
- `doc/prd.md` FR-10, FR-50, FR-56
- `doc/key-management.md` section 3
- `doc/capability-matrix.md` section 1
- `doc/decisions.md` D33, D71, D106
