---
title: 'Rename the instance'
epic: 11
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-66, D51, D77, FR-56, FR-3]
---

# Story 11.3: Rename the instance

As an operator,
I want to change the instance name with `vilicus instance rename`,
So that the household can move to a new name without losing any data.

**Acceptance Criteria:**

**AC1 (FR-66, D51)**
**Given** an instance named `vilicus.example.com` with enrolled members
**When** root runs `vilicus instance rename vilicus.example.org` with a certificate valid for the new name
**Then** the Gateway serves the new name
**And** every existing passkey, bound to the old name, can no longer log in

**AC2 (FR-66, D77)**
**Given** a renamed instance
**When** a member runs `vilicus member reenroll` with their own passphrase and completes the browser flow
**Then** they enroll a passkey on the new name and unlock their partition with all data intact

**AC3 (FR-66)**
**Given** a renamed instance
**When** the instance admin redeems the admin recovery code with `vilicus admin recover`
**Then** a new admin passkey is enrolled on the new name

**AC4 (FR-66, FR-56, FR-3)**
**Given** a rename
**When** it completes
**Then** an audit entry records the old and new names
**And** every member is notified on the out-of-browser notification channel

**Dependencies:**
- Story 9.12 (re-enrollment)
- Story 8.5 (admin recovery code redemption)

**References:**
- `doc/prd.md` FR-66, FR-108, FR-5
- `doc/decisions.md` D51, D77
- `doc/capability-matrix.md` section 1 (rename the instance)
