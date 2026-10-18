---
title: 'Admin recovery code redemption'
epic: 8
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-5, D101, AD-52, D5, D128]
---

# Story 8.5: Admin recovery code redemption

As an operator,
I want to regain admin control with the admin recovery code at the host,
So that a lost admin passkey or a rename never locks the instance, without the code ever giving access to member data.

**Acceptance Criteria:**

**AC1 (FR-5, D101)**
**Given** an existing instance
**When** root runs `vilicus admin recover` and types the code at the prompt
**Then** the Core checks it against the stored Argon2id hash and prints a one-time admin enrollment token of 128 random bits, single use, valid 15 minutes
**And** the Argon2id check runs through the one limiter of Story 4.4 AC6, which D128 names the admin recovery code in, so a burst of redemption attempts waits or is refused as retryable after 4 seconds instead of starting more derivations

**AC2 (FR-5)**
**Given** a valid admin enrollment token
**When** it is used in the browser on the instance name
**Then** a new admin passkey is enrolled and the previous admin credential is invalidated

**AC3 (FR-5, D101, AD-52)**
**Given** the web routes
**When** any route is offered the admin recovery code
**Then** none accepts it

**AC4 (FR-5, D5)**
**Given** a redeemed admin recovery code
**When** the new admin session queries member or household data
**Then** no member or household data becomes readable

**AC5 (FR-5)**
**Given** a redemption, successful or failed
**When** it completes
**Then** every adult is notified on the out-of-browser channel on success, and failures are rate limited and audited

**Dependencies:**
- Story 8.4 (admin recovery code generated and hashed)

**References:**
- `doc/prd.md` FR-5
- `doc/architecture-spine.md` AD-52
- `doc/capability-matrix.md` section 1
- `doc/decisions.md` D5, D101, D128
