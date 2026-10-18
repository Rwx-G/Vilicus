---
title: 'Instance admin passkey, destination and backup secret'
epic: 8
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-4, FR-5, FR-53, FR-56, AD-52, D76, D101, D105, UJ-1, FR-50, D128, D135]
---

# Story 8.4: Instance admin passkey, destination and backup secret

As an operator,
I want to create the instance admin on the instance name, confirm its alert destination and receive the backup secret and admin recovery code,
So that the instance has an administrator, a way to be alerted, and backups that can later be restored.

**Acceptance Criteria:**

**AC1 (FR-4, AD-52, UJ-1)**
**Given** the instance name and certificate are set
**When** the operator creates the instance admin's passkey on the instance name
**Then** the passkey is registered and every remaining step runs on admin-authenticated setup routes

**AC2 (FR-4, D76)**
**Given** the instance admin's passkey exists
**When** any wizard route is requested, including after a restart of the Core
**Then** it returns not found

**AC3 (FR-56, D105, D135)**
**Given** the admin is authenticated on a setup route
**When** the admin configures an out-of-browser destination
**Then** the step completes only after a test notification sent to it is confirmed by the receipt check of Story 8.1 AC4 (open until settled there; the push payload carries no token, D135)

**AC4 (FR-53, AD-52)**
**Given** the destination is confirmed
**When** the backup secret step runs
**Then** the Core generates a secret of at least 128 bits (Story 4.8) and shows it once, never letting it be chosen, and stores only the backup public key

**AC5 (FR-5, D101)**
**Given** bootstrap reaches the admin recovery code
**When** the code is generated
**Then** it is printed on the host console only, never sent to the browser, and stored only as an Argon2id hash, computed through the one Argon2id limiter of Story 4.4 AC6 (D128)

**AC6 (FR-4, UJ-1)**
**Given** every admin step is done
**When** the setup finishes
**Then** the wizard offers the first member enrollment, and each step is audited

**AC7 (FR-56, FR-50)**
**Given** an instance admin after bootstrap
**When** they change their out-of-browser destination in the instance admin web
**Then** a step-up bound to that change is required, then a test notification sent to the new destination must be confirmed by the receipt check of Story 8.1 AC4 before it replaces the old one (D135)

**Dependencies:**
- Story 8.3 (instance name and certificate)
- Story 7.6 (passkey registration)
- Story 4.8 (backup key pair)

**References:**
- `doc/prd.md` FR-4, FR-5, FR-53, FR-56, UJ-1
- `doc/architecture-spine.md` AD-31, AD-52
- `doc/architecture.md` section 7.1
- `doc/decisions.md` D76, D101, D105, D106, D128, D135
