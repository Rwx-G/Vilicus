---
title: 'Backup target configuration'
epic: 12
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-53, FR-3, FR-8, FR-50, FR-56, D106, DC-61]
---

# Story 12.1: Backup target configuration

As an operator,
I want to set the off-host backup target at the host CLI,
So that backups go to object storage that a host compromise cannot delete, and every adult can object to a change.

**Acceptance Criteria:**

**AC1 (FR-53, D106)**
**Given** no target configured
**When** root runs `vilicus backup target set` with an S3-compatible endpoint such as `https://s3.example.com`, a bucket and credentials entered at the prompt
**Then** the target is stored encrypted in Core metadata, recorded as pending

**AC2 (FR-53, D106)**
**Given** the target configuration
**When** the command is run
**Then** it states that the credentials must be able to write but not delete or overwrite, or that the bucket must use object lock, and records which of the two the operator declared

**AC3 (FR-53, FR-8, FR-56)**
**Given** a pending target change
**When** it is recorded
**Then** every adult receives an out-of-browser alert and the delay and veto of FR-8 start as a durable deadline
**And** the new target takes effect only when the delay ends without a veto

**AC4 (FR-53, FR-8, FR-50)**
**Given** a pending target change
**When** another adult vetoes in the member web with a step-up bound to that veto
**Then** the change is discarded and the previous target stays active

**AC5 (FR-3)**
**Given** any target change attempt, applied, vetoed or refused
**When** it completes
**Then** an audit entry records it without the credentials

**AC6 (FR-53, FR-50)**
**Given** V0.1
**When** the web routes and CLI commands are enumerated
**Then** none changes the backup secret, and no CLI command vetoes a pending target change

**Decision tasks:**
- [x] Settled by FR-50: another adult vetoes a pending target change in the member web with a step-up bound to that veto; no CLI veto for target changes in V0.1.
- [x] Settled by FR-50: changing the backup secret is not reachable in V0.1; a root CLI command comes with its own FR-50 row when rotation is wanted.

**Dependencies:**
- Story 11.1 (status shows the target and pending change)
- Story 9.6 (delay and veto machinery)

**References:**
- `doc/prd.md` FR-53, FR-8, FR-50
- `doc/architecture-spine.md` AD-31
- `doc/capability-matrix.md` section 1 (set or change the off-host backup target, or the backup secret)
- `doc/decisions.md` D106
