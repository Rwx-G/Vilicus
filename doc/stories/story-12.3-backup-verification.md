---
title: 'Backup verification'
epic: 12
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-53, FR-3, AD-31, AD-23]
---

# Story 12.3: Backup verification

As an operator,
I want every uploaded backup to be verified without the backup secret,
So that "verified" means the copy is complete and intact, and cold copies are dropped only after it.

**Acceptance Criteria:**

**AC1 (FR-53, AD-31)**
**Given** an uploaded backup
**When** `vilicus backup verify` runs
**Then** it checks the manifest MAC, every file hash and completeness against the manifest, without the backup secret

**AC2 (FR-53)**
**Given** a backup with one altered file, one missing file, or a modified manifest
**When** verification runs
**Then** it fails and names the defect

**AC3 (FR-53, AD-31)**
**Given** a scheduled backup
**When** its upload completes
**Then** verification runs automatically and its result is recorded in `core.db` and shown in `vilicus status`

**AC4 (AD-23)**
**Given** cold copies of migrated files older than a newly verified backup
**When** the verified backup is recorded
**Then** those cold copies may be removed, and none is removed before a verified backup exists

**AC5 (FR-3)**
**Given** any verification
**When** it finishes
**Then** an audit entry records the backup sequence number and the outcome

**Dependencies:**
- Story 12.2 (backup assembly and manifest)

**References:**
- `doc/prd.md` FR-53
- `doc/architecture-spine.md` AD-23, AD-31
- `doc/architecture.md` section 18
