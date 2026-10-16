---
title: 'Acknowledged upgrade and maintenance mode'
epic: 13
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-54, D84, AD-23, FR-50, FR-56]
---

# Story 13.2: Acknowledged upgrade and maintenance mode

As an instance admin,
I want a new version to wait for my explicit acknowledgement before it migrates the Core files,
So that no upgrade changes the instance's state without a human seeing the version change.

**Acceptance Criteria:**

**AC1 (FR-54, FR-50)**
**Given** the package has just been upgraded and the new version starts
**When** the instance admin opens the instance admin web
**Then** the screen shows the previous and the new version and asks for an acknowledgement confirmed by a step-up bound to that acknowledgement
**And** no other surface can acknowledge the upgrade

**AC2 (FR-54, FR-56)**
**Given** a package upgrade has been installed
**When** the new version starts and waits for the acknowledgement
**Then** every adult receives a content-free alert on the out-of-browser notification channel
**And** the alert is recorded in the audit log

**AC3 (FR-54)**
**Given** the acknowledgement is pending
**When** any client calls the Core
**Then** the Core runs in maintenance mode and serves only login, the acknowledgement and status; every other request is refused with a retryable error
**And** the new version reads the previous `core.db` schema without migrating it

**AC4 (FR-54, AD-23, D84)**
**Given** the instance admin acknowledged with a valid step-up
**When** the Core proceeds
**Then** `wrappers.db` and `core.db` migrate at once, each on a copy swapped in on success
**And** each `core.<partition>.db` and module file migrates at that partition's next unlock

**AC5 (FR-54, D84)**
**Given** one file's migration fails after the acknowledgement
**When** the Core handles the failure
**Then** the previous file is kept, only that file's module stops for that partition, every other file and module keeps running, and the instance admin is alerted

**Dependencies:**
- Story 13.1 (signed packages and upgrade verification)
- Story 3.7 (migrations on copies per file)
- Story 7.6 (step-up bound to one action)

**References:**
- `doc/prd.md` FR-50, FR-54, FR-56
- `doc/architecture-spine.md` AD-23
- `doc/architecture.md` section 17 (package upgraded, migration fails on one file)
- `doc/decisions.md` D84
