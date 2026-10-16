---
title: 'Upgrade check and CI upgrade test'
epic: 13
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-54, D84, AD-23, AD-33, AD-41]
---

# Story 13.4: Upgrade check and CI upgrade test

As an operator,
I want to see pending and failed migrations per file before and after an upgrade, and CI to prove each release upgrades cleanly,
So that I know what an upgrade will touch and that it will not strand the instance.

**Acceptance Criteria:**

**AC1 (FR-54, D84, AD-23)**
**Given** an installation with files at different schema versions
**When** the operator runs `vilicus upgrade check` as root
**Then** the report lists, per file, the pending migrations and any failed migration
**And** it needs no member passphrase, opens no member key and is audited

**AC2 (AD-23)**
**Given** the free space in the data directory is below twice the size of the largest file
**When** the operator runs `vilicus upgrade check`
**Then** the report flags the shortfall and names the required space

**AC3 (AD-33, AD-41)**
**Given** the previous release and the candidate release
**When** the CI upgrade test installs the previous release in the Debian 13 VM, creates a member and data, upgrades to the candidate and acknowledges the upgrade
**Then** the candidate reads the previous `core.db` schema until the acknowledgement, migrates after it, and the member unlocks and reads their data
**And** a failure blocks the merge

**AC4 (AD-41)**
**Given** a candidate release
**When** the CI upgrade test inspects its migrations
**Then** it fails if any `core.db` schema change of the release makes the schema unreadable by the previous version before the acknowledgement

**Dependencies:**
- Story 13.3 (anti-rollback marker)

**References:**
- `doc/prd.md` FR-54
- `doc/architecture-spine.md` AD-23, AD-33, AD-41
- `doc/decisions.md` D84
