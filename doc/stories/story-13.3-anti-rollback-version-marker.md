---
title: 'Anti-rollback version marker'
epic: 13
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-54, AD-34]
---

# Story 13.3: Anti-rollback version marker

As an operator,
I want the package scripts and the Core to refuse a version older than the highest one that ever ran,
So that an attacker or a mistake cannot roll the instance back to a version with known defects.

**Acceptance Criteria:**

**AC1 (FR-54, AD-34)**
**Given** a version has run on the host
**When** the Core starts
**Then** the highest version that ever ran is recorded both in `core.db` and in a marker file in the data directory

**AC2 (FR-54, AD-34)**
**Given** the marker records a version higher than the package being installed
**When** the operator installs the older package
**Then** the maintainer script refuses the installation with a message naming both versions
**And** the Core of the older version also refuses to start against that data directory, by its recorded version marker, not by a signature check

**AC3 (FR-54, AD-34)**
**Given** an existing installation and a backup written by an older version
**When** the operator runs `vilicus restore --replace` as root
**Then** the data directory is moved aside, the maintainer script finds no marker and accepts the version that wrote the backup
**And** after the restore the marker is set from the backup manifest

**AC4 (FR-54)**
**Given** a fresh empty data directory
**When** any version is installed
**Then** the installation proceeds and the marker is created at first start

**Dependencies:**
- Story 13.2 (acknowledged upgrades)
- Story 12.4 (restore and `vilicus restore --replace`)

**References:**
- `doc/prd.md` FR-54
- `doc/architecture-spine.md` AD-34
- `doc/architecture.md` section 16
