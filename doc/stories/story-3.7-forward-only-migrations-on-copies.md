---
title: 'Forward-only migrations on copies'
epic: 3
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-23, FR-54, AD-23, D21, D84, DC-50, E11]
---

# Story 3.7: Forward-only migrations on copies

As a project maintainer,
I want every database file migrated forward only, on a copy swapped in on success,
So that a failed migration keeps the previous file intact and stops only that file's module for that partition.

**Acceptance Criteria:**

**AC1 (FR-23, AD-23, D21, E11)**
**Given** a migration embedded in the binary as declarative SQL
**When** it runs
**Then** its frozen hash is checked first and a changed migration is refused
**And** it runs through the authorizer connection of Story 3.1, forward only, with no down migration.

**AC2 (AD-23, D84, DC-50)**
**Given** a file to migrate
**When** the runner migrates it
**Then** it closes every connection, runs `checkpoint(TRUNCATE)`, checks no WAL content remains, copies the file, migrates and fsyncs the copy, renames the original to `<file>.pre-<version>`, renames the copy into place and fsyncs the directory.

**AC3 (FR-23, AD-23, D84)**
**Given** the cold copies of a file
**When** a new migration runs
**Then** at most three cold copies are kept for that file, and each is kept until the caller records a verified-backup marker, which the storage layer takes as an input.

**AC4 (FR-54, AD-23, D84, DC-50)**
**Given** a migration that fails on one file
**When** the runner stops
**Then** the previous file stays in place untouched, the module is disabled for that partition, the runner returns a typed instance admin alert naming the file and version
**And** migrations of other files proceed.

**AC5 (FR-23)**
**Given** a file whose schema version is newer than the module code
**When** the Core opens it
**Then** it is refused, the module is not started for that file and a typed instance admin alert is returned.

**AC6 (AD-23)**
**Given** a pending migration
**When** the runner checks free space before copying
**Then** it refuses to start unless free space is at least twice the largest file to migrate, returning a typed error.

**Dependencies:**
- Story 3.6 (Core tables and two migration tracks)

**References:**
- `doc/prd.md` FR-23, FR-54
- `doc/architecture-spine.md` AD-23
- `doc/decisions.md` D21, D84
- `doc/research-notes.md` E11
