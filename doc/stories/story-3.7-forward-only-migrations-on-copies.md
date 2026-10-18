---
title: 'Forward-only migrations on copies'
epic: 3
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-23, FR-54, AD-23, D21, D84, DC-50, E11, D126, D127, D132]
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

**AC7 (D126, E11)**
**Given** a migration connection
**When** a statement reaches it outside the runner
**Then** it is refused, at open, after a successful migration, after a refused one and after a failed `BEGIN`, because the connection is left closed on every exit path
**And** the runner owns the transaction: migration SQL that begins, commits or rolls back a transaction or opens a savepoint is refused, and a refused statement ends the migration with nothing written (the file bytes, directory listing, schema and rows unchanged, as Story 1.7 AC1 checks).

**AC8 (D126, D132)**
**Given** the copy step of AC2
**When** the runner copies the file
**Then** the copy is made on the Core maintenance path of Story 3.1 AC9, as a file copy or with SQLite's online backup API, never with `VACUUM INTO` or `ATTACH`
**And** the migration connection sets `secure_delete` = ON like every other connection (Story 3.1 AC6).

**AC9 (D127)**
**Given** a module migration
**When** it holds `CREATE VIRTUAL TABLE` or `DROP VIRTUAL TABLE`
**Then** it is allowed only under the migration policy and only when the module name is `fts5`, compared case-insensitively; `fts5vocab`, `fts3`, `fts4`, `rtree` and every other module are refused
**And** the E11 hostile suite is rerun with `SQLITE_DBCONFIG_DEFENSIVE` on and passes.

**Decision tasks:**
- [ ] Confirm that FTS5 shadow tables stay read-only to module SQL under `SQLITE_DBCONFIG_DEFENSIVE` and that `integrity-check` passes after a migration, as D127 requires: `doc/research-notes.md` section 4 holds it as **open** (E15, and the E11 suite rerun with defensive mode on); this story can run the shadow-table DML check and `integrity-check` next to AC9 and record the result there.

**Dependencies:**
- Story 3.6 (Core tables and two migration tracks)
- Story 3.1 (connection setup, maintenance connection)

**References:**
- `doc/prd.md` FR-23, FR-54
- `doc/architecture-spine.md` AD-23
- `doc/decisions.md` D21, D84, D126, D127, D132
- `doc/research-notes.md` E11, E15, section 4
- `doc/qa/gates/1.7-e11-sqlite-migration-authorizer.yml` (E11-2)
