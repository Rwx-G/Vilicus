---
title: 'E11: SQLite migration authorizer'
epic: 1
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E11, FR-23, D21, I6]
---

# Story 1.7: E11: SQLite migration authorizer

As the owner,
I want hostile migrations run against the SQLite authorizer of the chosen SQLCipher build,
So that the storage layer can rely on the authorizer to keep a module confined to its own file.

**Acceptance Criteria:**

**AC1 (E11, FR-23, D21)**
**Given** rusqlite 0.40.2 with bundled SQLCipher and an authorizer installed on a migration connection, under `spikes/e11-authorizer/`
**When** unit tests run migrations containing `ATTACH`, `DETACH`, a `PRAGMA` outside an allowlist, and extension loading (SQL function and API call)
**Then** every forbidden statement is rejected and nothing is written

**AC2 (E11, I6)**
**Given** the same authorizer on an ordinary read connection
**When** the same hostile statements are submitted, together with an allowed `SELECT`
**Then** the hostile statements are rejected and the `SELECT` succeeds

**AC3 (E11, D21)**
**Given** any forbidden statement passes the authorizer
**When** the result is recorded
**Then** the fallback (a vetted statement parser in front of the connection) is recorded in `doc/decisions.md`

**Spike plan:**
- Question: does the SQLite authorizer block `ATTACH`, `DETACH`, unsafe `PRAGMA` and extension loading in the migration connection (E11)?
- Method: unit tests with hostile migrations against rusqlite 0.40.2 with bundled SQLCipher.
- Pass criterion: all forbidden statements rejected.
- Timebox: 2 working days.
- Fallback on failure: move to a vetted statement parser.
- Result record: E11 status in `doc/research-notes.md` with a link to the test run; the hostile test set kept for Story 3.1.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E11)
- `doc/decisions.md` D21
- `doc/architecture-spine.md` AD-5, AD-9, AD-23
- `doc/ai-safety.md` section 3 (I6)
- `doc/prd.md` FR-23
