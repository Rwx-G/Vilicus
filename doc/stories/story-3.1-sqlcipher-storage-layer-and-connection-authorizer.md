---
title: 'SQLCipher storage layer and connection authorizer'
epic: 3
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-5, AD-9, D2, D3, I6, E11, FR-23]
---

# Story 3.1: SQLCipher storage layer and connection authorizer

As a project maintainer,
I want `vilicus-storage` to open one SQLCipher file per module per partition under an authorizer on every connection,
So that no connection can attach another file, load an extension or run an unsafe pragma, and each file keeps exactly one key.

**Acceptance Criteria:**

**AC1 (AD-5, D2, D3)**
**Given** a raw 256-bit key supplied by the caller
**When** the storage layer opens a module file
**Then** the file is named `<module>.<partition>.db` and opened as SQLCipher with that raw key, never a passphrase-derived SQLCipher KDF
**And** opening it with another key fails without exposing any content.

**AC2 (AD-9, I6)**
**Given** a read handle
**When** it executes any statement other than `SELECT`
**Then** the authorizer refuses it.

**AC3 (AD-5, AD-9, I6, E11, FR-23)**
**Given** any connection opened by the storage layer, write, read or migration
**When** a statement uses `ATTACH`, `DETACH`, extension loading or a `PRAGMA` outside the read allowlist
**Then** the authorizer refuses it
**And** the hostile-statement tests of Story 1.7 run in this crate's test suite and pass; if E11 took its fallback, statements go through the vetted statement parser before execution.

**AC4 (AD-5)**
**Given** an open file
**When** its last connection closes
**Then** `checkpoint(TRUNCATE)` runs and no WAL content remains, checked by a test.

**AC5 (AD-5)**
**Given** a module file
**When** its key epoch (partition root version, generation) is written
**Then** it is written atomically to a clear sidecar `<file>.epoch` and repeated in the file's `_meta` table
**And** opening a file whose sidecar and `_meta` disagree fails with a typed error.

**Decision tasks:**
- [ ] Decide the SQLCipher version (spine Deferred). Recommended: keep the bundled 4.14.0 of `rusqlite` 0.40.2 unless a reading of the SQLCipher changelog from 4.14.0 to 4.19.x shows a security fix, in which case pin a self-built 4.19.x; record the reading and the choice before V0.1 ships. Gives up: the self-built path costs a build script and a vendored source.

**Dependencies:**
- Story 1.7 (E11 authorizer result and hostile tests)
- Story 2.4 (shared types)

**References:**
- `doc/architecture-spine.md` AD-5, AD-9, Stack, Deferred (SQLCipher version)
- `doc/decisions.md` D2, D3, D21
- `doc/ai-safety.md` I6
- `doc/research-notes.md` E11
