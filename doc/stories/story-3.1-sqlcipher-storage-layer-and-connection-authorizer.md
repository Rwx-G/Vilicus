---
title: 'SQLCipher storage layer and connection authorizer'
epic: 3
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-5, AD-9, D2, D3, I6, E11, FR-23, D126, D127, D132, D136, E17, DC-75]
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
**And** the hostile-statement tests of Story 1.7 run in this crate's test suite and pass, replaying `HOSTILE_STATEMENTS` (23) and `RUNTIME_HOSTILE_STATEMENTS` (2) of `spikes/sqlite-authorizer/src/hostile.rs` unchanged, with the controls that show each statement would run without the authorizer; E11 took no fallback, so no statement parser is built (D126).

**AC4 (AD-5)**
**Given** an open file
**When** its last connection closes
**Then** `checkpoint(TRUNCATE)` runs and no WAL content remains, checked by a test.

**AC5 (AD-5)**
**Given** a module file
**When** its key epoch (partition root version, generation) is written
**Then** it is written atomically to a clear sidecar `<file>.epoch` and repeated in the file's `_meta` table
**And** opening a file whose sidecar and `_meta` disagree fails with a typed error.

**AC6 (D126, D127, D132, D136, E11, E17)**
**Given** any connection the storage layer opens
**When** it is set up
**Then** it runs in this order: turn off `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` (one `sqlite3_db_config` FFI call, since `rusqlite`'s `DbConfig` omits the option and the bundled build enables the C API on every connection, Story 1.7 finding 1); key the file; run the setup pragmas, `trusted_schema` off, `secure_delete` = ON (never FAST, set on every connection because the pragma is per connection), `journal_size_limit`, WAL on writers, `synchronous = FULL` on writer connections; enable `SQLITE_DBCONFIG_DEFENSIVE`; read every one of these values back and fail the open on a mismatch; and only then install the authorizer, because SQLCipher pragmas go through the authorizer
**And** a test shows `sqlite3_load_extension` refused on every role, and `secure_delete` reading 1 on a migration connection as on the others.

**AC7 (D126, E11)**
**Given** the workspace build
**When** `libsqlite3-sys` compiles SQLCipher
**Then** extension loading is compiled out where the toolchain allows, with `LIBSQLITE3_FLAGS="-USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION"` in the `[env]` table of `ci/cargo-vendored.toml`, the Cargo configuration every CI build passes with `--config` (Story 2.2; its content check is extended to allow exactly that key, and no `.cargo/config.toml` may exist, Story 2.1), `SELECT load_extension('x')` failing with `no such function`, and `cargo tree -e features` never showing the `rusqlite` feature `load_extension` (procedure of Story 1.7, finding 1, not run there)
**And** if the toolchain cannot compile it out, the runtime switch of AC6 stays the control and the reason is recorded.

**AC8 (D126, I6)**
**Given** a connection with its authorizer installed
**When** statements run
**Then** no pragma outside a read-only introspection allowlist runs (`temp_store` is not in it, D132); SQL functions are allowlisted, so `load_extension`, `sqlcipher_export` and `fts5` are refused, and a test fails when the engine offers a function that is in neither the allowed nor the denied list; writes to SQLite's internal tables (`sqlite_` prefix) are refused outside migrations; a statement prepared before the authorizer is refused when it runs
**And** a function denied by the authorizer fails with `SQLITE_ERROR` ("not authorized to use function"), and `rusqlite` reports some prepare errors as `Error::SqlInputError` with no SQLite code, so the storage layer classifies both as refusals (Story 1.7, finding 2).

**AC9 (D126, D132)**
**Given** a copy of a file or a VACUUM
**When** the Core needs one
**Then** it runs on a dedicated Core maintenance connection with no module authorizer, opened for that purpose and closed after it, as a file copy or with SQLite's online backup API, never with `VACUUM INTO` or `ATTACH`, which the authorizer refuses
**And** VACUUM is used only as the fallback for content deleted while `secure_delete` was off.

**AC10 (D132, E17)**
**Given** a connection under its authorizer, where `PRAGMA wal_checkpoint(TRUNCATE)` is refused
**When** the storage layer checkpoints after a deletion that must be real
**Then** it calls `sqlite3_wal_checkpoint_v2(..., SQLITE_CHECKPOINT_TRUNCATE, ...)`, which the authorizer does not see, retried until it reports not busy and the WAL is empty (Story 1.11, `checkpoint_c_api_runs_under_the_authorizer`)
**And** the build keeps `SQLITE_TEMP_STORE=2` and a keyed connection's effective `temp_store` is 0, so temporary data stays in memory (test reads both settings).

**AC11 (AD-4, E11)**
**Given** a raw key handed to SQLCipher
**When** the connection is keyed
**Then** every buffer that holds the key or its hex form for `PRAGMA key` is zeroized on drop and never logged; the spike's `apply_raw_key`, which builds an unzeroized hex `String`, is not reused (Story 1.7, "Not for Story 3.1 as is").

**Decision tasks:**
- [ ] Decide the SQLCipher version (spine Deferred). Recommended: keep the bundled 4.14.0 of `rusqlite` 0.40.2 unless a reading of the SQLCipher changelog from 4.14.0 to 4.19.x shows a security fix, in which case pin a self-built 4.19.x; record the reading and the choice before V0.1 ships. Gives up: the self-built path costs a build script and a vendored source.

**Dependencies:**
- Story 1.7 (E11 authorizer result and hostile tests)
- Story 1.11 (E17 setup and checkpoint result)
- Story 2.4 (shared types)

**References:**
- `doc/architecture-spine.md` AD-5, AD-9, AD-23, Stack, Deferred (SQLCipher version)
- `doc/decisions.md` D2, D3, D21, D126, D127, D132, D136
- `doc/ai-safety.md` I6
- `doc/research-notes.md` E11, E17
- `spikes/sqlite-authorizer/` (`src/lib.rs` policies and `open()`, `src/hostile.rs`), `spikes/secure-delete-wal/`
- `doc/qa/gates/1.7-e11-sqlite-migration-authorizer.yml` (E11-1), `doc/qa/gates/1.11-e17-secure-delete-and-wal-behaviour.yml` (E17-1)
