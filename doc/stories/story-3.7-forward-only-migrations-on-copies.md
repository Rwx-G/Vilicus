---
title: 'Forward-only migrations on copies'
epic: 3
story: 7
status: review
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
- [x] Confirm that FTS5 shadow tables stay read-only to module SQL under `SQLITE_DBCONFIG_DEFENSIVE` and that `integrity-check` passes after a migration, as D127 requires: `doc/research-notes.md` section 4 holds it as **open** (E15, and the E11 suite rerun with defensive mode on); this story can run the shadow-table DML check and `integrity-check` next to AC9 and record the result there. Confirmed (Result, AC9): every shadow table is read-only to module SQL under defensive mode, on write handles and in migrations, and `integrity-check` passes after a migration and fails on a damaged index.

**Dependencies:**
- Story 3.6 (Core tables and two migration tracks)
- Story 3.1 (connection setup, maintenance connection)

**References:**
- `doc/prd.md` FR-23, FR-54
- `doc/architecture-spine.md` AD-23
- `doc/decisions.md` D21, D84, D126, D127, D132
- `doc/research-notes.md` E11, E15, section 4
- `doc/qa/gates/1.7-e11-sqlite-migration-authorizer.yml` (E11-2)

## Implementation Notes

**What was built**
- `crates/vilicus-types/src/digest.rs`: `sha256_hex`, a `const fn` that reads a frozen SHA-256 digest from its 64 lowercase hexadecimal digits (a malformed digest stops the build of the `const` item), and `SHA256_LEN`.
- `crates/vilicus-crypto/src/lib.rs`: `sha256(data)`, through `aws-lc-rs`, the Core's first runtime use of the Stack's crypto library (AD-3: runtime hashing is the Core's, through `vilicus-crypto`).
- `crates/vilicus-module-api/src/declaration.rs`: `Migration { sql, sha256 }`; `sha256_hex` is re-exported for module crates.
- `crates/vilicus-storage/`:
  - `authorizer.rs` (AC9, D127): `CREATE VIRTUAL TABLE` and `DROP VIRTUAL TABLE` are allowed under `Policy::Migration` only, for a module of `ALLOWED_MODULES` (`fts5`, ignoring ASCII case), in the `main` schema only, never under a Core or statistics table's name; every other module, `fts5vocab`, `fts3`, `fts4`, `rtree` included, and an FTS5 table in `temp`, stays refused. `data_version` joins the introspection pragmas (FTS5 reads it before it uses its index, Story 3.2's open point); `MIGRATION_PRAGMAS` (`quick_check`) is allowed under the two migration policies, since `ALTER TABLE ... ADD COLUMN` on a `STRICT` table runs it (Story 3.2's finding, so `STRICT` module and Core tables can now gain a column). `_migrations` joins `CORE_TABLES` and `CORE_PRIVATE_TABLES`.
  - `migration.rs` (new): `FrozenMigration { sql, sha256 }`; the record of frozen hashes in the Core table `_migrations` (track, version, sha256), its reading and its comparison (`MigrationChanged` names the first version that differs, is missing or is recorded beyond the code's).
  - `core_schema.rs`: `CORE_MIGRATIONS` are `FrozenMigration`s; Core migration 1, never released, gains `_migrations`; `core_migrations()` is public, for the Core's hash check.
  - `handle.rs`: `apply_module_migrations(&[FrozenMigration])` replaces the one-step `apply_module_migration(version, sql)`: Core first, a module track beyond the list is `NewerThanMigrations`, the record of the versions the file is at must match the list before anything runs, then each pending migration in its own `BEGIN IMMEDIATE` transaction, the checks made again under the write lock, its SQL under the migration policy, its version in `_meta` and its frozen hash in `_migrations` under the Core policy; a failed step is `MigrationFailed { track, version, cause }` (`is_refusal` looks through it). `apply_core_migrations` checks the Core track's record the same way. `migration_hashes(track)` reads the record on read and write handles.
  - `migration_copy.rs` (new, exported from `maintenance`): `copy_for_migration(file, key, verified_backup)`, `MigrationCopy::{file, from, swap_in, discard}`, `cold_copies`, `remove_covered_cold_copies`, `ColdCopy`, `SchemaVersions`, `VerifiedBackup`, `MAX_COLD_COPIES` (3), `available_space`.
  - `ffi.rs`: `available_bytes`, `statvfs` (`f_bavail * f_frsize`) through `libc`, the crate's fourth FFI call.
  - `error.rs`: `MigrationChanged`, `NewerThanMigrations`, `MigrationFailed`, `ColdCopiesFull`.
  - Tests: `tests/fts5.rs`, `tests/migration_copy.rs` (new); `tests/schema.rs`, `tests/statistics.rs`, `tests/replay.rs`, `tests/mod.rs` (`frozen`, a stand-in digest: the storage layer computes none).
- `crates/vilicus-core/`:
  - `alert.rs` (new): `InstanceAdminAlert::{MigrationFailed, NewerThanCode}`, each naming the module, the partition, the file name, the track and the version(s), identifiers only.
  - `registry/migrate.rs` (new): `Registry::migrate_files(&[FileToMigrate])` returns one `FileMigration` per file (`Current`, `Migrated { from, to, cold_copy }`, `Failed { alert, error }`, `NewerThanCode { alert }`), or `MigrationRunError` (`UnregisteredModule`, `InsufficientSpace`) before anything is touched; `MigrationError` (`Storage`, `File`, `StoredRow`, `Fts5Index`).
  - `registry/mod.rs`: `frozen_migrations(module)` checks `vilicus_crypto::sha256(sql)` against the frozen hash of every Core and module migration before any file is made or migrated (`FileError::ChangedMigration`); `Registry::open` compares the record of both tracks with the code's (`check_recorded_tracks`); `FileError::admin_alert` gives the alert of a file newer than the code at open; `create_migrated` runs the list.
  - `record/call.rs`: `RecordChange::table` is a `String`, the name the journal holds (Story 3.6's open point on a removed table).
  - Tests: `record/tests_migration.rs` (new), `registry/tests.rs` (FTS5 through real migrations, frozen hashes), `record/tests_journal.rs` (the removed table); every test migration is frozen with its SHA-256 (`registry::frozen`).
- `ci/build_time_code.toml`, `supply-chain/config.toml`, `Cargo.toml`, `Cargo.lock`: `aws-lc-rs` becomes a normal dependency of `vilicus-crypto` and `libc` one of `vilicus-storage`, both already in `Cargo.lock`; the exemptions of `aws-lc-rs`, `aws-lc-sys`, `cmake` and `fs_extra` move from `safe-to-run` to `safe-to-deploy`.

**Decisions and why** (drafted decision and spine texts under Open points)
- *The frozen hash* (AC1, D21): each `Migration` states the SHA-256 of its SQL. Two checks hold it: the Core computes the digest of every migration's SQL, the Core track's included, and refuses the module's migrations when one differs, before any file is made or copied (`verify_migrations`, the build-time test, runs it for every module too); and every file records the frozen hash of each migration it ran, in the migration's own transaction, so a released migration edited and frozen again is refused on every file that ran the first one, by the runner before any SQL runs and by the registry at every open. The digest is computed in `vilicus-crypto`, where AD-3 puts runtime hashing; `vilicus-storage` computes none and holds the agreement between file and code. Gives up: a fourth third-party C library in the release tree (AWS-LC, through `aws-lc-sys`) from this story rather than Epic 4; the alternatives were a non-cryptographic checksum (no audited choice and weak against an intentional collision) or a test-time check only (which does not hold a binary built without its tests).
- *Where the record lives*: a Core table `_migrations`, private like the journal (D148 lets module SQL read `_meta` and `_vocabulary` only), created by Core migration 1. Core migration 1 was edited rather than followed by a migration 2 because no file was released, and the rule "every applied migration has its row" then holds from the first one. Gives up: a file made by Stories 3.1 to 3.6 is not migrated (none exists outside tests).
- *The swap* (AC2): "renames the original to `<file>.pre-<version>`, renames the copy into place" leaves a moment with no `<file>`. The original is hard-linked as the cold copy instead, then the copy renamed over `<file>`, so `<file>` names the original until the rename and the migrated file after it; the end state is AD-23's. A crash between the link and the rename leaves a cold copy that is the live file (same inode), which the next migration removes. Gives up: a file system with hard links (ext4 and every Linux file system of the reference host).
- *The working copy*: in `<file>.migration/`, under the file's own name, so it is a `ModuleFile` every handle opens with its sidecar, on the same file system as the file; its name is distinct from every file the backup copies (AD-31 excludes working copies).
- *`<version>` in `<file>.pre-<version>`*: both tracks move, so `<version>` is `<core>.<module>`, the versions the cold copy holds; a Core-only migration and a module migration never collide.
- *The verified-backup marker* (AC3): `VerifiedBackup { versions }`, the schema versions of the file in the verified backup; a cold copy whose versions precede them is covered (no track ahead, one behind), so no clock is compared. "At most three" and "kept until the marker" together mean: the runner removes the covered cold copies, then refuses to start a migration that would leave a fourth (`ColdCopiesFull`); it never removes an uncovered one.
- *The free space* (AC6): `statvfs` in `vilicus-storage`'s FFI module (the standard library has no call for it; `libc` is in `Cargo.lock`); the run checks each data directory against twice the largest file it would copy there, the file and its WAL, before it touches anything. A copy that runs out of space anyway fails that file only. This is a new FFI call, which D140 lists by name (drafted amendment).
- *Checks of the migrated copy*: the copy is opened as `Registry::open` opens every file (versions, the record of frozen hashes, the schema against the declaration), every stored row is held to the declaration (`check_stored_rows`, Story 3.4's open point) and every declared FTS5 table runs FTS5's `integrity-check` (D127), before the swap; a failure is the file's failed migration.
- *The failing version* of an alert: the step the runner names (`MigrationFailed`, `ChangedMigration`), or else the first pending version, Core track first (a failed check of the migrated copy, a failed copy); 0 when the file could not be read at all.
- *"the module is disabled for that partition"* (AC4): the runner returns `FileMigration::Failed`, AD-54's `failed migration`; the file stays at its version, which `Registry::open` refuses (`MigrationPending`), so no module code runs on it. Holding the state across calls and answering callers with it is Story 3.9's.
- *FTS5*: `data_version` is allowed under every policy that runs statements, not only migrations, since FTS5 reads it on every use of its index (a search or a write on a read or write handle); it returns a commit counter. A migration may put an index on a shadow table (defensive mode does not refuse it); the registry refuses the file as it refuses every undeclared object.
- *A removed table* (Story 3.6's open point): the journal rows of a table a migration removes stay until retention; a repeated call of such a row returns the first call's changes under the journaled table name (`RecordChange::table` is a `String`), rather than failing.

**Files**
- `crates/vilicus-types/src/`: `digest.rs` (new), `lib.rs`
- `crates/vilicus-crypto/`: `Cargo.toml`, `src/lib.rs`
- `crates/vilicus-module-api/src/`: `declaration.rs`, `lib.rs`, `check.rs`, `tests.rs`
- `crates/vilicus-storage/`: `Cargo.toml`; `src/`: `migration.rs`, `migration_copy.rs` (new), `authorizer.rs`, `core_schema.rs`, `error.rs`, `ffi.rs`, `handle.rs`, `lib.rs`, `maintenance.rs`; `src/tests/`: `fts5.rs`, `migration_copy.rs` (new), `mod.rs`, `replay.rs`, `schema.rs`, `statistics.rs`
- `crates/vilicus-core/`: `Cargo.toml`; `src/`: `alert.rs` (new), `lib.rs`; `src/registry/`: `migrate.rs` (new), `mod.rs`, `tests.rs`; `src/record/`: `tests_migration.rs` (new), `call.rs`, `mod.rs`, `tests.rs`, `tests_call.rs`, `tests_deletion.rs`, `tests_journal.rs`
- `Cargo.toml`, `Cargo.lock`, `ci/build_time_code.toml`, `supply-chain/config.toml`
- `doc/stories/sprint-status.yaml` (3.7 `review`)

**Deviations**
- *AC1, "its frozen hash is checked first"*: checked twice, against the digest of the SQL (the Core, before any file is touched) and against the record of the file (the runner, before any SQL runs, and the registry at every open). "through the authorizer connection of Story 3.1": the migration handle, as before, now on the working copy.
- *AC2, "renames the original to `<file>.pre-<version>`"*: hard-linked, then the copy renamed over the file (Decisions); `<version>` is `<core>.<module>`. "closes every connection": the caller's (only the Core opens module files, AD-9); the runner checks the WAL empty after its own TRUNCATE checkpoint and the live file unchanged between the copy and the swap, and refuses otherwise.
- *AC3, "the caller records a verified-backup marker"*: the marker is the schema versions the verified backup holds (Decisions); recording it is Story 12.3's.
- *AC4, "the module is disabled for that partition"*: returned as `FileMigration::Failed` with the alert, the file refused at open as pending (Decisions); the persistent availability state is Story 3.9's. "alerted": the alert is returned typed; delivering it, and alerting the partition's members as AD-23 also says, is the alert path's (Epic 8).
- *AC5, "When the Core opens it"*: `Registry::open` refuses it (`NewerThanCode`, `CoreNewerThanCode`, as since Story 3.2), and `FileError::admin_alert` gives the typed alert; the runner returns the same alert without touching the file.
- *AC6*: the run's check, per data directory; `vilicus upgrade check` (Story 13.4) can call `available_space`.
- *AC8*: a plain file copy, the one `maintenance::copy_file` of Story 3.1 makes.

**Open points**
- *Design documents* (coordinator; none edited here):
  - **Drafted D149**, "Migrations on copies: frozen hashes, the swap, cold copies and FTS5", amending AD-23, D21, D84, D126, D127 and D140: "Context: story 3.7 builds the migration runner of AD-23; D21 freezes each migration's hash without saying how it is checked, AD-23's two renames leave a moment with no file, two tracks make `<file>.pre-<version>` ambiguous, the verified-backup marker is not defined, FTS5 needs `PRAGMA data_version` and a column added to a `STRICT` table runs `quick_check`, both refused before, and free space needs a system call D140 does not name. Decision: a module's migration states the SHA-256 of its SQL; before any file is made or migrated, the Core computes, through `vilicus-crypto` and `aws-lc-rs`, the digest of every migration of both tracks and refuses the module's migrations when one differs; every file records in the private Core table `_migrations` the frozen hash of each migration it ran, in the migration's transaction, and the runner and the registry refuse a file whose record differs from the code's for the versions it is at. A migration runs on a copy in `<file>.migration/`, made by a plain file copy after a TRUNCATE checkpoint that leaves the WAL empty; the copy is migrated Core track first, then opened as every file is (versions, record, schema), its stored rows held to the declaration and its FTS5 indexes checked with `integrity-check`; it is swapped in only if the live file did not change since the copy: the original is hard-linked as the cold copy `<file>.pre-<core>.<module>` with its key epoch sidecar, the copy renamed over the file and the directories synced, so the file's name never names nothing; what a crash leaves is cleared by the next migration. A failure keeps the previous file untouched, returns a typed instance admin alert naming the file, the track and the version, and lets the other files proceed. The verified-backup marker of a file is the schema versions of the file in a verified backup; a cold copy of an earlier state is covered by it and may be removed; at most three cold copies are kept, and a migration that would leave a fourth uncovered one does not start. A run starts only when each data directory has twice the largest file it would copy there, read with `statvfs`. `CREATE` and `DROP VIRTUAL TABLE` run under the module migration policy only, for `fts5` in the file's own schema; `PRAGMA data_version` is allowed under every policy that runs statements and `PRAGMA quick_check` under the two migration policies. Consequences: the release tree compiles AWS-LC from this story; a `STRICT` table can gain a column; `vilicus-storage` makes a fourth FFI call (`statvfs`, through `libc`); the backup leaves out `<file>.migration/` and `<file>.pre-*` by name."
  - **AD-23**: replace "renames the original to `<file>.pre-<version>` (this is the cold copy), renames the copy into place and fsyncs the directory" by "hard-links the original as `<file>.pre-<core>.<module>` (this is the cold copy, named after the versions of its two tracks, with its key epoch sidecar), renames the copy over the file and fsyncs the directory, so the file's name always names a complete file (D149)"; after "at most three per file" add "; a cold copy is covered once a verified backup holds a later state of its file, and a migration that would leave a fourth uncovered one does not start (D149)"; after "embedded in the binary with a frozen hash" add ", the SHA-256 of its SQL, checked by the Core before any migration runs and recorded per file in `_migrations` (D149)"; after "the migration policy allows `CREATE VIRTUAL TABLE` and `DROP VIRTUAL TABLE` only for the `fts5` module, case-insensitively" add ", in the file's own schema, with `PRAGMA data_version`, which FTS5 reads, allowed under every policy (D149)".
  - **AD-26**, the table list: after "`_vocabulary` (...)" add "`_migrations` (the frozen hash of each migration the file ran, D149)"; D148's "reads none but `_meta` and `_vocabulary`" stays true (`_migrations` is private).
  - **D140**, the FFI calls of `vilicus-storage`: add "`statvfs`, the free space the migration runner checks (D149)", and `libc` as the crate it goes through.
  - **D126**: after "no pragma outside a read-only introspection allowlist runs" add "(which holds `data_version`), except `quick_check` under the migration policies, which `ALTER TABLE` runs on a `STRICT` table (D149)".
  - `doc/research-notes.md` section 4, the FTS5 line: "**open**" becomes "settled by story 3.7: under `SQLITE_DBCONFIG_DEFENSIVE`, insert, update and delete on every FTS5 shadow table, and drop or alter of one, are refused to module SQL on write handles and in migrations, while the authorizer alone would allow them; FTS5's `integrity-check` passes after a migration and fails on a damaged index; the E11 suite passes with defensive mode on, checked on every handle". E15's row (per-record keys with FTS5) stays open: no record cipher exists yet.
  - `doc/architecture.md` section 12, Migrations: "renames the original to `<file>.pre-<version>` (the cold copy), renames the copy into place" follows AD-23's new text.
  - No test reads text these amendments change.
- *Story 3.9*: `FileMigration::Failed` and `NewerThanCode` map to AD-54's `failed migration` and `newer than code`; the runner's outcome is not remembered across starts, so a file whose migration failed is tried again at the next unlock (the same release fails the same way) until Story 3.9 holds the state.
- *Story 3.10*: the reference module declares its migrations with their frozen hashes (`sha256_hex`), and `verify_migrations` checks them; its two migrations in sequence can run through `migrate_files`.
- *Story 12.2 and 12.3*: the backup copies neither `<file>.migration/` nor `<file>.pre-*`; verification records, per file, the schema versions it holds, the `VerifiedBackup` the runner takes, and calls `remove_covered_cold_copies`.
- *Story 13.2 and 13.4*: `migrate_files` is the per-partition run at unlock (keys per file); `vilicus upgrade check` reports `FileMigration` per file and can call `available_space`. `core.db` and `wrappers.db` (AD-23) are not module files and get their own runner when they exist.
- *Epic 4*: `vilicus-crypto` already depends on `aws-lc-rs`; the crypto suite adds its primitives there.
- *Concurrency*: the runner takes the caller's word that no connection is open, as the copy of Story 3.1 does, with the WAL and live-file checks as a second line; the Core's writer thread (AD-9) is the first.
- *Free space during the run*: checked once, before the run; each migration leaves a cold copy, so a run of many files can still run out, which fails the file it happens on and keeps it.

## Result

All commands ran on 2026-10-21 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch at `562384d` made inside a new Docker volume, with an empty target directory; the mutations ran on copies of the tree in another volume, never on the working tree; every volume was removed afterwards. Each commit of the story, checked out in turn on that clone, passes `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and the workspace tests, none failing: `dc943f2` 440 passed, `d4bd00f` 442, `ffd0309` 448, `9dce494` 453, `a45c8be` 461, `4bfddc7` 469, `562384d` 470.

Gates, as `.github/workflows/ci.yml` runs them, at `562384d`:
- `python3 -m unittest discover -s ci`: `Ran 214 tests`, `OK`.
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- System OpenSSL: `libssl-dev` `3.5.7-1~deb13u3`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0. Also `cargo clippy -p vilicus-core --lib` and `cargo clippy -p vilicus` without the `testing` feature: clean.
- `cargo test --workspace --no-fail-fast --frozen --config ci/cargo-vendored.toml`: 470 passed, none failed (437 before the story): `vilicus-core` 137, `vilicus-storage` 132, `vilicus-types` 75, `vilicus-module-api` 46, `vilicus-crypto` 2 (doc tests included).
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`, after the four exemptions moved to `safe-to-deploy`.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `cargo tree --workspace -e features -i rusqlite`: `load_extension` appears nowhere (0 lines). `cargo tree -p vilicus -e normal,build -i aws-lc-rs`: through `vilicus-crypto` and `vilicus-core`; `-i libc`: through `vilicus-storage` and `vilicus-core`.
- No new package: `Cargo.lock` gains two edges, `vilicus-crypto` on `aws-lc-rs` 1.18.2 and `vilicus-storage` on `libc` 0.2.191, both already locked.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (FR-23, AD-23, D21, E11) | **Pass** (Deviations) | `every_core_migration_has_the_digest_its_frozen_hash_states`. `a_changed_migration_is_refused_before_it_runs_and_at_open`: a module migration whose SQL lost its digest fails `verify_migrations` with `ChangedMigration { Module, 2 }` and no file is made; a file that ran migration 2, opened with that migration edited and frozen again, is refused at open with the same error, and the runner refuses it with `MigrationChanged { Module, 2 }`. Runner level, `a_changed_migration_fails_the_file_before_anything_runs`: both cases fail the file with the alert naming the version, its bytes and directory unchanged. Storage: `versioned_migrations_apply_in_order_and_record_their_version` (one row per migration of both tracks, nothing run twice), `a_changed_migration_is_refused_before_anything_runs` (versions 1 and 2 changed, with and without a pending migration, and a list shorter than the file, `NewerThanMigrations`; version, record and schema unchanged), `a_record_that_disagrees_with_the_version_is_refused` (a row taken out, one beyond `_meta`, a changed Core row), `migration_sql_cannot_reach_the_record_of_frozen_hashes`. The E11 suite, through the migration handle, unchanged and passing. |
| AC2 (AD-23, D84, DC-50) | **Pass** (Deviations) | `a_migration_runs_on_a_copy_swapped_in_with_the_original_as_its_cold_copy`: a row left in the WAL is in the copy (the TRUNCATE checkpoint ran); the copy, in `fixture.household.db.migration/`, is byte for byte the checkpointed file; the live file is untouched while the copy migrates; the swap leaves `<file>`, `<file>.epoch`, `<file>.pre-1.0` (byte for byte the original, opening with the file's key, its sidecar at the file's epoch) and that sidecar; the live file is at module version 3 with the same epoch in its sidecar and `_meta`, with no WAL and no working directory. `no_copy_is_made_while_the_epoch_is_pending_or_the_wal_cannot_empty` (`EpochTransitionPending`; a reader holding a snapshot, `CheckpointIncomplete`; nothing created). `a_write_after_the_copy_refuses_the_swap` (`CopyRaced`, the write kept, no cold copy). `an_interrupted_migration_is_cleared_by_the_next_one` (a working directory, a cold copy hard-linked to the live file, an orphan sidecar: cleared, the live file untouched, the next migration completes). Runner: `a_pending_file_is_migrated_on_a_copy_and_its_original_kept_cold` (from 1.1 to 1.2, the cold copy `shop.household.db.pre-1.1`, the Core opens the migrated file). |
| AC3 (FR-23, AD-23, D84) | **Pass** (Deviations) | `at_most_three_cold_copies_are_kept_until_a_verified_backup_covers_them`: three migrations leave three cold copies; a fourth is refused with `ColdCopiesFull { kept: 3 }`, nothing changed, also under a marker of the oldest cold copy's own state; under a marker at 1.1 the oldest goes and the migration leaves three again; `remove_covered_cold_copies` removes the three a later marker covers. `a_state_precedes_every_later_one_and_no_other`. Runner: `a_file_with_three_uncovered_cold_copies_waits_for_a_verified_backup`. |
| AC4 (FR-54, AD-23, D84, DC-50) | **Pass** (Deviations) | `a_failed_migration_keeps_the_previous_file_and_the_others_proceed`: of two files in one run, the household file's back-fill breaks the declaration (`StoredRow`); its bytes and its names in the directory are as before, it stays at version 1, `Registry::open` refuses it as `MigrationPending`, and the alert is `MigrationFailed { shop, Household, shop.household.db, Module, 2 }`; the member's file of the same run is migrated. Storage: `a_failed_migration_leaves_the_previous_file_untouched` (copies discarded or dropped; bytes, listing, rows and version unchanged). |
| AC5 (FR-23) | **Pass** (Deviations) | `a_file_newer_than_the_code_is_refused_with_an_alert`: a file at module version 2 under code at 1 is left untouched by the runner with `NewerThanCode { Module, found 2, latest 1 }`, refused by `Registry::open` (`NewerThanCode`), whose `admin_alert` is the same alert; a Core track ahead gives the Core alert both ways. |
| AC6 (AD-23) | **Pass** | `a_run_without_twice_the_largest_file_free_does_not_start`: one file grown, sparse, past half the free space makes the run fail with `InsufficientSpace` (at least twice its size required) before the other file of the run is touched (bytes, listing, version). `the_free_space_of_the_data_directory_is_read` (`statvfs`; a missing directory is `Io`). |
| AC7 (D126, E11) | **Pass** | The closed connection at open, after a success, after a refusal and after a failed `BEGIN`, and transaction control refused with nothing written: the Story 1.7 replay (`a_migration_connection_is_closed_outside_the_runner`, `a_failed_begin_leaves_the_connection_closed`, `transaction_control_inside_a_migration_is_refused`), unchanged and passing. On the copy: `a_refused_statement_ends_the_migration_with_nothing_written` (`ATTACH`, `COMMIT`, `SAVEPOINT` in a module migration: `MigrationFailed { Module, 2 }`, a refusal; the file's bytes, listing, version and rows unchanged), `a_failed_migration_leaves_the_previous_file_untouched`. |
| AC8 (D126, D132) | **Pass** (Deviations) | The copy is `maintenance::copy_file`, a plain file copy (AC2's test compares it byte for byte with the checkpointed file); the migration handle of the copy reads back `secure_delete` 1 and defensive mode on (AC2's test). `a_pending_file_is_migrated_on_a_copy_and_its_original_kept_cold`: a migration deletes a 64-character random value; before, the decrypted file holds it (the control); after, no run of 8 bytes of it is in the migrated file, its WAL (0 frames) or its shm, while the cold copy still holds the row, as D132 says of cold copies. |
| AC9 (D127) | **Pass** | `only_a_module_migration_creates_or_drops_an_fts5_table` (policy unit test: `fts5` in three spellings under the migration policy only, never in `temp` or another schema, never a module of `DENIED_MODULES` or an unknown one, never under a Core or statistics table's name). `temporary_objects_and_virtual_tables_are_refused_in_a_migration` (`fts3`, `fts4`, `FTS4`, `rtree`, `rtree_i32`, `fts3tokenize`, `fts5vocab`, FTS5 in `temp`: refused, nothing written). `a_module_migration_creates_and_drops_fts5_tables` (three kinds of content, `secure-delete` 1, searched on a read handle, written on a write handle, dropped with its shadow tables by a later migration). `the_pragmas_fts5_and_strict_tables_run_are_allowed_where_they_run`, `a_column_is_added_to_a_strict_table_under_the_migration_authorizer`. The registry's FTS5 tests on tables made by a migration: `real_fts5_tables_with_their_declared_arguments_pass`, `a_real_fts5_table_without_secure_delete_is_refused`, `fts5_tables_absent_undeclared_or_of_another_kind_are_refused`, `an_index_a_migration_puts_on_a_shadow_table_is_refused`. The E11 suite with defensive mode on: every replay handle asserts it, and the replay passes. |
| Decision task (D127, E15) | **Settled** | `fts5_shadow_tables_are_read_only_to_module_sql_under_defensive_mode`: on every shadow table of three FTS5 tables (`_data`, `_idx`, `_docsize`, `_config`, `_content`), insert, update and delete on a write handle, and those plus drop, add column and rename in a migration, fail with "may not be modified", "dropped" or "altered", the file unchanged; the control, the write policy alone without defensive mode, deletes from each. `fts5_integrity_check_passes_after_a_migration`: `integrity-check` passes on every table after the migration and the writes, and fails once a connection outside defensive mode damages the index. Runner: `the_fts5_indexes_of_the_migrated_copy_are_checked` (a damaged index fails the file's migration, its file kept). |

Story 3.6's open point on a removed table: `a_repeated_call_is_answered_after_a_migration_removed_its_table` (a call journaled on `notes`, a migration on a copy drops the table, the repeated call is `Deduplicated` with the first call's changes, `notes` included).

Mutations, each on its own copy of the tree at `562384d`, applied alone to the unmodified tree, `cargo test -p <crate> --lib` on the tests named; the unmutated tree passed them all. 25 of 25 made a named test fail:
- **FTS5 policy**: virtual tables allowed under every policy: `only_a_module_migration_creates_or_drops_an_fts5_table`; any module: that test and `temporary_objects_and_virtual_tables_are_refused_in_a_migration`; any schema: the first; defensive mode off (its read-back relaxed): `fts5_shadow_tables_are_read_only_to_module_sql_under_defensive_mode` and `hostile_statements_are_refused_on_a_write_connection_and_select_succeeds`; `quick_check` under every policy: `the_pragmas_fts5_and_strict_tables_run_are_allowed_where_they_run`, `a_column_is_added_to_a_strict_table_under_the_migration_authorizer`; transaction control allowed in a migration: `transaction_control_inside_a_migration_is_refused`.
- **Frozen hashes**: the record not compared: `a_changed_migration_is_refused_before_anything_runs`, `a_record_that_disagrees_with_the_version_is_refused`; the hash not recorded: the first and `versioned_migrations_apply_in_order_and_record_their_version`; `_migrations` readable by module SQL: `migration_sql_cannot_reach_the_record_of_frozen_hashes`; the SQL not checked against its frozen hash: `a_changed_migration_is_refused_before_it_runs_and_at_open`, `a_changed_migration_fails_the_file_before_anything_runs`; the registry ignoring the record at open: `a_changed_migration_is_refused_before_it_runs_and_at_open`.
- **Copy and swap**: no checkpoint before the copy: `no_copy_is_made_while_the_epoch_is_pending_or_the_wal_cannot_empty`; the swap without the cold copy: `a_migration_runs_on_a_copy_swapped_in_with_the_original_as_its_cold_copy`; the swap over a file written since the copy: `a_write_after_the_copy_refuses_the_swap`; an interrupted swap's link kept: `an_interrupted_migration_is_cleared_by_the_next_one`; `discard` leaving the working copy: `a_failed_migration_leaves_the_previous_file_untouched`; `secure_delete` off (its read-back relaxed): `a_pending_file_is_migrated_on_a_copy_and_its_original_kept_cold`.
- **Cold copies**: no limit: `at_most_three_cold_copies_are_kept_until_a_verified_backup_covers_them`; a cold copy covered by a backup of its own state: that test and `a_state_precedes_every_later_one_and_no_other`.
- **Runner**: stored rows of the copy not checked: `a_failed_migration_keeps_the_previous_file_and_the_others_proceed`; FTS5 indexes not checked: `the_fts5_indexes_of_the_migrated_copy_are_checked`; free space not checked: `a_run_without_twice_the_largest_file_free_does_not_start`; a failed check still swapped in: `a_failed_migration_keeps_the_previous_file_and_the_others_proceed`, `a_refused_statement_ends_the_migration_with_nothing_written`; a module track newer than the code migrated: `a_file_newer_than_the_code_is_refused_with_an_alert`; a removed table's journal row refused: `a_repeated_call_is_answered_after_a_migration_removed_its_table`.
