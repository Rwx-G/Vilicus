---
title: 'SQLCipher storage layer and connection authorizer'
epic: 3
story: 1
status: done
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
- [x] Decide the SQLCipher version (spine Deferred). Recommended: keep the bundled 4.14.0 of `rusqlite` 0.40.2 unless a reading of the SQLCipher changelog from 4.14.0 to 4.19.x shows a security fix, in which case pin a self-built 4.19.x; record the reading and the choice before V0.1 ships. Gives up: the self-built path costs a build script and a vendored source. Done: the reading found a security fix, and the owner chose the self-built 4.19.0 (Implementation Notes, SQLCipher version; D143).

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

## Implementation Notes

**SQLCipher version (decision task)**
- Reading of 2026-10-21, from the official sources:
  - the SQLCipher changelog, `CHANGELOG.md` on the `master` branch of https://github.com/sqlcipher/sqlcipher;
  - the release list, https://github.com/sqlcipher/sqlcipher/releases. The latest 4.x is v4.19.0 (2026-09-08). v5.0.0-beta is a pre-release, outside the range.
- 4.15.0 (2026-04-28) "sanitize[s] the source database name passed to `sqlcipher_export`". The bug was reported by Deutsche Telekom Security GmbH.
  - Zetetic's release note (https://www.zetetic.net/blog/2026/04/28/sqlcipher-4.15.0-release/) calls it a defensive mode bypass: a crafted source name "could execute statements that defensive mode would otherwise block", up to direct modifications of `sqlite_schema` and database corruption. CVSS 4.0 base score 2.1, Low. Exploiting it needs an existing SQL injection or unrestricted SQL access that reaches `sqlcipher_export`. Zetetic recommends that all applications upgrade.
  - The Zetetic note gives no CVE id. The CVE record CVE-2026-51936 (https://osv.dev/vulnerability/CVE-2026-51936, which links NVD, the cvelistV5 entry, fix commit `30842cda35c88cdfc7a8adba1c9b20821d2c08d1` and that Zetetic note) names the same fix: "SQLCipher before 4.15.0", fixed in 4.15.0, 4.14.0 listed as affected.
- 4.16.0 to 4.19.0 bring SQLite 3.53.1 to 3.53.4 and robustness fixes. 4.19.0 also fixes the escaping of database aliases in `sqlcipher_export()` and of migration file names; none is called a security fix.
- The SQLite release notes from 3.51.3 to 3.53.4 (https://www.sqlite.org/changes.html) name no security fix.
- No `rusqlite` release bundles a SQLCipher above 4.14.0 (0.40.2 is the latest, https://github.com/rusqlite/rusqlite/releases).
- Rule applied: a security fix was found, so the self-built path. The owner chose SQLCipher 4.19.0, self-built and pinned (D143).
- What Vilicus was exposed to: the connection authorizer refuses `sqlcipher_export` on every connection, and no maintenance operation calls it. The flaw was therefore not reachable from SQL this layer runs. The upgrade removes the dependency on that single layer.

**What was built**
- `crates/vilicus-storage/sqlcipher/`, the vendored source:
  - `sqlite3.c`: the SQLCipher 4.19.0 amalgamation (SQLite 3.53.4 inside), generated from tag `v4.19.0` (tag object `58beb4a3...`, commit `c4b275a4...`).
  - `LICENSE.md` (BSD-3-Clause, Zetetic LLC) and `SQLITE_LICENSE.md` (public domain), copied from the tag.
  - `SHA256SUMS`.
  - `README.md`: origin, ids, hashes, the two CI checks, and how to regenerate.
  - `regenerate.sh`: clones the tag from the official repository, checks both object ids, runs `configure` and `make sqlite3.c`, and compares the result with `SHA256SUMS` and, file by file, with `cmp`; `--write` is the upgrade path.
  - Generation needs no tclsh: SQLite's build compiles its bundled `jimsh`. Two runs, from different directories and with and without the `configure` options, gave the same `sqlite3.c`. The files are `-text` in `.gitattributes`.
- `crates/vilicus-storage/build.rs`:
  - compiles `sqlcipher/sqlite3.c` with the system `cc` and archives it with `ar` (std `Command` only, no new crate);
  - links the archive with `static:+whole-archive=sqlcipher`, puts it on the search path, and links the system `libcrypto` after it;
  - `links = "vilicus-sqlcipher"` in the manifest keeps a second copy out of a build graph.
- Defines, reproduced from `libsqlite3-sys` 0.38.2 `bundled-sqlcipher`, which the E11 and E17 spikes ran on:
  - `SQLITE_CORE`, `SQLITE_DEFAULT_FOREIGN_KEYS=1`, `SQLITE_ENABLE_API_ARMOR`, `SQLITE_ENABLE_COLUMN_METADATA`, `SQLITE_ENABLE_DBSTAT_VTAB`;
  - `SQLITE_ENABLE_FTS3`, `SQLITE_ENABLE_FTS3_PARENTHESIS`, `SQLITE_ENABLE_FTS5`, `SQLITE_ENABLE_JSON1`, `SQLITE_ENABLE_MEMORY_MANAGEMENT`, `SQLITE_ENABLE_RTREE`, `SQLITE_ENABLE_STAT4`;
  - `SQLITE_SOUNDEX`, `SQLITE_THREADSAFE=1`, `HAVE_USLEEP=1`, `HAVE_ISNAN`, `_POSIX_THREAD_SAFE_FUNCTIONS`, `HAVE_LOCALTIME_R`;
  - for SQLCipher: `SQLITE_HAS_CODEC`, `SQLITE_TEMP_STORE=2`, `SQLITE_EXTRA_INIT=sqlcipher_extra_init`, `SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown`, `HAVE_STDINT_H=1`.
- Defines that change:
  - `SQLITE_ENABLE_LOAD_EXTENSION=1` is replaced by `SQLITE_OMIT_LOAD_EXTENSION` (AC7);
  - `SQLCIPHER_CRYPTO_OPENSSL` is added; it is SQLCipher's default provider, now named explicitly;
  - `SQLITE_USE_URI` is left out (review): no dependency opens a URI, and without it a filename is a path unless a connection passes `SQLITE_OPEN_URI`, which this crate never does.
- Compile flags:
  - `-ffunction-sections -fdata-sections`;
  - hardening (review): `-fPIC -fstack-protector-strong -fstack-clash-protection`, plus `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2` when optimizing (fortify needs optimization, and Ubuntu's gcc defines level 3 by default);
  - optimisation and debug info follow cargo's `OPT_LEVEL` and `DEBUG`.
  - At `-O2` the amalgamation compiles with no warning with gcc 14.2.0 (Debian 13) and 13.3.0 (Ubuntu 24.04), and the object calls the fortified `*_chk` functions. A test checks that the archive references `__stack_chk_fail`.
- `CC` and `AR` choose the compiler and the archiver. `CFLAGS` and `LIBSQLITE3_FLAGS` are not read, so no environment variable changes the defines or the flags. The build script passes its defines and the archive path to the tests.
- `crates/vilicus-storage/src/`:
  - `ffi.rs`: the only `unsafe`, four functions, each allowed locally with a `// SAFETY:` comment (D140):
    - `sqlite3_db_config(SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION)`, set and read;
    - `sqlite3_key_v2`, keying from a byte buffer;
    - `sqlite3_wal_checkpoint_v2(TRUNCATE)`, returning busy as a value.
  - `authorizer.rs`: the E11 policies (`Closed`, `Migration`, `Write`, `Read`) and a Core-only `Epoch` policy, `authorize` as a pure function, and the lists:
    - moved from the spike: `INTROSPECTION_PRAGMAS`, `ALLOWED_FUNCTIONS`, `INTERNAL_ALTER_FUNCTIONS`, `MIGRATION_INTERNAL_TABLES`; `DENIED_FUNCTIONS` and `COMPILED_OUT_FUNCTIONS` are test-only, since the policy never reads them.
    - `CORE_TABLES` (`_meta`; review M1): no module policy inserts, updates, deletes, creates, drops, alters, indexes or attaches a trigger to them, compared ignoring case. The authorizer receives the table without its schema, so `main._meta` matches too. A trigger body is authorized when it fires, so a trigger that writes `_meta` fails the statement that fires it. `Epoch` writes `CORE_TABLES` rows and nothing else.
    - `ALLOWED_MODULES` (test-only) and `DENIED_MODULES` (review item 5): every virtual table module the engine offers is reviewed. `fts5` is allowed, for Story 3.7. The rest is denied: `dbstat`, the FTS3, FTS4 and R-tree modules, `fts5vocab` and `pragma_module_list`. A read of a table bearing a denied module's name is refused, which is how the eponymous `dbstat` is reached. `CREATE VIRTUAL TABLE` stays refused for every module.
    - SQLite 3.53 adds `json_array_insert` and `jsonb_array_insert`. The coverage test named them, and they are allowed after review: they compute on their arguments like `json_insert`.
  - `file.rs`:
    - `Partition` (`Household`, `Home`, `Member(Id)`, written `household`, `home` or the id text);
    - `ModuleFile` (directory, `ModuleName`, partition), which gives `<module>.<partition>.db`, `<file>.epoch`, `<file>.epoch.next` (pending sidecar), `<file>.create` (staging file of `create`) and `<file>-wal`;
    - `KeyEpoch { partition_root_version, generation }` (`u32` each). The sidecar is a three-line text format with one canonical form: `vilicus key epoch 1`, then `partition_root_version <n>`, then `generation <m>`.
    - `read_epoch` fails with `EpochSidecarMissing` when there is no sidecar, `MalformedEpoch`, or `EpochTransitionPending { current, pending }` when a pending sidecar exists. Sidecars are written atomically: temporary file, `fsync`, rename, directory `fsync`.
  - `handle.rs`: `open::<R>(file, key)`, `create(file, key, epoch)`, `Handle<R>` for the roles `Read`, `Write` and `Migration` (sealed marker types), and `Settings`.
    - Setup order (AC6):
      1. open read-write without `SQLITE_OPEN_URI`, busy timeout `BUSY_TIMEOUT` (100 ms, `[ASSUMPTION]`);
      2. extension loading API off;
      3. key through `sqlite3_key_v2` with the `x'<hex>'` form;
      4. the schema read that turns a wrong key into `Error::WrongKey`;
      5. `trusted_schema` off, `secure_delete` ON, `journal_size_limit` 0, `journal_mode` WAL on writers, `synchronous` FULL, `query_only` on readers;
      6. `SQLITE_DBCONFIG_DEFENSIVE` on;
      7. everything read back, with `foreign_keys` 1 and `temp_store` 0 too, and checked (`Error::SetupMismatch`);
      8. the epoch of the sidecar against `_meta`, `Error::EpochMismatch`, or one of the typed sidecar errors above;
      9. the role's opening policy, `Closed` for migration.
    - A handle exposes `prepare`, `execute`, `execute_batch`, `query_row` and `close`, never its `Connection`. `Handle<Migration>::apply_migration` is the spike's runner.
    - `Handle<Write>` adds `write_epoch` and `checkpoint_truncate`. `checkpoint_truncate` moved off the other roles (review item 6); its documentation says that a deletion that must be real needs short-lived readers.
    - `create` (review item 2):
      - it builds the file under `<file>.create`, with `_meta`, closed after a TRUNCATE checkpoint and synced;
      - it then writes the sidecar, then renames the file into place and syncs the directory;
      - a staging file, alone or with a sidecar, is an interrupted `create` and is discarded;
      - a sidecar with neither file nor staging file is `EpochSidecarWithoutFile`.
    - `write_epoch` (review item 2):
      - it writes the pending sidecar, then updates `_meta` in one transaction under the `Epoch` policy, then renames the pending sidecar over the sidecar and syncs the directory;
      - on a failure before the rename it removes the pending sidecar and returns the original error, even when the rollback fails.
    - `close` and `Drop` run one TRUNCATE checkpoint, then close. A busy checkpoint means another connection is open, so this one is not the last.
    - `checkpoint_truncate` retries up to 10 times, until not busy and the WAL file is empty, then returns `Error::CheckpointIncomplete`.
  - `maintenance.rs` (AC9; review item 8), each function opening its own connections, set up like a writer with no authorizer, and closing them:
    - `copy_file`: a plain copy, refused while the WAL holds content; it compares the file's length, modification time and WAL before and after (`CopyRaced`);
    - `backup`: the online backup API in bounded steps into a target opened with the full setup (no URI, busy timeout, extension loading off, key, pragmas, `DEFENSIVE`, read back);
    - both refuse an existing destination or destination sidecar, write under `<destination>.partial`, then publish the sidecar `<destination>.epoch` (epoch read from the source), the rename and a directory sync; any failure removes the partial file;
    - `vacuum`.
  - `error.rs`: `Error` and `is_refusal`.
    - `is_refusal` classifies `SQLITE_AUTH`, the `SQLITE_ERROR` "not authorized to use function", and "authorizer malfunction", in both `SqliteFailure` and `SqlInputError` (AC8). "Authorizer malfunction" is what SQLite reports when the callback returns an unknown code, which `rusqlite` does when it panics; the statement did not run, so it fails closed.
    - `Display` and a hand-written `Debug` leave out the SQL text `rusqlite` would print, and `source` hands out no `rusqlite` error (review nit).
  - `tests/`: 74 tests with the crate's unit tests (Result). `tests/hostile.rs` is a byte-for-byte copy of `spikes/sqlite-authorizer/src/hostile.rs`, and a test compares the two files. `tests/core_tables.rs` holds the `_meta` hostile statements.
- `ci/check_sqlcipher_source.py` and `ci/test_check_sqlcipher_source.py`, run in `workspace-policy`, pinned in `WorkflowAgreementTest`. They fail when:
  - a file differs from `SHA256SUMS`, or `SHA256SUMS` is malformed or uses CRLF;
  - a file in the directory is not listed;
  - `build.rs` compiles a file that is not listed;
  - `regenerate.sh` names another version than the amalgamation;
  - the README does not state the pinned tag, ids or hashes;
  - `regenerate.sh` sets a repository other than `https://github.com/sqlcipher/sqlcipher`, or names any other URL (review M2).
- `.github/workflows/ci.yml`:
  - the `sqlcipher-regenerate` job (review M2):
    - it runs `regenerate.sh` in the pinned `rust:1.99-trixie` image, with the checkout mounted read-only; the clone of the tag is its only network access;
    - it is path-filtered inside the job through `ci/must_run.py`, like `hpke-review`, on `crates/vilicus-storage/sqlcipher`, the workflow and both scripts, so it can be a required check; it always runs on the weekly schedule and on manual runs.
  - `lint`, `build-and-test` and `vm-smoke`, the jobs that compile `vilicus-storage`, check the system OpenSSL first: `dpkg -s libssl-dev`, then `pkg-config --modversion openssl` (review item 7).
  - `WorkflowAgreementTest` pins the job, the condition on every step after its detection, the watched paths, the read-only mount and the OpenSSL step in each of the three jobs.
- Dependencies (`[workspace.dependencies]`, used by `vilicus-storage` only):
  - `rusqlite =0.40.2` (MIT), default features off, with `sqlcipher`, `modern_sqlite` (the bindings and API `bundled-sqlcipher` implied), `hooks` and `backup`;
  - `zeroize =1.9.1` (Apache-2.0 OR MIT), already in the tree.
  - `Cargo.lock` grows from 86 to 93 packages. `vendor/` gains seven crates: `rusqlite` 0.40.2, `libsqlite3-sys` 0.38.2 (MIT), `bitflags` 2.13.2, `fallible-iterator` 0.3.0, `fallible-streaming-iterator` 0.1.9, `smallvec` 1.16.3 and `vcpkg` 0.2.15 (all MIT and/or Apache-2.0). `pkg-config` 0.3.34 was already there. No `deny.toml` licence or duplicate entry was needed.
  - `deny.toml` notes that the vendored SQLCipher C source is outside cargo-deny's view.
  - `ci/build_time_code.toml` gains `libsqlite3-sys`, which copies bindings and asks for `-lsqlcipher` and compiles nothing, and `vilicus-storage`.
  - `supply-chain/`: the imports now cover `fallible-iterator`, `fallible-streaming-iterator`, `pkg-config` and `vcpkg`. Four exemptions are added at their exact versions with notes in the house style: `bitflags`, `libsqlite3-sys`, `rusqlite`, `smallvec`. `zeroize` moves from safe-to-run to safe-to-deploy. No `[[trusted]]` entry.

**Decisions and why**
- *Mechanism: `rusqlite` `sqlcipher` (link) feature plus this crate's build script* (option a of the owner's brief). Option b, a custom amalgamation in `libsqlite3-sys`, does not exist:
  - its `build_bundled` compiles `{lib_name}/sqlite3.c` from its own package directory, so a different amalgamation would mean editing the vendored crate or a `[patch]`, both refused;
  - the only knobs are `LIBSQLITE3_FLAGS` and the `SQLITE_MAX_*` variables, which change the defines, not the source;
  - its linked path (`sqlcipher` without `bundled`) builds nothing. It probes `pkg-config`, or uses `SQLCIPHER_LIB_DIR`, which is not known before the build. Otherwise it prints `rustc-link-lib=dylib=sqlcipher` and copies prebuilt bindings, the 3.51.3/4.14.0 bindings under `bundled_bindings`, which declare a subset of the 3.53.4 API; SQLite keeps its ABI.
  - So a crate must compile the library and make `-lsqlcipher` resolve to it.
- *The build script sits in `vilicus-storage`, not in a new crate*: a new workspace crate would need an AD-3 node, so a spine change.
- *`+whole-archive`*: `rustc` orders native libraries by crate dependency, and `vilicus-storage` and `libsqlite3-sys` are not ordered relative to each other. Whole-archive defines every SQLite symbol wherever the archive lands. `libcrypto` follows it in the same crate's link line, so `--as-needed` keeps it. The archive also sits on the search path, so `libsqlite3-sys`'s `-lsqlcipher` finds it rather than a system SQLCipher.
  - Found during the review: a binary that links `rusqlite` without linking this crate, such as an integration test of the crate that does not use it, fails to link, because nothing brings `-lcrypto` after the archive.
  - The `-as-needed` link modifier that would fix it is unstable (nightly only).
  - Only `vilicus-storage` depends on `rusqlite`, and its tests are unit tests, so no build meets the case; `build.rs` documents it.
- *`cc` and `ar` through `std::process`, not the `cc` crate*: the brief forbids new direct dependencies, `cc` included. What it gives up: no cross-compilation, which the script refuses explicitly (native Unix target only), and no MSVC.
- *Read handles opened read-write with `query_only`* (see `handle.rs`): a `SQLITE_OPEN_READONLY` connection cannot checkpoint, so a reader that closes last would leave WAL content and break AC4. The authorizer and `query_only` both still refuse writes. What it gives up: the read-only open flag as a third guard.
  - `query_only` cannot be turned off from SQL. The pragma allowlist holds only table-argument introspection pragmas, so no settable pragma passes with or without a value, and a test shows `PRAGMA query_only = 0` refused on a read handle (review item 4).
- *`BEGIN` stays allowed on read handles* (review item 6): a cross-module read made of several queries (AD-9) needs one snapshot to see one state. What it gives up: a long snapshot keeps deleted rows in the WAL. `checkpoint_truncate` then reports `CheckpointIncomplete` rather than claiming the deletion done, and the callers that delete for real keep their readers short.
- *Keying through `sqlite3_key_v2`, not `PRAGMA key`* (AC11): the SQL text of a `PRAGMA key` stays in SQLite's statement memory unwiped, and `rusqlite` copies it into `SqlInputError`. The C call reads the buffer and SQLCipher copies it into its own context. A test checks that no product source builds `PRAGMA key` text.
- *The key parameter stays `&[u8; 32]`, not a zeroizing key type* (review nit):
  - key types belong to `vilicus-crypto` (AD-4), which `vilicus-storage` may not depend on (D140: both are private to the Core);
  - a borrowed array lets the Core pass the bytes straight from its locked key slot, inside the closure of D131, with no copy;
  - the storage layer's only copy is the hex text, which is `Zeroizing`;
  - an owned zeroizing type here would force a second, unlocked copy at every open.
- *`_meta` is a key-value table* (`key TEXT PRIMARY KEY, value INTEGER`, `STRICT`, `WITHOUT ROWID`), so the schema versions of AD-26 join it as rows in Story 3.2 without a migration. Module SQL may read it: the epoch is a counter, not a secret.
- *Recovery rule for an interrupted change of epoch* (review item 2), assumed here for the rekey story, which owns the key handling:
  - `write_epoch` leaves at most two candidate epochs in clear, the sidecar and the pending sidecar, and the `_meta` update is one transaction. A rekey must change the file key in that same transaction for the rule to hold.
  - Every open fails with `EpochTransitionPending { current, pending }` until the Core resolves it, by opening the file with the key of each candidate in turn. Exactly one opens it and matches `_meta`:
    - if it is `current`, the change did not happen and the pending sidecar is removed;
    - if it is `pending`, the pending sidecar is renamed over the sidecar.
  - This story provides the failure and the two epochs, not the resolution.
- *Interrupted `create`*: the final name exists only once the file and its sidecar are durable. A staging file therefore always means an interrupted `create` that never held module data, which the next `create` discards; nothing else is guessed.
- *A second pin of the file hashes in the CI check: not added* (review M2):
  - the regeneration job compares the files with what the tag produces;
  - a second copy of the hashes would sit in the same reviewed diff as the source it guards, and add nothing that job does not prove;
  - the repository pin does add something: it fixes what the job trusts, from a file outside the vendored directory, and a tag name resolves only among that repository's own refs.
- *`copy_file` and a concurrent connection* (review item 8): only the Core opens module files, and it serializes a copy with the file's writer thread (AD-9), so no connection opens in between. The before-and-after comparison is a second line that turns a missed race into `CopyRaced`, not a lock.
- *`write_epoch` writes the pending sidecar, then `_meta`, then the rename*; a crash anywhere fails closed with a typed error carrying both epochs.
- *Busy timeout 100 ms*, `[ASSUMPTION]`: `rusqlite`'s default is 5 s, and D136 wants a checkpoint that meets a reader to fail fast and be retried. One writer per file means writers do not wait on each other.

**Files**
- `crates/vilicus-storage/`: `Cargo.toml`, `build.rs`, `sqlcipher/` (6 files), `src/lib.rs`, `src/ffi.rs`, `src/authorizer.rs`, `src/error.rs`, `src/file.rs`, `src/handle.rs`, `src/maintenance.rs`, `src/tests/` (`mod.rs`, `core_tables.rs`, `engine.rs`, `hostile.rs`, `maintenance.rs`, `replay.rs`, `setup.rs`)
- `Cargo.toml`, `Cargo.lock`, `vendor/` (7 crates), `deny.toml`, `supply-chain/config.toml`, `supply-chain/imports.lock`, `.gitattributes`
- `ci/check_sqlcipher_source.py`, `ci/test_check_sqlcipher_source.py`, `ci/build_time_code.toml`, `ci/test_check_supply_chain.py`, `.github/workflows/ci.yml`
- `doc/stories/sprint-status.yaml` (epic 3 `in-progress`, 3.1 `review`)

**Deviations**
- *AC7, the carrier of the flags.* Extension loading is compiled out in `build.rs`, not by `LIBSQLITE3_FLAGS` in `ci/cargo-vendored.toml`. `LIBSQLITE3_FLAGS` is read only by `libsqlite3-sys`'s bundled build, which no longer runs. `ci/cargo-vendored.toml` and its check are unchanged and stay the source replacement only. The result is stronger: no environment can turn it back on, and every build, local or CI, compiles it out.
- *AC6, "`sqlite3_load_extension` refused on every role".* With extension loading compiled out, the C function is not in the archive (`nm` shows no `load_extension` symbol), so no test can call it. Every role reads the `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` switch back as 0, and the open fails otherwise. `SELECT load_extension('x')` is `no such function` with and without the authorizer, and `PRAGMA compile_options` shows `OMIT_LOAD_EXTENSION` and no `ENABLE_LOAD_EXTENSION`. The runtime switch stays, as D126 asks while the toolchain could change. A mutation that compiles extension loading back in and removes the switch call fails the setup test.
- *AC3, extension loading statements.* The three `load_extension` hostile statements fail as `no such function` before the authorizer is asked, on every connection and in the controls, where the spike saw an authorizer refusal. The replay accepts that outcome for that class only. The lists are unchanged.
- *AC3, `apply_migration` on a write connection* (a spike test). Handles are typed, so `apply_migration` exists on `Handle<Migration>` only and the case cannot be written.
- *AC4, which close checkpoints.* Every close runs a TRUNCATE checkpoint, as AD-23 says. The guarantee that "no WAL content remains" holds at the last close, which the tests show with the writer last and with a reader last. While other connections are open, a busy checkpoint at close is not an error.
- *Migration policy and FTS5.* `CREATE VIRTUAL TABLE ... USING fts5` stays refused here, as in E11. D127's allowance, with the registry's argument check, is Story 3.7 AC9.
- *Synchronous FULL on read handles too.* A read handle can be the connection that checkpoints at close, so FULL applies to every role.
- *`CopyRaced` has no test.* The race it detects needs a connection that writes between two system calls of the copy, an interleaving no test here can force. The comparison is plain code and is documented as a second line, not a guarantee.

**Review of 2026-10-21** (independent review on PR #4; each fix carries a test, and a mutation that removes it fails that test, in Result):

| Item | Resolution |
|---|---|
| M1, `_meta` open to module SQL | Core tables refused to every module policy and to trigger bodies when they fire; `write_epoch` writes them under the Core-only `Epoch` policy. `tests/core_tables.rs`. |
| M2, hash check proves consistency only | `sqlcipher-regenerate` CI job, byte-for-byte comparison with what the tag produces, repository pinned in the Python check. |
| 2, epoch crash windows | `create` through a staging file; `write_epoch` through a pending sidecar; typed `EpochTransitionPending`, `EpochSidecarWithoutFile`; recovery rule under Decisions. |
| 3, missing sidecar as `Io` | `EpochSidecarMissing`; the test removes the sidecar instead of emptying it (an empty one is still `MalformedEpoch`). |
| 4, pragma values on read handles | No settable pragma is allowlisted; `query_only` refused on a read handle in any spelling, and still 1 afterwards. |
| 5, virtual table modules | Module coverage test over `pragma_module_list`; `dbstat` denied. |
| 6, `checkpoint_truncate` on every role | Write handles only; short-lived readers documented; `BEGIN` on reads kept (Decisions). |
| 7, implicit `libssl-dev` | Check step in `lint`, `build-and-test`, `vm-smoke`. |
| 8, maintenance copies | Existing destination refused, `.partial` then rename, partial removed on failure, sidecar carried, backup target fully set up, race detected (`CopyRaced`). |
| Nits | `SQLITE_USE_URI` removed; `build.rs` comment corrected; hardening flags; `Debug` without SQL; authorizer malfunction is a refusal; key parameter kept as `&[u8; 32]` (Decisions); `write_epoch` keeps the original error when the rollback fails. |

**Open points**
- *Design documents* (coordinator), changes this story's code implies beyond D143:
  - D140: the third FFI call, `sqlite3_key_v2`.
  - D143: the compile differs from `bundled-sqlcipher` by `SQLITE_USE_URI` removed and the hardening flags, besides extension loading.
  - AD-5, if the design should state them: the pending sidecar `<file>.epoch.next`, and the fail-closed rule while it exists.
  - D126: virtual table modules are reviewed like functions, and `dbstat` is refused.
  - AD-26, if the design should state it: `_meta` is out of reach of module SQL, migrations included. The Core track of a migration (Story 3.2) then needs its own policy to change `_meta`, like `Epoch`.
- *Rekey story*: implements the recovery rule of an interrupted change of epoch (Decisions), and must change the file key in the same transaction as `_meta`.
- *The other Core tables* (`_journal`, `_outbox`, `_consumed`, `_dead_letter`, AD-26): they join `CORE_TABLES` with the stories that create them (3.6, 3.8), with a Core policy for the writes the pipeline makes in them.
- *Binary licence notice* (Story 5.7): SQLCipher's BSD-3-Clause requires binary redistributions to reproduce its notice. The `.deb` must carry `crates/vilicus-storage/sqlcipher/LICENSE.md`.
- *SQLCipher's own log*: on a wrong key, SQLCipher writes `ERROR CORE sqlite3Codec: error decrypting page 1 data` lines to stderr (seen in the test runs). The text holds no secret. Routing or silencing it (`PRAGMA cipher_log`, `cipher_log_level`, which go through the authorizer and would join the setup) belongs to the logging story.
- *CI OpenSSL*: the GitHub `ubuntu-24.04` runner (image 20261012.334.1) ships `libssl-dev` 3.0.13 and `pkg-config`, and no SQLCipher package (runner image readme). The check step now makes that explicit, with no install. The build and the storage tests pass in an `ubuntu:24.04` container against OpenSSL 3.0.13. The target is Debian 13's 3.5.7. The engine test asserts an OpenSSL 3 provider, not a minor version.
- *`vilicus` does not link SQLCipher yet*: `vilicus-core` does not use `vilicus-storage`, so `rustc` leaves it out of the binary (`ldd` shows no `libcrypto`). The first Core story that opens a file brings the link and its runtime dependency on `libcrypto.so.3`.
- *`Partition` lives in `vilicus-storage`*: if another crate needs the partition names, it moves to `vilicus-types`.
- *Owner review of 4 new exemptions*: `cargo vet` suggests `cargo vet inspect rusqlite 0.40.2` (23 729 lines) and `libsqlite3-sys 0.38.2` (598 760 lines, almost all the unused bundled amalgamations).
- *Required check*: the owner adds `SQLCipher amalgamation regenerated from its tag (D143)` to the required checks.
- *E15 and D127* (defensive mode with FTS5 shadow tables): Story 3.7.

## Result

All commands ran on 2026-10-21 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran, after the review fixes, on a fresh clone of the branch made inside the container, with an empty target directory. Mutations ran on a copy with their own target directory, never on the working tree. Before the review fixes, the branch ran on GitHub as PR #4, 9 of 9 checks green, with the 55 storage tests of that state.

Engine, as the tests print it: SQLite 3.53.4, SQLCipher 4.19.0 community, OpenSSL 3.5.7 (Debian 13). On `ubuntu:24.04` with `libssl-dev` 3.0.13: the same engine on OpenSSL 3.0.13, 74 storage tests passed.

Gates, as `.github/workflows/ci.yml` runs them:
- `python3 -m unittest discover -s ci`: `Ran 210 tests`, `OK` (198 before the story; 11 in `ci/test_check_sqlcipher_source.py`, 1 more in `WorkflowAgreementTest`).
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`. Before the allowlist entries it named `libsqlite3-sys 0.38.2` and `vilicus-storage 0.0.0` build scripts.
- `python3 ci/check_supply_chain.py --vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0. `cargo build -p vilicus-storage --release` (with `_FORTIFY_SOURCE=2`): exit 0.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 199 tests passed, none failed (125 before the story; `vilicus-storage` 74).
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`. Before: `9 unvetted dependencies`.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `sqlcipher-regenerate`, its command run locally: `docker run --rm -v "$PWD:/w:ro" -w /w <pinned image> bash crates/vilicus-storage/sqlcipher/regenerate.sh` prints `SQLCipher v4.19.0 (c4b275a47932888216bade83aff2bbc73df0ff85) regenerates to the files of SHA256SUMS, byte for byte`, exit 0. It has not run on GitHub yet.
- The OpenSSL check step, as run in an `ubuntu:24.04` container: `Status: install ok installed`, `Version: 3.0.13-0ubuntu3.16`, `3.0.13`.
- `cargo tree --workspace -e features -i rusqlite`: features `backup`, `hooks`, `modern_sqlite`, `sqlcipher`; `load_extension` appears nowhere (0 lines).

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (AD-5, D2, D3) | **Pass** | `file::tests::a_file_is_named_module_dot_partition_dot_db` (`tasks.household.db`, `tasks.home.db`, `tasks.<member id>.db`, and the `.epoch` sidecar). `create_writes_an_encrypted_file_named_module_dot_partition`: no plaintext header, and a marker row is absent from the raw bytes. `the_file_is_keyed_with_the_raw_key_not_a_passphrase_kdf`: the same 64 hex digits given as a passphrase do not open the file, the `x'...'` form does. `another_key_fails_without_exposing_content`: every role gets `Error::WrongKey`, whose `Display` and `Debug` hold neither the marker nor a table name. |
| AC2 (AD-9, I6) | **Pass** | `each_runtime_role_runs_only_its_own_statements`: a read handle runs `SELECT` (with functions, in an explicit read transaction) and the introspection pragmas, and refuses `INSERT`, `UPDATE`, `DELETE` and `CREATE TABLE` as refusals. A write handle refuses DDL, `VACUUM` and `INSERT INTO sqlite_sequence`. `query_only_cannot_be_turned_off_on_a_read_handle`: four spellings of `PRAGMA query_only` refused, `query_only` still 1. The 25 hostile statements on a read handle, below. |
| AC3 (AD-5, AD-9, I6, E11, FR-23) | **Pass** | `the_hostile_lists_are_the_spike_file_unchanged` compares the bytes of `src/tests/hostile.rs` with the spike's file. `every_hostile_statement_is_refused_in_a_migration_and_nothing_is_written`: the 23 statements, each ending a migration; file bytes, directory, schema and rows unchanged. `hostile_statements_are_refused_on_a_read_connection_and_select_succeeds` and `..._on_a_write_connection_...`: the 23 plus the 2 runtime statements, each followed by a `SELECT` that succeeds, file and directory unchanged. Controls: `without_the_authorizer_no_hostile_statement_is_an_auth_refusal`, `without_the_authorizer_a_plaintext_copy_can_be_written`, `without_the_authorizer_vacuum_into_writes_a_copy`. Also `transaction_control_inside_a_migration_is_refused`, `temporary_objects_and_virtual_tables_are_refused_in_a_migration`, `an_ordinary_migration_applies_under_the_authorizer`, `a_refused_migration_leaves_the_connection_usable`, `a_migration_connection_is_closed_outside_the_runner`, `a_failed_begin_leaves_the_connection_closed`, `internal_alter_functions_cannot_be_called_from_migration_sql`, `planted_trigger_and_view_cannot_call_a_denied_function`, `sqlite_dbpage_is_not_compiled_in`. The `_meta` statements (`tests/core_tables.rs`): `every_meta_statement_is_refused_in_a_migration` (11 statements, `main.` and other cases included, the epoch intact after each), `every_meta_write_is_refused_on_a_write_handle` (6), `a_trigger_that_writes_meta_is_refused_when_it_fires` (a trigger created by a migration, a planted one, and one fired inside the migration that creates it), with the control `without_the_authorizer_every_meta_statement_runs`, where a `DROP TABLE _meta` makes every later open fail with `MissingEpoch`. Extension loading statements: `no such function` (Deviations). No statement parser is built. |
| AC4 (AD-5) | **Pass** | `the_last_close_leaves_no_wal_content`: 20 writes put content in the WAL; the writer's close, with a reader still open, leaves a 0-byte WAL; the reader's close, the last one, removes the WAL. `a_reader_closing_last_leaves_no_wal_content`: a reader holding a snapshot keeps the writer's checkpoint from completing (WAL content remains after the writer's close); after the reader commits and closes last, no WAL content remains. |
| AC5 (AD-5) | **Pass** | `the_epoch_is_in_the_sidecar_and_in_meta` (sidecar text and `_meta` rows). `write_epoch_updates_both_and_leaves_no_staging_file` (no `.tmp` or `.next` left). `a_sidecar_that_disagrees_with_meta_fails_every_open`: `Error::EpochMismatch` naming both epochs on every role. `a_meta_that_disagrees_with_the_sidecar_fails_the_open`. `a_missing_or_malformed_epoch_fails_the_open` (`MalformedEpoch` for a bad or empty sidecar, `MissingEpoch`, `EpochSidecarMissing` for a removed sidecar). `create_refuses_an_existing_file_or_an_unexplained_sidecar`. `an_interrupted_create_is_discarded_by_the_next_one` (a staging file with and without a sidecar). `an_interrupted_change_of_epoch_fails_closed_with_both_epochs` (pending sidecar, `_meta` before and after the update, every role). `a_failed_change_of_epoch_leaves_the_previous_epoch`. `file::tests::the_sidecar_round_trips_and_refuses_any_other_shape` (10 refused shapes, CRLF and leading zeros included). |
| AC6 (D126, D127, D132, D136, E11, E17) | **Pass** | `every_role_reads_back_the_setup`: on the migration, write and read roles, `secure_delete` 1, `trusted_schema` off, `journal_size_limit` 0, `journal_mode` `wal`, `synchronous` 2, `foreign_keys` on, `temp_store` 0, `DEFENSIVE` on and the extension loading switch 0; `query_only` on for the read role only. `a_setting_that_reads_back_wrong_is_a_typed_error` (8 settings). `an_open_whose_setting_reads_back_wrong_fails`: a read handle on a file in rollback-journal mode gets `SetupMismatch { journal_mode, found: "delete" }`. `the_setup_pragmas_are_refused_once_the_authorizer_is_on`: with the authorizer installed first, `PRAGMA key` and every setup pragma are refused, which is why the setup comes first. Extension loading: see AC7 and Deviations. |
| AC7 (D126, E11) | **Pass, compiled out** | `extension_loading_is_compiled_out_and_temp_store_is_memory`: `OMIT_LOAD_EXTENSION` in `PRAGMA compile_options`, no `ENABLE_LOAD_EXTENSION`. `load_extension_is_no_such_function_on_every_connection`: `SELECT load_extension('x')` fails with `no such function` without the storage layer and on read and write handles, and fails on the closed migration handle too (as a refusal or `no such function`, the test accepts either). `nm` of `libsqlcipher.a` shows `sqlite3_db_config`, `sqlite3_key_v2` and `sqlite3_wal_checkpoint_v2`, and no `load_extension` symbol. `cargo tree -e features` shows no `load_extension` feature. Carrier of the flags: `build.rs` (Deviations). |
| AC8 (D126, I6) | **Pass** | `temp_store_is_refused_under_every_policy` (pragma allowlist). `every_engine_function_is_reviewed_exactly_once`: the engine's 127 functions are in exactly one list; it fails on an unreviewed function, which is how `json_array_insert` and `jsonb_array_insert` were found; and `load_extension` must be absent from the engine. `every_engine_module_is_reviewed_exactly_once`: the engine's 10 virtual table modules, likewise. `dbstat_is_refused` and `reads_of_denied_modules_are_refused`. `denied_functions_are_refused_and_classified_as_refusals`: `sqlcipher_export` and `fts5` on write and read handles fail as `Error::Refused` with `SQLITE_ERROR` and "not authorized to use function". `error::tests::an_authorizer_malfunction_is_a_refusal`. `internal_table_writes_are_refused_outside_migrations`. `a_statement_prepared_before_the_authorizer_is_rechecked`. Unit tests of the pure policy (`confinement_actions_are_denied_under_every_policy`, `each_policy_allows_only_its_own_actions`, `core_tables_are_written_only_under_the_core_policy`, `functions_are_matched_ignoring_case_and_unknown_ones_are_denied`). |
| AC9 (D126, D132) | **Pass** | `vacuum_runs_on_the_maintenance_path_only`: `VACUUM` is refused on a write handle and runs through `maintenance::vacuum`, rows kept, WAL empty after. `the_online_backup_writes_a_copy_with_its_sidecar`: 4-page steps while a writer is open; the copy is encrypted, opens through `open` with the same key and epoch, and holds the same rows; no partial file is left. `a_copy_never_replaces_an_existing_file_or_sidecar`. `a_failed_backup_leaves_no_partial_file` (wrong key). `a_copy_that_fails_late_leaves_no_partial_file` (the sidecar write fails after the partial file exists, for the backup and the file copy). `a_file_copy_needs_an_empty_wal_and_carries_the_sidecar`. No path uses `VACUUM INTO` or `ATTACH`. |
| AC10 (D132, E17) | **Pass** | `the_checkpoint_pragma_is_refused_on_every_handle`. `checkpoint_truncate_empties_the_wal_and_reports_a_busy_one`: after a deletion, with a reader holding a snapshot, `checkpoint_truncate` retries for at least the busy timeout and returns `CheckpointIncomplete`; once the reader commits it succeeds and the WAL is 0 bytes. `extension_loading_is_compiled_out_and_temp_store_is_memory` (`TEMP_STORE=2`) and `a_keyed_connection_keeps_the_build_temp_store` (`temp_store` 0 on every role). |
| AC11 (AD-4, E11) | **Pass** | `the_key_text_is_one_buffer_of_its_final_size`: the `x'...'` text is a `Zeroizing<Vec<u8>>` (typed in the test, so a plain `Vec` does not compile) whose capacity equals its length, so no reallocation left a copy. `no_product_source_keys_through_sql_text`. `the_key_is_never_printed`: a handle's `Debug` and an error hold neither the key nor its hex form. `error::tests::neither_display_nor_debug_prints_the_sql_text`. The spike's `apply_raw_key` is not reused. |

Mutations, each on a copy of the repository with a dedicated target directory, every restored file given a new modification time so each mutation rebuilds. The unmutated copy passed all 74 storage tests and the Python suite in the same setup. Each mutation made the named tests fail, 56 of 56:
- **Authorizer:**
  - read policy allowing `INSERT`: `each_runtime_role_runs_only_its_own_statements`;
  - unknown actions allowed (`ATTACH`, `DETACH`, virtual tables): the write and migration hostile replays and `confinement_actions_are_denied_under_every_policy`;
  - every pragma allowed: the read replay, `the_checkpoint_pragma_is_refused_on_every_handle`, `temp_store_is_refused_under_every_policy`;
  - `query_only` allowed: `query_only_cannot_be_turned_off_on_a_read_handle`;
  - `sqlcipher_export` allowlisted: `denied_functions_are_refused_and_classified_as_refusals`, `every_engine_function_is_reviewed_exactly_once`;
  - internal tables writable on write handles: `internal_table_writes_are_refused_outside_migrations` and the write replay;
  - transaction control allowed in migrations: `transaction_control_inside_a_migration_is_refused`;
  - the migration connection opened under the migration policy: `a_migration_connection_is_closed_outside_the_runner`;
  - the runner not closing the connection after a failure: that test and `a_failed_begin_leaves_the_connection_closed`;
  - the function denial not classified as a refusal: `denied_functions_are_refused_and_classified_as_refusals`, `planted_trigger_and_view_cannot_call_a_denied_function`;
  - an authorizer malfunction not classified as a refusal: `an_authorizer_malfunction_is_a_refusal`;
  - denied modules readable: `dbstat_is_refused`, `reads_of_denied_modules_are_refused`;
  - `dbstat` dropped from the reviewed modules: `every_engine_module_is_reviewed_exactly_once`, `dbstat_is_refused`.
- **Core tables (M1):**
  - `_meta` writable on write handles: `every_meta_write_is_refused_on_a_write_handle`, `a_trigger_that_writes_meta_is_refused_when_it_fires`, `core_tables_are_written_only_under_the_core_policy`;
  - `_meta` writable in migrations: `every_meta_statement_is_refused_in_a_migration`;
  - schema changes on `_meta` allowed: the same test;
  - the epoch policy (now `Policy::Core`, Story 3.2) writing any table: `core_tables_are_written_only_under_the_core_policy`;
  - `write_epoch` under the write policy: `write_epoch_updates_both_and_leaves_no_staging_file`.
- **Setup:** `secure_delete` FAST, `trusted_schema` left on, `DEFENSIVE` not enabled, `synchronous` NORMAL, and the authorizer installed before the setup each make `every_role_reads_back_the_setup` fail. The read-back removed from `connect`: `an_open_whose_setting_reads_back_wrong_fails`. A first run showed this one undetected, so that test was added. A first `synchronous` mutation, removing the pragma, was equivalent to the original, since the build already defaults to FULL; it was replaced by NORMAL.
- **Epoch and keys:**
  - epoch mismatch ignored: both mismatch tests;
  - a pending sidecar ignored: `an_interrupted_change_of_epoch_fails_closed_with_both_epochs`;
  - a failed change of epoch keeping its pending sidecar: `a_failed_change_of_epoch_leaves_the_previous_epoch`;
  - an interrupted `create` not discarded: `an_interrupted_create_is_discarded_by_the_next_one`;
  - an unexplained sidecar accepted by `create`: `create_refuses_an_existing_file_or_an_unexplained_sidecar`;
  - a missing sidecar left as an I/O error: `a_missing_or_malformed_epoch_fails_the_open`;
  - wrong key not mapped to `WrongKey`: `another_key_fails_without_exposing_content`;
  - the key passed as a passphrase (no `x'...'`): `the_file_is_keyed_with_the_raw_key_not_a_passphrase_kdf`;
  - the key text as a plain `Vec`: compile error in `the_key_text_is_one_buffer_of_its_final_size`;
  - the key buffer allocated small: the same test fails;
  - SQL text in an error's `Display` and `Debug`: `neither_display_nor_debug_prints_the_sql_text`.
- **Checkpoints:**
  - no checkpoint at close: `the_last_close_leaves_no_wal_content`;
  - read handles opened with `SQLITE_OPEN_READONLY`: `a_reader_closing_last_leaves_no_wal_content`;
  - a busy checkpoint reported as done: `checkpoint_truncate_empties_the_wal_and_reports_a_busy_one`;
  - PASSIVE instead of TRUNCATE: that test and `the_last_close_leaves_no_wal_content`.
- **Maintenance:**
  - the file copy ignoring the WAL: `a_file_copy_needs_an_empty_wal_and_carries_the_sidecar`;
  - a copy over an existing destination: `a_copy_never_replaces_an_existing_file_or_sidecar`;
  - the partial file left after a failed backup, and after a failed file copy: `a_copy_that_fails_late_leaves_no_partial_file`. A first run showed the backup case undetected: `a_failed_backup_leaves_no_partial_file` fails before any partial file exists, so the late-failure test was added;
  - a copy without its sidecar: `the_online_backup_writes_a_copy_with_its_sidecar`, `a_file_copy_needs_an_empty_wal_and_carries_the_sidecar`.
- **Build:**
  - extension loading compiled back in: `extension_loading_is_compiled_out_and_temp_store_is_memory`, `load_extension_is_no_such_function_on_every_connection`, `every_engine_function_is_reviewed_exactly_once`;
  - compiled back in with the FFI switch call removed: `every_role_reads_back_the_setup` (the switch reads 1);
  - `SQLITE_TEMP_STORE=3`: the temp store test;
  - `SQLITE_TEMP_STORE=1`: SQLCipher's own `#error` stops the build;
  - `SQLITE_DEFAULT_FOREIGN_KEYS=1` dropped: `every_role_reads_back_the_setup`;
  - the stack protector replaced by `-fno-stack-protector`: `the_library_is_compiled_with_the_stack_protector`.
- **Pins and CI:**
  - one hostile statement edited in the copy: `the_hostile_lists_are_the_spike_file_unchanged`;
  - `TAG` moved in `regenerate.sh`: `the_engine_is_the_pinned_sqlcipher_on_openssl`;
  - `REPOSITORY` pointed at a fork: `test_check_sqlcipher_source.TreeTest`;
  - the `sqlcipher-regenerate` job renamed away, or its step made `if: false`: `WorkflowAgreementTest`;
  - the OpenSSL check removed from `build-and-test`: `WorkflowAgreementTest`.
- **By hand:**
  - one byte of the real `sqlite3.c` changed: `ci/check_sqlcipher_source.py` reports the SHA-256 differing from `SHA256SUMS`, exit 1;
  - the review's M2 case, that byte changed together with its hash in `SHA256SUMS` and the README: `ci/check_sqlcipher_source.py` passes, and `regenerate.sh` fails, `the amalgamation generated from v4.19.0 differs from SHA256SUMS`, exit 1.
