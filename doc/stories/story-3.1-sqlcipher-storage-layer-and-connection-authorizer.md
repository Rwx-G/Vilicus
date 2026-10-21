---
title: 'SQLCipher storage layer and connection authorizer'
epic: 3
story: 1
status: review
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
- Rule applied: a security fix was found, so the self-built path. The owner chose SQLCipher 4.19.0, self-built and pinned (D143, recorded by the coordinator).
- What Vilicus was exposed to: the connection authorizer refuses `sqlcipher_export` on every connection, and no maintenance operation calls it. The flaw was therefore not reachable from SQL this layer runs. The upgrade removes the dependency on that single layer.

**What was built**
- `crates/vilicus-storage/sqlcipher/`, the vendored source:
  - `sqlite3.c`: the SQLCipher 4.19.0 amalgamation (SQLite 3.53.4 inside), generated from tag `v4.19.0` (tag object `58beb4a3...`, commit `c4b275a4...`).
  - `LICENSE.md` (BSD-3-Clause, Zetetic LLC) and `SQLITE_LICENSE.md` (public domain), copied from the tag.
  - `SHA256SUMS`.
  - `README.md`: origin, ids, hashes and how to regenerate.
  - `regenerate.sh`: clones the tag, checks both object ids, runs `configure` and `make sqlite3.c`, and compares the result with `SHA256SUMS`; `--write` is the upgrade path.
  - Generation needs no tclsh: SQLite's build compiles its bundled `jimsh`. Two runs, from different directories and with and without the `configure` options, gave the same `sqlite3.c`. The files are `-text` in `.gitattributes`.
- `crates/vilicus-storage/build.rs`:
  - compiles `sqlcipher/sqlite3.c` with the system `cc` and archives it with `ar` (std `Command` only, no new crate);
  - links the archive with `static:+whole-archive=sqlcipher`, puts it on the search path, and links the system `libcrypto` after it;
  - `links = "vilicus-sqlcipher"` in the manifest keeps a second copy out of a build graph.
- Defines, reproduced from `libsqlite3-sys` 0.38.2 `bundled-sqlcipher`, which the E11 and E17 spikes ran on:
  - `SQLITE_CORE`, `SQLITE_DEFAULT_FOREIGN_KEYS=1`, `SQLITE_ENABLE_API_ARMOR`, `SQLITE_ENABLE_COLUMN_METADATA`, `SQLITE_ENABLE_DBSTAT_VTAB`;
  - `SQLITE_ENABLE_FTS3`, `SQLITE_ENABLE_FTS3_PARENTHESIS`, `SQLITE_ENABLE_FTS5`, `SQLITE_ENABLE_JSON1`, `SQLITE_ENABLE_MEMORY_MANAGEMENT`, `SQLITE_ENABLE_RTREE`, `SQLITE_ENABLE_STAT4`;
  - `SQLITE_SOUNDEX`, `SQLITE_THREADSAFE=1`, `SQLITE_USE_URI`, `HAVE_USLEEP=1`, `HAVE_ISNAN`, `_POSIX_THREAD_SAFE_FUNCTIONS`, `HAVE_LOCALTIME_R`;
  - for SQLCipher: `SQLITE_HAS_CODEC`, `SQLITE_TEMP_STORE=2`, `SQLITE_EXTRA_INIT=sqlcipher_extra_init`, `SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown`, `HAVE_STDINT_H=1`.
- Defines that change:
  - `SQLITE_ENABLE_LOAD_EXTENSION=1` is replaced by `SQLITE_OMIT_LOAD_EXTENSION` (AC7);
  - `SQLCIPHER_CRYPTO_OPENSSL` is added; it is SQLCipher's default provider, now named explicitly.
- Optimisation and debug info follow cargo's `OPT_LEVEL` and `DEBUG`, as the `cc` crate would. `-fPIC -ffunction-sections -fdata-sections`.
- `CFLAGS` and `LIBSQLITE3_FLAGS` are not read. The build script passes its defines to the test binary, so a test compares them with `PRAGMA compile_options`.
- `crates/vilicus-storage/src/`:
  - `ffi.rs`: the only `unsafe`, four functions, each allowed locally with a `// SAFETY:` comment (D140):
    - `sqlite3_db_config(SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION)`, set and read;
    - `sqlite3_key_v2`, keying from a byte buffer;
    - `sqlite3_wal_checkpoint_v2(TRUNCATE)`, returning busy as a value.
  - `authorizer.rs`: the E11 policies (`Closed`, `Migration`, `Write`, `Read`), `authorize` as a pure function, and the lists moved from the spike:
    - `INTROSPECTION_PRAGMAS`, `ALLOWED_FUNCTIONS`, `INTERNAL_ALTER_FUNCTIONS`, `MIGRATION_INTERNAL_TABLES`;
    - `DENIED_FUNCTIONS` and `COMPILED_OUT_FUNCTIONS`, test-only, since the policy never reads them.
    - SQLite 3.53 adds `json_array_insert` and `jsonb_array_insert`. The coverage test named them, and they are allowed after review: they compute on their arguments like `json_insert`.
  - `file.rs`:
    - `Partition` (`Household`, `Home`, `Member(Id)`, written `household`, `home` or the id text);
    - `ModuleFile` (directory, `ModuleName`, partition), which gives `<module>.<partition>.db`, `<file>.epoch` and `<file>-wal`;
    - `KeyEpoch { partition_root_version, generation }` (`u32` each). The sidecar is a three-line text format with one canonical form: `vilicus key epoch 1`, then `partition_root_version <n>`, then `generation <m>`.
    - `read_epoch`. The sidecar is written atomically: temporary file, `fsync`, rename, directory `fsync`.
  - `handle.rs`: `open::<R>(file, key)`, `create(file, key, epoch)`, `Handle<R>` for the roles `Read`, `Write` and `Migration` (sealed marker types), and `Settings`.
    - Setup order (AC6):
      1. open read-write without `SQLITE_OPEN_URI`, busy timeout `BUSY_TIMEOUT` (100 ms, `[ASSUMPTION]`);
      2. extension loading API off;
      3. key through `sqlite3_key_v2` with the `x'<hex>'` form;
      4. the schema read that turns a wrong key into `Error::WrongKey`;
      5. `trusted_schema` off, `secure_delete` ON, `journal_size_limit` 0, `journal_mode` WAL on writers, `synchronous` FULL, `query_only` on readers;
      6. `SQLITE_DBCONFIG_DEFENSIVE` on;
      7. everything read back, with `foreign_keys` 1 and `temp_store` 0 too, and checked (`Error::SetupMismatch`);
      8. the epoch of the sidecar against `_meta` (`Error::EpochMismatch`);
      9. the role's opening policy, `Closed` for migration.
    - A handle exposes `prepare`, `execute`, `execute_batch`, `query_row`, `checkpoint_truncate` and `close`, never its `Connection`. `Handle<Write>::write_epoch` writes `_meta`, then the sidecar. `Handle<Migration>::apply_migration` is the spike's runner.
    - `close` and `Drop` run one TRUNCATE checkpoint, then close. A busy checkpoint means another connection is open, so this one is not the last.
    - `checkpoint_truncate` retries up to 10 times, until not busy and the WAL file is empty, then returns `Error::CheckpointIncomplete`.
  - `maintenance.rs` (AC9), each function opening its own connection, set up like a writer with no authorizer, and closing it:
    - `copy_file`: a plain copy, refused while the WAL holds content, synced;
    - `backup`: the online backup API in bounded steps into a new file under the same key;
    - `vacuum`.
  - `error.rs`: `Error` and `is_refusal`, which classifies `SQLITE_AUTH` and the `SQLITE_ERROR` "not authorized to use function", in both `SqliteFailure` and `SqlInputError` (AC8). `Display` leaves out the SQL text `rusqlite` would print.
  - `tests/`: 55 tests with the crate's unit tests (Result). `tests/hostile.rs` is a byte-for-byte copy of `spikes/sqlite-authorizer/src/hostile.rs`, and a test compares the two files.
- `ci/check_sqlcipher_source.py` and `ci/test_check_sqlcipher_source.py`, run in `workspace-policy`, pinned in `WorkflowAgreementTest`. They fail when:
  - a file differs from `SHA256SUMS`, or `SHA256SUMS` is malformed or uses CRLF;
  - a file in the directory is not listed;
  - `build.rs` compiles a file that is not listed;
  - `regenerate.sh` names another version than the amalgamation;
  - the README does not state the pinned tag, ids or hashes.
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
- *`cc` and `ar` through `std::process`, not the `cc` crate*: the brief forbids new direct dependencies, `cc` included. What it gives up: no cross-compilation, which the script refuses explicitly (native Unix target only), and no MSVC.
- *Read handles opened read-write with `query_only`* (see `handle.rs`): a `SQLITE_OPEN_READONLY` connection cannot checkpoint, so a reader that closes last would leave WAL content and break AC4. The authorizer and `query_only` both still refuse writes. What it gives up: the read-only open flag as a third guard.
- *Keying through `sqlite3_key_v2`, not `PRAGMA key`* (AC11): the SQL text of a `PRAGMA key` stays in SQLite's statement memory unwiped, and `rusqlite` copies it into `SqlInputError`. The C call reads the buffer and SQLCipher copies it into its own context. A test checks that no product source builds `PRAGMA key` text.
- *`_meta` is a key-value table* (`key TEXT PRIMARY KEY, value INTEGER`, `STRICT`, `WITHOUT ROWID`), so the schema versions of AD-26 join it as rows in Story 3.2 without a migration.
- *`write_epoch` writes `_meta`, then the sidecar*: a crash between the two leaves them disagreeing, and the next open fails with a typed error instead of using either.
- *Busy timeout 100 ms*, `[ASSUMPTION]`: `rusqlite`'s default is 5 s, and D136 wants a checkpoint that meets a reader to fail fast and be retried. One writer per file means writers do not wait on each other.

**Files**
- `crates/vilicus-storage/`: `Cargo.toml`, `build.rs`, `sqlcipher/` (6 files), `src/lib.rs`, `src/ffi.rs`, `src/authorizer.rs`, `src/error.rs`, `src/file.rs`, `src/handle.rs`, `src/maintenance.rs`, `src/tests/` (`mod.rs`, `engine.rs`, `hostile.rs`, `maintenance.rs`, `replay.rs`, `setup.rs`)
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

**Open points**
- *D143 and the Stack row* (coordinator): the decision text and the Stack row change are in the report to the coordinator, not in the design documents.
- *Binary licence notice* (Story 5.7): SQLCipher's BSD-3-Clause requires binary redistributions to reproduce its notice. The `.deb` must carry `crates/vilicus-storage/sqlcipher/LICENSE.md`.
- *SQLCipher's own log*: on a wrong key, SQLCipher writes `ERROR CORE sqlite3Codec: error decrypting page 1 data` lines to stderr (seen in the test runs). The text holds no secret. Routing or silencing it (`PRAGMA cipher_log`, `cipher_log_level`, which go through the authorizer and would join the setup) belongs to the logging story.
- *CI OpenSSL*: the GitHub `ubuntu-24.04` runner (image 20261012.334.1) ships `libssl-dev` 3.0.13 and `pkg-config`, and no SQLCipher package (runner image readme), so no install step was added. The build and the storage tests pass in an `ubuntu:24.04` container against OpenSSL 3.0.13. The target is Debian 13's 3.5.7. The engine test asserts an OpenSSL 3 provider, not a minor version.
- *`vilicus` does not link SQLCipher yet*: `vilicus-core` does not use `vilicus-storage`, so `rustc` leaves it out of the binary (`ldd` shows no `libcrypto`). The first Core story that opens a file brings the link and its runtime dependency on `libcrypto.so.3`.
- *`Partition` lives in `vilicus-storage`*: if another crate needs the partition names, it moves to `vilicus-types`.
- *Owner review of 4 new exemptions*: `cargo vet` suggests `cargo vet inspect rusqlite 0.40.2` (23 729 lines) and `libsqlite3-sys 0.38.2` (598 760 lines, almost all the unused bundled amalgamations).
- *E15 and D127* (defensive mode with FTS5 shadow tables): Story 3.7.

## Result

All commands ran on 2026-10-21 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch made inside the container, with an empty target directory. Mutations ran on a copy with their own target directory, never on the working tree.

Engine, as the tests print it: SQLite 3.53.4, SQLCipher 4.19.0 community, OpenSSL 3.5.7 (Debian 13). On `ubuntu:24.04` with `libssl-dev` 3.0.13: the same engine on OpenSSL 3.0.13, 55 storage tests passed.

Gates, as `.github/workflows/ci.yml` runs them:
- `python3 -m unittest discover -s ci`: `Ran 208 tests`, `OK` (198 before; 10 in `ci/test_check_sqlcipher_source.py`).
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`. Before the allowlist entries it named `libsqlite3-sys 0.38.2` and `vilicus-storage 0.0.0` build scripts.
- `python3 ci/check_supply_chain.py --vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 180 tests passed, none failed (125 before; `vilicus-storage` 55).
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`. Before: `9 unvetted dependencies`.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `bash crates/vilicus-storage/sqlcipher/regenerate.sh` (needs the network, not a CI gate): `SQLCipher v4.19.0 (c4b275a47932888216bade83aff2bbc73df0ff85) regenerates to the files of SHA256SUMS`, exit 0.
- `cargo tree --workspace -e features -i rusqlite`: features `backup`, `hooks`, `modern_sqlite`, `sqlcipher`; `load_extension` appears nowhere (0 lines).

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (AD-5, D2, D3) | **Pass** | `file::tests::a_file_is_named_module_dot_partition_dot_db` (`tasks.household.db`, `tasks.home.db`, `tasks.<member id>.db`, and the `.epoch` sidecar). `create_writes_an_encrypted_file_named_module_dot_partition`: no plaintext header, and a marker row is absent from the raw bytes. `the_file_is_keyed_with_the_raw_key_not_a_passphrase_kdf`: the same 64 hex digits given as a passphrase do not open the file, the `x'...'` form does. `another_key_fails_without_exposing_content`: every role gets `Error::WrongKey`, whose `Display` and `Debug` hold neither the marker nor a table name. |
| AC2 (AD-9, I6) | **Pass** | `each_runtime_role_runs_only_its_own_statements`: a read handle runs `SELECT` (with functions, in an explicit read transaction) and the introspection pragmas, and refuses `INSERT`, `UPDATE`, `DELETE` and `CREATE TABLE` as refusals. A write handle refuses DDL, `VACUUM` and `INSERT INTO sqlite_sequence`. The 25 hostile statements on a read handle, below. |
| AC3 (AD-5, AD-9, I6, E11, FR-23) | **Pass** | `the_hostile_lists_are_the_spike_file_unchanged` compares the bytes of `src/tests/hostile.rs` with the spike's file. `every_hostile_statement_is_refused_in_a_migration_and_nothing_is_written`: the 23 statements, each ending a migration; file bytes, directory, schema and rows unchanged. `hostile_statements_are_refused_on_a_read_connection_and_select_succeeds` and `..._on_a_write_connection_...`: the 23 plus the 2 runtime statements, each followed by a `SELECT` that succeeds, file and directory unchanged. Controls: `without_the_authorizer_no_hostile_statement_is_an_auth_refusal`, `without_the_authorizer_a_plaintext_copy_can_be_written`, `without_the_authorizer_vacuum_into_writes_a_copy`. Also `transaction_control_inside_a_migration_is_refused`, `temporary_objects_and_virtual_tables_are_refused_in_a_migration`, `an_ordinary_migration_applies_under_the_authorizer`, `a_refused_migration_leaves_the_connection_usable`, `a_migration_connection_is_closed_outside_the_runner`, `a_failed_begin_leaves_the_connection_closed`, `internal_alter_functions_cannot_be_called_from_migration_sql`, `planted_trigger_and_view_cannot_call_a_denied_function`, `sqlite_dbpage_is_not_compiled_in`. Extension loading statements: `no such function` (Deviations). No statement parser is built. |
| AC4 (AD-5) | **Pass** | `the_last_close_leaves_no_wal_content`: 20 writes put content in the WAL; the writer's close, with a reader still open, leaves a 0-byte WAL; the reader's close, the last one, removes the WAL. `a_reader_closing_last_leaves_no_wal_content`: a reader holding a snapshot keeps the writer's checkpoint from completing (WAL content remains after the writer's close); after the reader commits and closes last, no WAL content remains. |
| AC5 (AD-5) | **Pass** | `the_epoch_is_in_the_sidecar_and_in_meta` (sidecar text and `_meta` rows). `write_epoch_updates_both_and_leaves_no_staging_file`. `a_sidecar_that_disagrees_with_meta_fails_every_open`: `Error::EpochMismatch` naming both epochs on every role. `a_meta_that_disagrees_with_the_sidecar_fails_the_open`. `a_missing_or_malformed_epoch_fails_the_open` (`MalformedEpoch`, `MissingEpoch`). `create_refuses_an_existing_file_or_sidecar`. `file::tests::the_sidecar_round_trips_and_refuses_any_other_shape` (10 refused shapes, CRLF and leading zeros included). |
| AC6 (D126, D127, D132, D136, E11, E17) | **Pass** | `every_role_reads_back_the_setup`: on the migration, write and read roles, `secure_delete` 1, `trusted_schema` off, `journal_size_limit` 0, `journal_mode` `wal`, `synchronous` 2, `foreign_keys` on, `temp_store` 0, `DEFENSIVE` on and the extension loading switch 0; `query_only` on for the read role only. `a_setting_that_reads_back_wrong_is_a_typed_error` (8 settings). `an_open_whose_setting_reads_back_wrong_fails`: a read handle on a file in rollback-journal mode gets `SetupMismatch { journal_mode, found: "delete" }`. `the_setup_pragmas_are_refused_once_the_authorizer_is_on`: with the authorizer installed first, `PRAGMA key` and every setup pragma are refused, which is why the setup comes first. Extension loading: see AC7 and Deviations. |
| AC7 (D126, E11) | **Pass, compiled out** | `extension_loading_is_compiled_out_and_temp_store_is_memory`: `OMIT_LOAD_EXTENSION` in `PRAGMA compile_options`, no `ENABLE_LOAD_EXTENSION`. `load_extension_is_no_such_function_on_every_connection`: `SELECT load_extension('x')` fails with `no such function` without the storage layer and on read and write handles, and fails on the closed migration handle too (as a refusal or `no such function`, the test accepts either). `nm` of `libsqlcipher.a` shows `sqlite3_db_config`, `sqlite3_key_v2` and `sqlite3_wal_checkpoint_v2`, and no `load_extension` symbol. `cargo tree -e features` shows no `load_extension` feature. Carrier of the flags: `build.rs` (Deviations). |
| AC8 (D126, I6) | **Pass** | `temp_store_is_refused_under_every_policy` (pragma allowlist). `every_engine_function_is_reviewed_exactly_once`: the engine's 127 functions are in exactly one list; it fails on an unreviewed function, which is how `json_array_insert` and `jsonb_array_insert` were found; and `load_extension` must be absent from the engine. `denied_functions_are_refused_and_classified_as_refusals`: `sqlcipher_export` and `fts5` on write and read handles fail as `Error::Refused` with `SQLITE_ERROR` and "not authorized to use function". `internal_table_writes_are_refused_outside_migrations`. `a_statement_prepared_before_the_authorizer_is_rechecked`. Unit tests of the pure policy (`confinement_actions_are_denied_under_every_policy`, `each_policy_allows_only_its_own_actions`, `functions_are_matched_ignoring_case_and_unknown_ones_are_denied`). |
| AC9 (D126, D132) | **Pass** | `vacuum_runs_on_the_maintenance_path_only`: `VACUUM` is refused on a write handle and runs through `maintenance::vacuum`, rows kept, WAL empty after. `the_online_backup_writes_a_copy_under_the_same_key`: 4-page steps while a writer is open, the copy encrypted, same rows, an existing destination refused. `a_file_copy_needs_an_empty_wal`: refused with an open writer's WAL content, done after the close. No path uses `VACUUM INTO` or `ATTACH`. |
| AC10 (D132, E17) | **Pass** | `the_checkpoint_pragma_is_refused_on_every_handle`. `checkpoint_truncate_empties_the_wal_and_reports_a_busy_one`: after a deletion, with a reader holding a snapshot, `checkpoint_truncate` retries for at least the busy timeout and returns `CheckpointIncomplete`; once the reader commits it succeeds and the WAL is 0 bytes. `extension_loading_is_compiled_out_and_temp_store_is_memory` (`TEMP_STORE=2`) and `a_keyed_connection_keeps_the_build_temp_store` (`temp_store` 0 on every role). |
| AC11 (AD-4, E11) | **Pass** | `the_key_text_is_one_buffer_of_its_final_size`: the `x'...'` text is a `Zeroizing<Vec<u8>>` (typed in the test, so a plain `Vec` does not compile) whose capacity equals its length, so no reallocation left a copy. `no_product_source_keys_through_sql_text`. `the_key_is_never_printed`: a handle's `Debug` and an error hold neither the key nor its hex form. The spike's `apply_raw_key` is not reused. |

Mutations, each on a copy of the crate with a dedicated target directory, every restored file given a new modification time so each mutation rebuilds. The unmutated copy passed all 55 tests in the same setup. Each mutation made the named tests fail, 32 of 32:
- **Authorizer:**
  - read policy allowing `INSERT`: `each_runtime_role_runs_only_its_own_statements`;
  - unknown actions allowed (`ATTACH`, `DETACH`, virtual tables): the write and migration hostile replays and `confinement_actions_are_denied_under_every_policy`;
  - every pragma allowed: the read replay, `the_checkpoint_pragma_is_refused_on_every_handle`, `temp_store_is_refused_under_every_policy`;
  - `sqlcipher_export` allowlisted: `denied_functions_are_refused_and_classified_as_refusals`, `every_engine_function_is_reviewed_exactly_once`;
  - internal tables writable on write handles: `internal_table_writes_are_refused_outside_migrations` and the write replay;
  - transaction control allowed in migrations: `transaction_control_inside_a_migration_is_refused`;
  - the migration connection opened under the migration policy: `a_migration_connection_is_closed_outside_the_runner`;
  - the runner not closing the connection after a failure: that test and `a_failed_begin_leaves_the_connection_closed`;
  - the function denial not classified as a refusal: `denied_functions_are_refused_and_classified_as_refusals`, `planted_trigger_and_view_cannot_call_a_denied_function`.
- **Setup:** `secure_delete` FAST, `trusted_schema` left on, `DEFENSIVE` not enabled, `synchronous` NORMAL, and the authorizer installed before the setup each make `every_role_reads_back_the_setup` fail. The read-back removed from `connect`: `an_open_whose_setting_reads_back_wrong_fails`. A first run showed this one undetected, so that test was added. A first `synchronous` mutation, removing the pragma, was equivalent to the original, since the build already defaults to FULL; it was replaced by NORMAL.
- **Epoch and keys:**
  - epoch mismatch ignored: both mismatch tests;
  - wrong key not mapped to `WrongKey`: `another_key_fails_without_exposing_content`;
  - the key passed as a passphrase (no `x'...'`): `the_file_is_keyed_with_the_raw_key_not_a_passphrase_kdf`;
  - the key text as a plain `Vec`: compile error in `the_key_text_is_one_buffer_of_its_final_size`;
  - the key buffer allocated small: the same test fails.
- **Checkpoints:**
  - no checkpoint at close: `the_last_close_leaves_no_wal_content`;
  - read handles opened with `SQLITE_OPEN_READONLY`: `a_reader_closing_last_leaves_no_wal_content`;
  - a busy checkpoint reported as done: `checkpoint_truncate_empties_the_wal_and_reports_a_busy_one`;
  - PASSIVE instead of TRUNCATE: that test and `the_last_close_leaves_no_wal_content`.
- **Maintenance:** the file copy ignoring the WAL: `a_file_copy_needs_an_empty_wal`.
- **Build:**
  - extension loading compiled back in: `extension_loading_is_compiled_out_and_temp_store_is_memory`, `load_extension_is_no_such_function_on_every_connection`, `every_engine_function_is_reviewed_exactly_once`;
  - compiled back in with the FFI switch call removed: `every_role_reads_back_the_setup` (the switch reads 1);
  - `SQLITE_TEMP_STORE=3`: the temp store test;
  - `SQLITE_TEMP_STORE=1`: SQLCipher's own `#error` stops the build;
  - `SQLITE_DEFAULT_FOREIGN_KEYS=1` dropped: `every_role_reads_back_the_setup`.
- **Pins:**
  - one hostile statement edited in the copy: `the_hostile_lists_are_the_spike_file_unchanged`;
  - `TAG` moved in `regenerate.sh`: `the_engine_is_the_pinned_sqlcipher_on_openssl`;
  - one byte of the real `sqlite3.c` changed: `ci/check_sqlcipher_source.py` reports the SHA-256 differing from `SHA256SUMS`, exit 1.
