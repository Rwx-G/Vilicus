---
title: 'E11: SQLite migration authorizer'
epic: 1
story: 7
status: 'done'
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

## Implementation Notes

**What was built.** A standalone crate, `spikes/sqlite-authorizer/` (own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`), never part of the product workspace.

- `src/lib.rs`:
  - **Policies.** The authorizer is a pure function, `authorize(policy, context)`, with four policies: `Closed` (denies everything), `Migration`, `Write` and `Read`. Under each policy, any action not explicitly allowed is denied, including action codes the binding does not know.
  - **Pragmas.** Limited to `INTROSPECTION_PRAGMAS` (read-only schema introspection, matched ignoring case).
  - **Functions.** Allowlisted in `ALLOWED_FUNCTIONS`, the reviewed built-ins. `DENIED_FUNCTIONS` records the built-ins reviewed and left out; the policy never reads it. A test fails when the engine offers a function that is in neither list. The migration policy also allows `INTERNAL_ALTER_FUNCTIONS`, which `ALTER TABLE` calls internally (finding 9).
  - **Internal tables.** Row writes to SQLite's internal tables (`sqlite_` prefix) are refused, except `MIGRATION_INTERNAL_TABLES` under the migration policy (finding 9).
  - **`open()`.** In order: turns off the extension loading C API; keys the file with a raw 256-bit key (`x'...'` form, no SQLCipher KDF); sets `secure_delete` on and `trusted_schema` off, plus WAL for writers; installs the role's opening policy. A migration connection opens `Closed`.
  - **`apply_migration()`.** Opens the transaction with the authorizer removed and runs the migration SQL under `Migration`, which refuses transaction control. It rolls back on error, and on every exit (success, failure, or a failed `BEGIN`) leaves the connection `Closed`.
  - **`is_authorizer_denial()`.** Classifies a refusal (finding 2).
- `src/hostile.rs`:
  - The hostile statement set as data. `HOSTILE_STATEMENTS` (23 statements) covers attach, detach, unsafe pragma, extension loading and copy out. `RUNTIME_HOSTILE_STATEMENTS` (2 statements) writes to `sqlite_sequence`, which the migration policy must allow (finding 9).
  - A `{dir}` placeholder, filled through `escape_for_sql_string`, means anything that slipped through would write only into a scratch directory.
  - Kept for Story 3.1 to replay unchanged.
- Tests (28 functions; they iterate over the hostile constants and never retype them):
  - unit tests of the pure policy;
  - `tests/migration.rs` (AC1, closed migration connections, the failed `BEGIN`);
  - `tests/runtime.rs` (AC2, AD-5, setup pragmas, planted schema objects);
  - `tests/extension_api.rs` (extension loading through the C API);
  - `tests/function_list.rs` (allowlist coverage);
  - `tests/control.rs` (the same statements without the authorizer).
- `Dockerfile`: `rust:1.99-trixie` pinned by digest `sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a`, plus clippy and rustfmt.
- `run.sh`:
  - builds the image and mounts the crate read-only;
  - keeps the target directory and the cargo registry in named Docker volumes (`vilicus-sqlite-authorizer-target`, `vilicus-cargo-registry`);
  - prints one `PASS` or `FAIL` line per check;
  - fails when a test is ignored or the number of passing tests differs from `EXPECTED_TESTS` (28);
  - ends with `RESULT PASS` or `RESULT FAIL`, with a non-zero exit on any failure.

**Dependencies.**
- Direct: one, `rusqlite` `=0.40.2`, default features off, with `bundled-sqlcipher` (compiles the SQLCipher amalgamation shipped with `libsqlite3-sys` and links the system libcrypto) and `hooks` (the authorizer API). `rusqlite` is MIT, compatible with Apache-2.0.
- Resolved: `libsqlite3-sys` 0.38.2, `bitflags` 2.13.2, `fallible-iterator` 0.3.0, `fallible-streaming-iterator` 0.1.9, `smallvec` 1.16.3. Build only: `cc` 1.8.0, `pkg-config` 0.3.34, `vcpkg` 0.2.15.
- Engine, as reported at run time: SQLite 3.51.3, SQLCipher 4.14.0 community, crypto provider OpenSSL 3.5.7 (Debian 13 `libssl3`).
- Toolchain: rustc 1.99.1, a patch release above the spine's 1.99.0.

**Decision tasks.** The story carries none. The SQLCipher version decision belongs to Story 3.1; this spike ran on the bundled 4.14.0 the spine names and does not settle it.

**Deviations.**

- Location: the story names `spikes/e11-authorizer/`; the spike lives in `spikes/sqlite-authorizer/` as the epic's spike instructions asked.
- Scope: AC2 names a read connection; the hostile set also runs on a write connection, because AD-5 requires the authorizer on every connection the Core opens. The refused set also covers:
  - in a migration: transaction control, temporary objects and virtual tables;
  - on a migration connection outside the runner: everything.

  Allowed statements were checked on each role, to show that the policy refuses without breaking ordinary work.
- Native Windows build not attempted: `bundled-sqlcipher` needs an OpenSSL for the target. The crate is built and run only in the Linux container.

**Not for Story 3.1 as is.** `apply_raw_key` builds the key as a hex `String` and embeds it in the SQL text of `PRAGMA key`; neither is zeroized. That is acceptable for a spike with a fixed test key. It must not be copied into `vilicus-storage`, where key material is zeroized on drop and kept out of logs (`doc/architecture.md` section 4).

**Findings.**

1. **The extension loading C API is on by default on this build.**
   - **Cause.** `libsqlite3-sys` 0.38.2 compiles the bundled SQLCipher with `-DSQLITE_ENABLE_LOAD_EXTENSION=1`, which sets `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` on every new connection. `sqlite3_load_extension` then reaches the dynamic loader (`control.load_extension_api_on_by_default_in_bundled_build`).
   - **Consequence.** The authorizer never sees this C call, so D21's "extension loading disabled" is not true by default. The SQL function `load_extension()` is governed by a separate flag and is off by default.
   - **What the spike does.** `open()` turns the C API off through `sqlite3_db_config`. That is one `unsafe` FFI call, because `rusqlite`'s `DbConfig` omits the option. The call is then refused on every role.
   - **Reach.** Only Rust code in the Core can reach that API (rusqlite's own wrapper needs its `load_extension` feature). This guards against a dependency or a future code path, not against SQL.
   - **Not run here: the stronger fix.** It compiles extension loading out with `LIBSQLITE3_FLAGS="-USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION"`. It was not run because the C API tests link `sqlite3_load_extension`, which that build removes. Procedure for Story 3.1:
     - set that variable in the workspace `.cargo/config.toml` `[env]`;
     - check that `SELECT load_extension('x')` fails with `no such function`;
     - check that `cargo tree -e features` never shows the `rusqlite` feature `load_extension`.
2. **A denied function call is not `SQLITE_AUTH`.** SQLite reports most authorizer refusals as `SQLITE_AUTH`, but a denied function as `SQLITE_ERROR` with the message `not authorized to use function: <name>`. Separately, `rusqlite`'s `Error::sqlite_error_code()` returns `None` for `Error::SqlInputError`, which `modern_sqlite` (implied by `bundled-sqlcipher`) uses for prepare errors SQLite can locate in the SQL text. `is_authorizer_denial()` handles both. Storage-layer code that maps errors must do the same, or it will misclassify function denials.
3. **`VACUUM` is refused under the authorizer.**
   - `VACUUM` and `VACUUM INTO` attach a database internally, and the authorizer refuses that `ATTACH` when the statement runs (`authorization denied`). Nothing is written (`write.refused.vacuum`, `read.vacuum_into`, `write.vacuum_into`).
   - In a migration, `VACUUM` is already refused because the runner's transaction is open. The migration test accepts that refusal for `VACUUM` statements only.
   - Without the authorizer, `VACUUM INTO` writes an encrypted copy (same key), not a plaintext one.
   - Consequences: the E17 fallback ("vacuum after shredding") and the D84 copy step both need a Core maintenance path outside the authorizer (proposed update 5).
4. **The authorizer is what stands between SQL and a plaintext copy.** Without it, `ATTACH ... KEY ''` followed by `SELECT sqlcipher_export(...)` writes the encrypted module file out as a plaintext SQLite file (`control.plaintext_export_possible_without_authorizer`). Under the policy, both statements are refused.
5. **Pragma table functions are covered.** `SELECT * FROM pragma_database_list` runs the pragma internally, and the authorizer sees it as a `PRAGMA` (`SQLITE_AUTH`). Pragma table functions do not accept a value for settable pragmas such as `journal_mode`: the argument is read as a schema name.
6. **SQLCipher pragmas go through the authorizer.** In the amalgamation, `sqlite3Pragma` calls the authorizer before handing `key`, `rekey` and `cipher_*` to SQLCipher, and the tests confirm the refusal of each. The Core must therefore key the connection and run its setup pragmas before installing the authorizer. `open()` does so, and the setup is read back per role (`<role>.setup.*`):
   - `secure_delete` 1 and `trusted_schema` 0 on every role;
   - `journal_mode` `wal` on migration and write connections.
7. **Statements prepared before the authorizer are re-checked.** Installing the authorizer expires prepared statements. A statement prepared before it is refused when it runs (`write.statement_prepared_before_authorizer`), so a statement cache cannot carry a forbidden statement past it.
8. **Planted schema objects.** A trigger or view whose body calls `sqlcipher_export('main')` is planted in the file without the authorizer.
   - With `trusted_schema` turned back on, so that only the authorizer can refuse, both are refused by the authorizer (`<role>.planted_sqlcipher_export_refused_by_authorizer`).
   - On connections from `open()`, both are refused: the trigger by the authorizer, the view by `trusted_schema` off (`unsafe use of sqlcipher_export()`), which fires first.
9. **SQLite's own nested statements pass through the authorizer.**
   - `ALTER TABLE ... RENAME` and `DROP COLUMN` call internal functions (`sqlite_rename_*`, `sqlite_drop_column`) and rewrite `sqlite_master`, `sqlite_temp_master` and `sqlite_sequence`. `ANALYZE` writes the statistics tables. Each is an ordinary authorizer action.
   - The migration policy therefore allows those functions and tables. The functions stay unreachable from SQL text (`migration.internal_alter_function_not_callable`: `no such function`).
   - Because writes to `sqlite_sequence` must be allowed in a migration, the two `sqlite_sequence` hostile statements run on read and write connections only, where they are refused.
   - `sqlite_dbpage`, which writes raw pages, is not compiled into this build: a statement against it fails with `no such table` before the authorizer is asked (`control.sqlite_dbpage_not_compiled_in`).
10. **Refusing virtual tables blocks FTS5.** The migration policy refuses `CREATE VIRTUAL TABLE` (`migration.not_allowlisted.virtual_table`, an FTS5 table), but D23 puts full-text search on encrypted SQLite. As built, no module can create its FTS5 index. Proposed update 6 resolves this. `fts5` is the function that hands out FTS5's internal API pointer, so it stays denied; `bm25`, `highlight` and `snippet` are allowed.

## Result

Command, from the repository root on any host with Docker (Git Bash on Windows works): `bash spikes/sqlite-authorizer/run.sh`.

Run on 2026-10-16: exit code 0, `RESULT PASS`, 255 `PASS` lines and no `FAIL` line:
- 4 gates: `fmt`, `clippy` (`--all-targets -- -D warnings`), `build_tests`, and `test_count` (28 passed, 0 ignored, 28 expected);
- 28 test functions;
- 223 individual checks.

A deliberate formatting fault was injected once and reverted, to confirm that `run.sh` prints `FAIL fmt` and `RESULT FAIL` and exits 1.

| Criterion | Result | Evidence |
|---|---|---|
| AC1 (E11, FR-23, D21): forbidden statements rejected in a migration, nothing written | **Pass** | `test.every_hostile_statement_is_refused_in_a_migration_and_nothing_is_written`: each of the 23 hostile statements ends a migration that first creates a table and inserts a row. Each is refused, and after closing, the file bytes, the directory listing, the schema and the rows are unchanged (`migration.<name>` lines). All are authorizer refusals except `VACUUM INTO`, which SQLite refuses inside the runner's transaction (finding 3). Extension loading, SQL function: refused by the authorizer, even with loading switched on (`write.load_extension_function_refused_with_loading_on`). Extension loading, API call: refused on every role (`<role>.load_extension_api_refused`: switch 0, `not authorized`), by the switch `open()` turns off, not by the authorizer (finding 1). Also refused in a migration, with nothing written: transaction control (6 statements), temporary objects and virtual tables (4 statements). A migration connection refuses `CREATE TABLE`, `INSERT`, `SELECT` and `ATTACH` outside the runner: at open, after a successful migration, after a refused one, after a failed `BEGIN`, and on a write connection passed to `apply_migration` (`migration.closed_*`, `migration.failed_begin.*`, `write.closed_after_apply_migration.*`). Allowed: an ordinary migration applies and is committed (`migration.allowed.*`). It covers create table and index; add, rename and drop column; rename table; insert (with `AUTOINCREMENT`), update and delete; a recursive CTE; a view; a trigger; drop index; introspection pragmas in lower and upper case; and `ANALYZE`. |
| AC2 (E11, I6): hostile statements rejected on a read connection, `SELECT` succeeds | **Pass** | `test.hostile_statements_are_refused_on_a_read_connection_and_select_succeeds`: each of the 25 hostile statements is refused and followed by a `SELECT` that succeeds on the same connection (`read.<name>`, `read.select_after_<name>`); file and directory unchanged. The same holds on a write connection (`write.*`). Role checks: a read connection refuses `INSERT` and `CREATE TABLE` and runs `PRAGMA TABLE_INFO(items)`; a write connection refuses DDL, `VACUUM` and `INSERT INTO sqlite_sequence`, and runs an `AUTOINCREMENT` insert. |
| AC3 (E11, D21): fallback recorded if any forbidden statement passes | **Not triggered** | No forbidden SQL statement passed the authorizer. The one path it cannot see, the extension loading C API, is not SQL, so a statement parser would not cover it either; the connection setting closes it (finding 1). No fallback is recorded in `doc/decisions.md`. |
| Controls | **Pass** | `test.without_the_authorizer_no_hostile_statement_is_an_auth_refusal`: without the authorizer, every attach, detach, pragma, export, `VACUUM INTO` and `sqlite_sequence` statement runs. The `load_extension()` function fails with exactly `not authorized` (loading off) and is not classified as an authorizer refusal. |
| Policy unit tests and function coverage | **Pass** | Under every policy, an unknown action code (9999), `ATTACH`, `DETACH`, virtual tables and temporary objects are denied, and each policy's intended row of allowed actions holds. `functions.every_engine_function_reviewed`: all 126 functions the engine offers are in exactly one of the two lists. |

Not run here: the compile-out build of finding 1 (procedure given there).

## Proposed design document updates

1. `doc/research-notes.md` section 3, after the experiment table, add: "E11 passed on 2026-10-16 (rusqlite 0.40.2, SQLCipher 4.14.0, SQLite 3.51.3): every hostile statement was refused on migration, write and read connections and nothing was written; see Story 1.7 Result and `spikes/sqlite-authorizer/run.sh`. The extension loading C API is outside the authorizer's reach and is on by default in the bundled build; the Core turns it off on every connection (D120)."
2. `doc/decisions.md`: leave D21's text unchanged and add a new decision record, amending D21 (next free number; D120 at the time of writing, renumber if another record took it first). Change the D21 row's status to "Accepted, amended by D84 and D120". The new record reads: "Amends D21. Context: the bundled SQLCipher build enables the extension loading C API on every connection, and the SQLite authorizer cannot see that C call (E11, Story 1.7). Decision: every connection the Core opens turns off `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` before use, and the build compiles extension loading out where the toolchain allows; the authorizer allowlists SQL functions, so `load_extension` and `sqlcipher_export` are refused. Consequences: one FFI call in the storage layer until extension loading is compiled out."
3. `doc/architecture-spine.md` AD-5 rule, after "has an authorizer that refuses `ATTACH`, `DETACH` and extension loading (invariant I6)", add: "The Core keys each connection and runs its setup pragmas (`secure_delete` on, `trusted_schema` off) before installing the authorizer; after that, no pragma outside a read-only introspection allowlist runs, SQL functions are allowlisted, writes to SQLite's internal tables are refused outside migrations, and the extension loading C API is off (D120). A function call denied by the authorizer fails with `SQLITE_ERROR`, not `SQLITE_AUTH`, and the storage layer classifies it as a refusal."
4. `doc/architecture-spine.md` AD-23 rule, after "applied per file through the authorizer connection, forward only (D21).", add: "The migration connection refuses every statement outside the runner. The runner owns the transaction, and migration SQL that commits, rolls back or opens a savepoint is refused."
5. `doc/architecture-spine.md` AD-23 rule, after "Before copying, the Core closes every connection to the file, runs `checkpoint(TRUNCATE)` and checks that no WAL content remains.", add: "The copy is made by the Core's maintenance path outside any authorizer connection, as a file copy or with SQLite's online backup API, never with `VACUUM INTO` or `ATTACH`, which the authorizer refuses." In `doc/research-notes.md`, E17 row, Fallback cell, append: "(`VACUUM` is refused on module connections because it attaches a database internally; a vacuum runs from the same Core maintenance path)".
6. `doc/architecture-spine.md` AD-23 rule, append: "A module that needs full-text search declares its FTS5 tables in the registry; the migration policy allows `CREATE VIRTUAL TABLE` and `DROP VIRTUAL TABLE` only for the `fts5` module (D23), and refuses every other virtual table module." Recommended over a Core-created path, because it keeps FTS5 schemas in the module's migrations, where the frozen hash already covers them. What it gives up: FTS5 shadow tables (`<name>_data`, `<name>_idx`, and the others) become writable to the module's write connection, and E15 should check that a crafted write to them cannot corrupt more than that module's own index. Not tested here.
7. `doc/stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md` AC3, append: "And the extension loading C API is off on every connection, checked by a test." Story 3.1 should also take as tasks the compile-out procedure of finding 1 and the warning in "Not for Story 3.1 as is".
