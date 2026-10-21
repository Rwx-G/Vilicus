---
title: 'Module registry and record envelope'
epic: 3
story: 2
status: done
author: Rwx-G
created: 2026-10-16
implements: [FR-18, FR-22, FR-58, FR-68, AD-6, AD-9, I8, I36, D98, D103, D104, I6, AD-5, D127]
---

# Story 3.2: Module registry and record envelope

As a project maintainer,
I want modules registered at build time through `vilicus-module-api`, with the registry refusing any table or field that lacks its envelope and declarations,
So that every record the Core stores carries provenance, typed fields and its data types.

**Acceptance Criteria:**

**AC1 (FR-22, AD-9)**
**Given** a module crate implementing `vilicus-module-api`
**When** the binary is built
**Then** the registry lists its schema, migrations and record types at build time, with no runtime registration path.

**AC2 (FR-18, AD-6, I8)**
**Given** a module table
**When** the registry loads it
**Then** it is refused unless it carries `id`, `source`, `taint`, `data_types`, `author`, `created_at`, `updated_at` and `rev`
**And** a registry test with a table missing `source` or `taint` fails registration.

**AC3 (FR-58, D98, D104)**
**Given** a field of a module table
**When** the registry loads it
**Then** it is refused unless declared structured or free text with a maximum length
**And** a structured field is refused unless its value set is fixed at build time (compiled enumeration, bounded number, date, opaque UUIDv7) or it is declared a reviewed vocabulary.

**AC4 (FR-68, I36, D103)**
**Given** a record kind
**When** the registry loads it
**Then** it is refused unless it declares the data types its fields may hold, each from the closed set of `vilicus-types`
**And** a record kind declaring a type outside the set fails registration.

**AC5 (AD-9)**
**Given** the Rust table declaration and the schema the module's migrations produce
**When** the build-time test runs, and again when the Core opens a file
**Then** the declaration is compared with `PRAGMA table_xinfo` of the migrated schema
**And** any difference fails the test or refuses the file with a typed error.

**AC6 (I6, AD-5)**
**Given** two module crates
**When** the crate graph check runs
**Then** a module crate that depends on another module's storage or table types fails the build

**AC7 (D127, D132)**
**Given** a module that needs full-text search
**When** the registry loads its FTS5 table declaration
**Then** it is refused unless its arguments are on the allowlist: a built-in tokenizer among `unicode61`, `ascii`, `porter` and `trigram`, and `content=` empty or naming a table of the same module
**And** it is refused unless the table's migration sets its `secure-delete` option to 1 (D132); the `fts5()` SQL function stays denied (Story 3.1).

**Dependencies:**
- Story 3.1 (storage layer)
- Story 2.4 (data type set, envelope types)

**References:**
- `doc/prd.md` FR-18, FR-22, FR-58, FR-68
- `doc/architecture-spine.md` AD-6, AD-9
- `doc/ai-safety.md` I8, I36
- `doc/decisions.md` D98, D103, D104, D127, D132

## Implementation Notes

**What was built**
- `crates/vilicus-module-api/` (the module port, no new dependency):
  - `src/declaration.rs`: a module declares its file in one `ModuleDeclaration`, plain `'static` data in a `const` item:
    - `name`, in the `ModuleName` grammar;
    - `tables`: each `Table` holds one record kind, with `data_types` (`&[DataType]`, the closed set of `vilicus-types`, re-exported) and `fields`;
    - each `Field` has a `name`, a `kind` and `optional` (`NULL` allowed, otherwise `NOT NULL`). `FieldKind` is `Structured(Structured)` or `FreeText { max_len }` (characters). `Structured` is `Enumeration(&[&str])`, `Integer { min, max }`, `Date`, `Timestamp` (UTC milliseconds), `Uuid` (16-byte UUIDv7) or `ReviewedVocabulary(name)`. `FieldKind::sql_type` gives the column type each kind is stored as (`TEXT`, `INTEGER` or `BLOB`);
    - `fts5_tables`: `Fts5Table { name, columns, tokenizer, content }`, with `Fts5Tokenizer` the four built-ins of D127 (`ALL`, `as_str`) and `Fts5Content` either `Contentless` or `Table(name)`;
    - `migrations`: `Migration { sql }`, version = position from 1 (`latest_version`).
  - `ENVELOPE`: the record envelope of AD-6, in its order, with each column's SQL type, nullability and key (Decisions). Nothing in a declaration names the envelope: every table carries it.
  - `FTS5_SHADOW_SUFFIXES`: the shadow table names FTS5 creates, which no module table may take.
  - `src/check.rs`: the declaration rules as `const fn`s. `ModuleDeclaration::validate` returns the first rule broken as a `DeclarationError`; `assert_valid` panics with the rule, so `const _: () = MODULE.assert_valid();` in a module crate fails its build. The rules:
    - module name in the `ModuleName` grammar (`ModuleName::is_valid`, a `const fn` added to `vilicus-types`);
    - every table, field, FTS5 table and column, enumeration value and vocabulary name an identifier: a lowercase ASCII letter, then lowercase ASCII letters, digits and underscores, at most `IDENTIFIER_MAX_LEN` (64), outside the `sqlite_` prefix (`is_identifier`);
    - no field named like an envelope column;
    - at least one data type per record kind, none twice;
    - free text with `max_len` above 0; an enumeration with at least one value, none twice; an integer range with `min <= max`;
    - unique table names, FTS5 tables and their shadow names included; unique fields; non-empty migrations;
    - an FTS5 table indexes at least one column, none twice; `content=` names a declared table of the module, whose fields the FTS5 columns must be.
- `crates/vilicus-core/src/registry/` (the registry, as the spine's layer table places it in the Core):
  - `Registry::new(&'static [&'static ModuleDeclaration]) -> Result<Registry, RegistryError>`, a `const fn`: it runs every module's `validate` and refuses two modules of one name. A binary builds it in a `const` item, where a refusal is a build error. No method adds a module once it is built. The `const fn` can still be called at run time on a leaked list, as the tests do (review, minor 2), so the guarantee is that the binary's registry is a `const` item, which a review of the binary sees, not a property of the type.
  - `modules()` and `module(&ModuleName)` list the registered declarations: schema, migrations, record kinds and their data types.
  - `Registry::open::<R: Inspect>(file, key) -> Result<Handle<R>, FileError>`: the open of AC5. It refuses a file of an unregistered module, opens it through `vilicus-storage`, then:
    - reads the module schema version from `_meta`: below the module's latest is `MigrationPending`, above is `NewerThanCode`;
    - at the latest version, compares the declaration with the file (`schema.rs`) and refuses a difference with `FileError::Schema(SchemaError)`.
  - `Registry::verify_migrations(directory, key) -> Result<(), VerifyError>`: the build-time test of AC5. For each module, it creates a new file, applies the module's migrations in order through the versioned runner, then opens the file through `open`, which compares it.
  - `schema.rs`: `Snapshot::read` takes the storage schema and the `secure-delete` option of each declared FTS5 table present; `compare` is a pure function. The file must hold exactly (rules as revised after the review, below):
    - the Core tables of `vilicus_storage::CORE_TABLES` and SQLite's internal objects (`sqlite_` prefix, which no migration can create);
    - each declared table, ordinary, created by the one statement its declaration implies, compared token by token (`canonical_table`): `CREATE TABLE <table> (<column> <TYPE> [NOT NULL] [PRIMARY KEY], ...)`, envelope first then the fields in declared order, `NOT NULL` unless optional, `PRIMARY KEY` on `id` only, no other clause, `STRICT` the only table option allowed;
    - its columns read back through `PRAGMA table_xinfo` at their declared type, nullability and key, not generated, and no other column; no foreign key; as indexes, only the one the `id` primary key makes and plain indexes made by `CREATE INDEX` over its columns (not `UNIQUE`, not partial, no expression, `BINARY` collation);
    - each declared FTS5 table as an `fts5` virtual table whose arguments are its declared columns, `content` and `tokenize` (absent `tokenize` reads as `unicode61`) and no other option, with `secure-delete` at integer 1, and exactly the four shadow tables FTS5 makes in the allowed modes (`_data`, `_idx`, `_docsize`, `_config`), each created by FTS5's own statement (`FTS5_SHADOWS`).
  - Anything else is refused: another table, a view, a trigger, a virtual table that is not declared, any other shadow or index. `SchemaError` names the table and the column, index or object at fault. Names compare ignoring ASCII case, as SQLite's do.
  - `sql.rs`: a tokenizer for the statements in `sqlite_master` with SQLite's rules (ASCII white space, `--` and `/* */` comments, single-quoted strings, the three identifier quotings with their doubled quotes), and the token comparison: a keyword matches a bare word only, a name a bare word or a quoted identifier, ignoring ASCII case.
  - `fts5.rs`: reads back the `CREATE VIRTUAL TABLE` text SQLite keeps, into module, columns as written and `key = value` options, with quoted values unquoted. Anything it does not recognise is an error, so the comparison refuses it.
- `crates/vilicus-storage/` (what the registry reads and the migration tracks):
  - `MigrationTrack { Core, Module }` and `Handle<Migration>::apply_versioned_migration(track, version, sql)`:
    - in the runner's one transaction, the order check runs first: `version` must be the recorded version plus one, otherwise `Error::MigrationOutOfOrder` before any SQL runs;
    - then the migration SQL under the migration policy;
    - then the `_meta` row `core_schema_version` or `module_schema_version`, written under the Core policy.
    - The transaction is `BEGIN IMMEDIATE`, so the order check reads the version under the write lock and a concurrent writer makes the call fail as busy (review nit).
    - A failure rolls back the schema and the version together. The unversioned `apply_migration` is test-only (`#[cfg(test)]`, for the Story 1.7 replay), so every schema change in product code moves a track's version (review, minor 5).
  - `Policy::Epoch` is renamed `Policy::Core`: the Core's own statements on `CORE_TABLES`, the key epoch and now the schema versions (the open point of Story 3.1).
  - `Inspect`, implemented for `Read` and `Write` only, carries `schema_version(track)` (0 before the first migration, `Error::MalformedSchemaVersion` for a stored value outside `u32` or not an integer), `schema()` and `fts5_option(table, key)`. A migration handle has none of them (`compile_fail` example).
  - `schema.rs`: `Schema { tables, objects }`:
    - `tables` comes from `pragma_table_list` of `main`, each a `TableInfo` with its `TableKind` (ordinary, virtual, shadow, view), `strict`, `without_rowid` and, for an ordinary table, its `ColumnInfo` from `pragma_table_xinfo` (name, declared type, `NOT NULL`, key position, `hidden`), its `IndexInfo` from `pragma_index_list` and `pragma_index_xinfo` (origin, `UNIQUE`, partial, key columns with collation) and its `ForeignKey`s from `pragma_foreign_key_list`;
    - `objects` comes from `sqlite_master` (`SchemaObject`: kind, name, table, SQL).
    - `fts5_option` reads `<table>_config`, and counts an integer value only.
  - `table_list` joins the introspection pragma allowlist, so a read or write handle can read the schema under its own authorizer. It reads names and kinds of the connection's own schemas and no file path.
  - `CORE_TABLES` is public, for the registry.
- `crates/vilicus-types/src/source.rs`: `ModuleName::is_valid`, the grammar as a `const fn`.
- `ci/test_check_workspace.py` (AC6): hand-written edges, refused for every kind of dependency:
  - a module to another module, in both directions (`test_a_module_depending_on_another_module_fails`);
  - a module to `vilicus-storage`;
  - the reference module to a module.
- No new package. `vilicus-core` names `vilicus-types` directly, an edge AD-3 already reaches (D140), and takes `rusqlite` (already in the lockfile, used by `vilicus-storage`) as a dev-dependency, for the registry tests to build real FTS5 tables outside the authorizer (review, M2). `Cargo.lock` gains those two lines; `cargo deny`, `vet` and `audit` see the same packages.

**Decisions and why** (choices the documents leave open; the coordinator records them, see Open points)
- *Where the parts live*:
  - the rules of a declaration are `vilicus-module-api`'s, as `const fn`s, so a module checks its own declaration in its build without reaching the Core, which AD-3 forbids;
  - the registry is the Core's: it reruns the rules on every module, so a declaration that skipped `assert_valid` is still refused, and it alone compares with a file, through `vilicus-storage`;
  - the storage layer reads the schema and writes the versions, and holds no knowledge of declarations.
  - What it gives up: one rule set runs twice, on purpose.
- *One table, one record kind*: AD-9's record types and FR-68's record kinds map to tables; the data types are declared per table. What it gives up: a table holding several kinds of record would need splitting; nothing in V0.1 asks for one.
- *The envelope is fixed by `ENVELOPE`, not declared per table*. The check of AC2 runs on the migrated file, where it matters: a migration that leaves out `source` or `taint` fails registration, and a declaration cannot name a field like an envelope column. The SQL types:
  - `id` `BLOB NOT NULL PRIMARY KEY` (16-byte UUIDv7, conventions);
  - `source`, `taint`, `data_types` `TEXT NOT NULL`;
  - `author` `BLOB` and nullable, since the conventions leave it empty for `Display`, `Adapter` and assistant-origin rules;
  - `created_at`, `updated_at`, `rev` `INTEGER NOT NULL` (UTC milliseconds, conventions).
  - How `source` and the `data_types` set are written in their `TEXT` columns is Story 3.5's: names keep the stored form independent of the order of `DataType`, which a bit mask would freeze.
- *Structured kinds*:
  - D104's four become `Enumeration`, `Integer`, `Date` and `Uuid`, plus `Timestamp`, an instant in the conventions' UTC milliseconds, and `ReviewedVocabulary`;
  - numbers are integers only, so an amount is in its smallest unit;
  - enumeration values are identifiers, so a compiled value cannot carry a sentence;
  - a field that is none of these does not compile, so "declared structured or free text" holds by type.
- *FTS5 `content=`*: D127 allows it empty or naming a table of the same module. The registry reads this as two choices, `content=''` and `content='<declared table>'`. An FTS5 table without `content=` keeps its own copy of the text in its `_content` shadow table, outside any envelope, so it is refused. The rest of the allowlist:
  - `tokenize` takes a bare built-in name, so `porter unicode61` and tokenizer arguments such as `remove_diacritics 2` are refused;
  - no other option is allowed, `content_rowid`, `prefix`, `detail`, `columnsize` and `contentless_delete` included, nor a column flag such as `UNINDEXED`.
  - What it gives up: those options until a decision allows one.
- *Undeclared objects are refused*: a trigger in a module file could write rows the typed record API never sees, skipping envelope, validation and journal (AD-9). Views and undeclared tables are refused too. What it gives up: a module needing a view needs a declaration kind first.
- *Any clause with behaviour is a difference* (review, M1). The first version compared only type, nullability, key and generation, so `REFERENCES ... ON DELETE CASCADE`, `ON CONFLICT REPLACE`, `DEFAULT`, `COLLATE`, `CHECK`, `UNIQUE` and `WITHOUT ROWID` passed and acted outside the typed record API: cascades deleted rows with no journal, `REPLACE` swapped a row's `source`, a `NULL` `taint` was stored as a default. The registry now compares the whole statement with the one the declaration implies, token by token, rather than parsing column definitions: whatever SQLite adds to its grammar, a clause the declaration does not imply is a token the comparison does not expect, so it fails closed. The pragmas read the same facts a second way (foreign keys, indexes, columns).
  - Declarations model no index, so only plain indexes are allowed: a `UNIQUE` index refuses or, with `REPLACE`, deletes rows; a partial or expression index evaluates SQL on every write; a collation changes what counts as equal.
  - Declarations model no default, so a field added by a later migration is optional (SQLite requires a default for an added `NOT NULL` column). A module that needs a new `NOT NULL` field rebuilds the table (create, copy, drop, rename), which the migration policy allows.
  - Declarations model no foreign key: a reference without an action would still refuse writes in an order the Core does not know; cross-record references are opaque ids (AD-10).
  - The declared order is the column order: a field a later migration adds is declared last.
- *`STRICT` is allowed, not required*, as the only table option. Requiring it was the first design, because it makes SQLite refuse a value of the wrong type instead of converting it (D98). The build-time test found that SQLite checks a column added to a `STRICT` table with `pragma_quick_check`, which the migration authorizer refuses, so a `STRICT` table could never gain a column (`a_column_cannot_be_added_to_a_strict_table_under_the_migration_authorizer`). Type checking therefore rests on Story 3.4's validation before every write. What it gives up: a second line against a write the validation misses.
- *Schema versions*:
  - they are `_meta` rows (`core_schema_version`, `module_schema_version`), absent meaning 0, as Story 3.1 prepared;
  - only the runner writes them, in the migration's own transaction, under the Core policy, so module SQL can neither forge nor skip one;
  - a migration's version is its position in the declaration, so no version can be declared out of order.
  - The registry compares a file with its declaration only at the latest version, and reports an older or newer one as a typed error that Stories 3.7 and 3.9 act on.
- *`table_list` in the pragma allowlist*: it is the only interface that tells a shadow table from an ordinary one, which the FTS5 rules need, and it reads names and kinds only. `database_list`, which reveals file paths, stays refused (Story 1.7 hostile list).
- *FTS5 shadow tables* (review, M2): SQLite marks a table as an FTS5 shadow table by its name alone, so `<table>_content` beside a contentless table passed as a shadow and held rows with no envelope. The allowed modes (contentless or external content, no other option) fix the shadow set to `_data`, `_idx`, `_docsize` and `_config`; any other is refused, each must be present, and each must be created by the statement FTS5 writes, which the tests read back from real FTS5 tables (SQLite 3.53.4, D143). What it gives up: an FTS5 option that changes the shadow set (`columnsize=0`, `contentless_delete`) needs the list extended with its decision.
- *Reserved names* (review, minor 3): a field cannot be named `rowid`, `oid` or `_rowid_` (`ROWID_NAMES`), which would take the rowid's place in every statement naming it; an FTS5 column cannot be `rank`, `rowid` or the table's own name (`FTS5_RESERVED_COLUMNS`).

**Files**
- `crates/vilicus-module-api/src/`: `lib.rs`, `declaration.rs`, `check.rs`, `tests.rs`
- `crates/vilicus-core/`: `Cargo.toml`, `src/lib.rs`, `src/registry/` (`mod.rs`, `schema.rs`, `fts5.rs`, `tests.rs`)
- `crates/vilicus-storage/src/`: `lib.rs`, `authorizer.rs`, `error.rs`, `file.rs`, `handle.rs`, `schema.rs`, `tests/mod.rs`, `tests/schema.rs`
- `crates/vilicus-types/src/source.rs`
- `ci/test_check_workspace.py`, `Cargo.toml` (comment), `Cargo.lock`, `crates/vilicus-storage/build.rs` (comment)
- `crates/vilicus-core/src/registry/sql.rs` (review)
- `doc/stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md` (the renamed test, review minor 4)
- `doc/stories/sprint-status.yaml` (3.2 `review`)

**Deviations**
- *AC2, "when the registry loads it"*: the Rust declaration cannot omit the envelope, which it carries by construction, so the refusal applies where a table can lack it, to the schema the migrations produce. It runs in the build-time test and at every open. The declaration side refuses a field that takes an envelope column's name.
- *AC3, "refused unless declared structured or free text"*: a field has no third form in Rust. What is refused is a column the migrations create without a declaration (`UndeclaredColumn`) and a declaration with no bound: free text of length 0, an empty enumeration, an empty range, a value outside the identifier grammar.
- *AC4, "a type outside the set fails registration"*: `DataType` is a closed enum, so such a declaration does not compile, which is earlier than registration. A `compile_fail` example (`DataType::Pets`, error E0599) shows it. A record kind with no data type is refused by `validate`, at build time in a `const` item (`compile_fail` example, E0080) and by `Registry::new`.
- *AC5, at open*: the comparison runs when the file is at the module's latest schema version. A file behind it is `MigrationPending`, which Story 3.7 migrates. A file ahead of it is `NewerThanCode` (D21). Comparing those files against the latest declaration would report a false difference.
- *AC6*: the AD-3 graph already refused these edges (`mods` reaches `modapi` and `types` only, and `vilicus-storage` is private to the Core). The story adds hand-written tests, so an encoding error in `ci/crate_graph.toml` that the derived tests would share still fails.
- *AC1, "no runtime registration path"*: no method adds a module to a built registry, and the binary's registry is a `const` item. The `const fn` constructor is public, so code can call it at run time on leaked data (the tests do); the first version of this story claimed a `compile_fail` example proved otherwise, which was wrong and is withdrawn (review, minor 2). Restricting the constructor further (a macro over an inline `const` block) would still need a public function behind it, so it was not done.
- *AC7, Partial*: no migration can create an FTS5 table before Story 3.7 allows `CREATE VIRTUAL TABLE ... USING fts5` (D127; Story 3.1 kept it refused). What this story tests, on real FTS5 tables created outside the authorizer in a migrated file and opened through `Registry::open`:
  - accepted declarations and their shadow tables, `secure-delete` absent or 0 refused, a fake `_content` shadow, a rebuilt and a dropped `_docsize`, an absent FTS5 table, an ordinary table under the FTS5 name, an undeclared FTS5 table;
  - the argument allowlist on the snapshot of a real FTS5 table whose stored text is replaced by each refused form, most of which FTS5 itself accepts;
  - the storage side, reading the virtual table, its shadow tables and the option, on a file whose FTS5 tables were created without the authorizer;
  - the `fts5()` function stays denied (`denied_functions_are_refused_and_classified_as_refusals`, Story 3.1).
  - Not tested: an FTS5 table made by a migration through the runner and the migration authorizer, which needs Story 3.7.

**Open points**
- *Design documents* (coordinator), changes this story's code implies:
  - AD-6: the envelope's SQL types, `author` nullable, and that a declaration cannot name a field like an envelope column.
  - AD-9: the placement of the rules (module API, `const`) and of the registry (Core), and the comparison rules: the canonical statement compared token by token, undeclared tables, views, triggers, foreign keys, generated columns and indexes other than plain ones refused, `STRICT` allowed and not required, and why.
  - D127: the reading of `content=` (two choices, own content refused) and of the tokenizer and option allowlist.
  - AD-26: the two schema version rows of `_meta`, written by the runner under the Core policy in the migration's transaction.
  - D126: `table_list` joins the introspection pragma allowlist.
- *Story 3.3*: tools join `ModuleDeclaration`. The registry's `modules()` gives the CI matrix check its source.
- *Story 3.4*:
  - value validation per kind: the `Date` text form, `max_len` counted in characters, vocabulary labels at most 32 characters from a restricted alphabet;
  - with `STRICT` not required, that validation is the only type guard on writes;
  - a migration that back-fills a column with `UPDATE` writes values no declaration checks (a `DEFAULT` is now refused).
  - If a second guard is wanted, allowing `quick_check` in the migration policy would let tables be `STRICT`.
- *Story 3.5*:
  - the text forms of `source` and `data_types`, and the meaning of a `NULL` `author`;
  - the per-table flag of a record kind exempt from elevation (Story 3.10 AC2) is not in `Table` yet.
- *Story 3.6*:
  - `_journal`, `_outbox`, `_consumed` and `_dead_letter` join `CORE_TABLES`, created on the Core track with `apply_versioned_migration(MigrationTrack::Core, ..)`;
  - `verify_migrations` then runs the Core track before the module's;
  - the registry already ignores every name in `CORE_TABLES`.
- *Story 3.7*:
  - the frozen hash of each migration (`Migration` has room for it);
  - the FTS5 allowance in the migration policy, with which `verify_migrations` exercises AC7 end to end: the tests of this story on real FTS5 tables must be repeated with the tables made by a migration through the runner;
  - creating an FTS5 table runs `PRAGMA data_version`, which the migration policy refuses (found by the review's probe): the allowance must account for it;
  - a migration cannot add a column to a `STRICT` table under the authorizer (finding above).
- *Story 3.9*: `MigrationPending` and `NewerThanCode` map to AD-54's `migrating` and `newer than code`.
- *Story 3.10*:
  - the reference module declares a `ModuleDeclaration` checked with `assert_valid`;
  - the testbed builds a `const` registry with it, and its build-time test calls `verify_migrations`.
- *The binary*: V0.1 ships no module, so `vilicus` builds no registry yet. It still references no Core code, so SQLCipher is still not linked into it (Story 3.1 open point).

## Result

All commands ran on 2026-10-21, last after the review fixes (commit `61e1604`), in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch made inside the container, with an empty target directory. Mutations ran on another clone with its own target directory, never on the working tree.

Gates, as `.github/workflows/ci.yml` runs them:
- `python3 -m unittest discover -s ci`: `Ran 211 tests`, `OK` (210 before the story; 1 more in `test_check_workspace.py`, and two rows more in `HandWrittenEdgeTest.FORBIDDEN`).
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 255 passed, none failed (242 before the review fixes). `vilicus-storage` 84 (74 before the story) and 1 example, `vilicus-module-api` 15 and 3 examples, `vilicus-core` 26 and 1 example.
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`, unchanged.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `cargo tree --workspace -e features -i rusqlite`: `load_extension` appears nowhere (0 lines).
- The fuzz coverage check is not concerned: `vilicus-proto` is unchanged.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (FR-22, AD-9) | **Pass** | `registry::tests::the_registry_lists_its_modules_built_at_build_time`: a `const` registry built from a `'static` list lists each module's tables, data types, fields and migrations, and its build-time test passes. `the_registry_refuses_invalid_or_duplicate_modules`: a declaration that breaks a rule and two modules of one name are refused by `Registry::new`. The `vilicus_core::registry` example: the `const` registry builds. `Registry` has no method that adds a module; its `const fn` constructor can be called at run time on leaked data (Deviations). |
| AC2 (FR-18, AD-6, I8) | **Pass** | `a_table_missing_an_envelope_column_fails_registration`: a migration that leaves out each envelope column in turn, `source` and `taint` included, fails the build-time test with `EnvelopeColumnMissing` naming the column. `an_envelope_column_of_another_shape_fails_registration`: `taint INTEGER`, a nullable `source`, an `id` that is not the primary key, a `NOT NULL` `author` and `rev ANY` each fail with `ColumnMismatch`. `a_field_named_like_an_envelope_column_is_refused` (each envelope name). `the_envelope_is_the_one_of_ad_6` reads AD-6 in the spine and compares it with `ENVELOPE`. |
| AC3 (FR-58, D98, D104) | **Pass** | `fields_without_a_bounded_declaration_are_refused`: free text of length 0, an empty enumeration, a value listed twice, a value that is a sentence, an empty integer range and a vocabulary name outside the grammar are refused, and the smallest bounds are accepted. `fields_must_be_the_declared_ones`: an undeclared column, a declared field without its column, a field of another type, a field `NOT NULL` that is optional and the reverse, and a generated column each fail with a typed error. `every_field_kind_maps_to_its_sql_type`, `identifiers_follow_their_grammar`. A field outside structured or free text cannot be written (Deviations). |
| AC4 (FR-68, I36, D103) | **Pass** | `a_record_kind_without_data_types_is_refused`: no data type and a data type listed twice are refused, and each member of `DataType::ALL` alone is accepted. The `assert_valid` examples: a record kind without a data type stops the build in a `const` item (`compile_fail`, E0080), and `DataType::Pets` does not compile (`compile_fail`, E0599). `the_registry_refuses_invalid_or_duplicate_modules` (no data type, at the registry). |
| AC5 (AD-9) | **Pass** | Build-time test: `the_migrations_of_a_conforming_module_produce_its_declaration` (two migrations, the second adding a column and a table, with an index); `undeclared_objects_and_missing_tables_fail_registration` (an undeclared table, view and trigger, and a declared table no migration creates); every AC2 and AC3 schema test runs through `verify_migrations`. Review M1: `clauses_with_behaviour_fail_registration` (a foreign key with `ON DELETE CASCADE`, one to `_meta(key)` with `ON UPDATE CASCADE`, `UNIQUE ON CONFLICT REPLACE`, `PRIMARY KEY ON CONFLICT REPLACE`, `ON CONFLICT REPLACE DEFAULT` on `taint`, `COLLATE NOCASE`, `CHECK`, a `DEFAULT` on `source`, `WITHOUT ROWID`, envelope columns in another order); `only_plain_indexes_pass_registration` (a unique partial expression index, a `UNIQUE` index, an expression index, a `NOCASE` index and a partial index refused; a plain index with `DESC` and `COLLATE BINARY` accepted); `case_and_comments_do_not_make_a_difference`; `registry::sql::tests` (5 tests of the tokenizer). At open: `the_core_checks_each_file_it_opens` (read and write handles open a conforming file; a declaration with one more field gets `FieldMissing`, one with a field less gets `UndeclaredColumn`); `a_file_of_another_version_or_module_is_refused_at_open` (`MigrationPending { found: 2, latest: 3 }`, `NewerThanCode { found: 2, latest: 1 }`, `UnregisteredModule`). Storage: `read_and_write_handles_read_the_schema` (table kinds, `STRICT`, `WITHOUT ROWID`, columns with a generated one, indexes, views and triggers, under each role's authorizer); `versioned_migrations_apply_in_order_and_record_their_version` (out of order refused before its SQL runs); `a_failed_migration_keeps_the_previous_version`; `migration_sql_cannot_write_a_schema_version`; `a_new_file_is_at_version_zero_on_both_tracks`; `a_malformed_schema_version_is_a_typed_error` (a negative and a text version); `a_migration_waits_for_no_concurrent_writer` (busy while another connection holds a write transaction, nothing written); the indexes and foreign keys of `read_and_write_handles_read_the_schema`; the `Inspect` example (a migration handle has no `schema`, `compile_fail`, E0599). The `STRICT` finding: `a_column_cannot_be_added_to_a_strict_table_under_the_migration_authorizer`. |
| AC6 (I6, AD-5) | **Pass** | `ci/test_check_workspace.py`: `test_a_module_depending_on_another_module_fails` (both directions, normal, build and dev dependencies); `test_forbidden_edges_fail` with the new rows `vilicus-mod-sample -> vilicus-storage` and `vilicus-mod-reference -> vilicus-mod-sample`; the existing `test_two_crates_of_one_pattern_node_may_not_depend_on_each_other` and `test_dev_dependency_on_a_test_crate_only_from_crates_that_reach_the_core`. |
| AC7 (D127, D132) | **Partial**: tested on real FTS5 tables built outside the authorizer, not yet through a migration (Story 3.7) | `fts5_tables_outside_the_allowlist_are_refused` (content outside the module, a column not in the content table, no column, a column twice, `UNINDEXED`); `the_tokenizers_are_the_allowlist_of_d127` reads D127 and compares it with `Fts5Tokenizer::ALL`; `reserved_column_names_are_refused` (`rank`, `rowid`, the table's name). On real FTS5 tables, opened through `Registry::open`: `real_fts5_tables_with_their_declared_arguments_pass` (external content with `porter`, contentless with the default tokenizer, other spellings; their shadow tables match `FTS5_SHADOWS`); `a_real_fts5_table_without_secure_delete_is_refused` (absent, 0); `shadow_tables_are_exactly_the_ones_fts5_makes` (a fake `_content` beside a contentless table, a rebuilt and a dropped `_docsize`); `fts5_tables_absent_undeclared_or_of_another_kind_are_refused`; `fts5_arguments_outside_the_declaration_or_the_allowlist_are_refused` (twelve refused forms on a real table's snapshot). `registry::fts5::tests` (4 tests of the reader, ASCII white space included). Storage: `fts5_tables_and_their_options_are_read`. `fts5()` stays denied: `denied_functions_are_refused_and_classified_as_refusals` (Story 3.1) passes unchanged. Not tested: an FTS5 table made by a migration (Story 3.7). |

Mutations, each on the clone, with the files reset (and so rebuilt) after each. The unmutated clone passed the storage, module API and Core tests and `test_check_workspace.py` in the same setup. Each mutation made the named tests fail, 54 of 54 (37 before the review, 17 for its rules; the 37 reran against the revised code, five of them naming the FTS5 tests by their new names):
- **Declaration rules (`vilicus-module-api`):**
  - a field may take an envelope name: `a_field_named_like_an_envelope_column_is_refused`;
  - a record kind without a data type accepted: `a_record_kind_without_data_types_is_refused`, `the_registry_refuses_invalid_or_duplicate_modules`, and the `compile_fail` example of `assert_valid`, which then builds;
  - free text without a maximum accepted: `fields_without_a_bounded_declaration_are_refused`, `the_registry_refuses_invalid_or_duplicate_modules`;
  - an empty enumeration, unchecked enumeration values, an empty integer range: `fields_without_a_bounded_declaration_are_refused`;
  - FTS5 content outside the module, an FTS5 column outside its content table: `fts5_tables_outside_the_allowlist_are_refused`;
  - the `sqlite_` prefix accepted: `identifiers_follow_their_grammar`;
  - FTS5 shadow names free for tables: `duplicate_fields_and_tables_are_refused`;
  - `taint` dropped from `ENVELOPE`: `the_envelope_is_the_one_of_ad_6`, `the_registry_lists_its_modules_built_at_build_time`.
- **Registry (`vilicus-core`):**
  - envelope columns optional: `a_table_missing_an_envelope_column_fails_registration`;
  - column type ignored, nullability ignored: `an_envelope_column_of_another_shape_fails_registration`, `fields_must_be_the_declared_ones`;
  - generated columns accepted: `fields_must_be_the_declared_ones`;
  - undeclared columns accepted: `fields_must_be_the_declared_ones`, `the_core_checks_each_file_it_opens`;
  - undeclared tables accepted: `undeclared_objects_and_missing_tables_fail_registration`, `fts5_tables_absent_undeclared_or_of_another_kind_are_refused`, `shadow_tables_are_exactly_the_ones_fts5_makes`;
  - triggers accepted: `undeclared_objects_and_missing_tables_fail_registration`;
  - FTS5 tokenizer, content, options outside the allowlist, each unchecked: `fts5_arguments_outside_the_declaration_or_the_allowlist_are_refused`;
  - `secure-delete` unchecked: `a_real_fts5_table_without_secure_delete_is_refused`;
  - an FTS5 value with a stray quote read: `unreadable_text_is_refused`;
  - `open` without the check: `the_core_checks_each_file_it_opens`, `a_file_of_another_version_or_module_is_refused_at_open`, `a_table_missing_an_envelope_column_fails_registration`;
  - the schema version unchecked: `a_file_of_another_version_or_module_is_refused_at_open`;
  - `Registry::new` without the declaration rules, two modules of one name accepted: `the_registry_refuses_invalid_or_duplicate_modules`.
- **Storage:**
  - the version written under the migration policy: `versioned_migrations_apply_in_order_and_record_their_version`;
  - migration SQL allowed to write `_meta`: `migration_sql_cannot_write_a_schema_version`;
  - the order check removed: `versioned_migrations_apply_in_order_and_record_their_version`;
  - the version committed apart from the migration, before it: `a_failed_migration_keeps_the_previous_version`;
  - `table_list` off the allowlist: `read_and_write_handles_read_the_schema`, `the_migrations_of_a_conforming_module_produce_its_declaration`;
  - `Inspect` for the migration role: the `compile_fail` example of `Inspect`, which then builds;
  - a text `secure-delete` counted: `fts5_tables_and_their_options_are_read`.
- **Review rules:**
  - the statement not compared: `clauses_with_behaviour_fail_registration`;
  - foreign keys accepted: `clauses_with_behaviour_fail_registration`;
  - indexes unchecked: `only_plain_indexes_pass_registration`, `clauses_with_behaviour_fail_registration`;
  - a `UNIQUE`, a partial, an expression or a non-`BINARY` index accepted, each: `only_plain_indexes_pass_registration`;
  - shadow tables accepted by name alone (the first version's rule), shadow statements unchecked, a missing shadow table accepted, each: `shadow_tables_are_exactly_the_ones_fts5_makes`;
  - line comments read as tokens: `case_and_comments_do_not_make_a_difference`, `comments_and_quotes_hide_their_content`;
  - string literals read as identifiers: `keywords_match_bare_words_only_and_names_match_quoted_identifiers`, `statements_split_into_sqlite_tokens`;
  - keywords matched by quoted identifiers: `keywords_match_bare_words_only_and_names_match_quoted_identifiers`;
  - rowid field names, FTS5 reserved columns accepted, each: `reserved_column_names_are_refused`;
  - a text schema version read as 0: `a_malformed_schema_version_is_a_typed_error`;
  - Unicode white space in the FTS5 reader: `only_ascii_white_space_separates_the_header`.
  - The mutations of the statement comparison, the foreign key check, the index check and the shadow name rule each put back the first version's behaviour for that rule, so the review's probes, as tests, fail on the code they found.
  - Not shown by a test: `BEGIN IMMEDIATE` against a deferred transaction. Under WAL, a deferred transaction that read the version cannot write once another writer committed (`SQLITE_BUSY_SNAPSHOT`), so the outcome a test can observe is the same busy failure; the immediate begin makes it surface before any work. The test-only `apply_migration` is a compile-time property.
- **Crate graph (`ci/crate_graph.toml`):**
  - modules reaching modules: `test_a_module_depending_on_another_module_fails`;
  - modules reaching storage, the reference module reaching modules: `test_forbidden_edges_fail`.
- First runs: four mutations ran two packages without `--no-fail-fast`, so the second package did not run, and one mutation did not compile in a `const fn`. The runner was corrected and the five reran; the list above is their result.

**Review of 2026-10-21** (independent review on PR #4; each fix carries tests, and a mutation that removes it fails them, above):

| Item | Resolution |
|---|---|
| M1, clauses with behaviour passed the comparison | The table's statement compared token by token with the declaration's canonical one (`sql.rs`, `canonical_table`); foreign keys refused; only the primary key index and plain indexes allowed; `STRICT` the only option. Every probe is a test in `clauses_with_behaviour_fail_registration` or `only_plain_indexes_pass_registration`. |
| M2, any table SQLite flags as a shadow accepted | Exactly `_data`, `_idx`, `_docsize`, `_config`, each with FTS5's own statement; tests on real FTS5 tables (`rusqlite` dev-dependency of `vilicus-core`). Through a migration: Story 3.7, with `PRAGMA data_version` (Open points). |
| 1, AC7 | Partial, with what is and is not tested (Deviations, Result). |
| 2, AC1 claim | Withdrawn and reworded: the constructor is a public `const fn`; the guarantee is the binary's `const` item (Deviations). |
| 3, reserved names | `ROWID_NAMES` for fields, `FTS5_RESERVED_COLUMNS` and the table's own name for FTS5 columns. |
| 4, Story 3.1 Result | The renamed test `core_tables_are_written_only_under_the_core_policy`; status unchanged. |
| 5, unversioned runner | `apply_migration` is `#[cfg(test)]`. |
| Nits | A non-integer version is `MalformedSchemaVersion`; `BEGIN IMMEDIATE`; ASCII white space in the FTS5 reader and the tokenizer; names compare ignoring ASCII case. |
