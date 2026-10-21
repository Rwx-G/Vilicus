---
title: 'Structured field validation and reviewed vocabularies'
epic: 3
story: 4
status: review
author: Rwx-G
created: 2026-10-16
implements: [FR-58, DC-53, DC-59, D98, D104, I40]
---

# Story 3.4: Structured field validation and reviewed vocabularies

As a project maintainer,
I want the storage layer to validate every structured field against its declaration on every write,
So that a value outside its declared type is refused, never truncated or coerced, and structured data stays safe to treat as untainting.

**Acceptance Criteria:**

**AC1 (FR-58, DC-53, D98, I40)**
**Given** a write with a structured field whose value is outside its declared closed type (an unknown enumeration value, a number out of bounds, an invalid date, a malformed UUIDv7)
**When** the storage layer validates it
**Then** the whole write is refused with a typed error and nothing is stored.

**AC2 (FR-58, I40)**
**Given** a field value longer than its declared maximum length, structured or free text
**When** the write is validated
**Then** it is refused, never truncated.

**AC3 (DC-59, D104, I40)**
**Given** a reviewed-vocabulary field
**When** a write carries a label that is not among the confirmed labels of that vocabulary, or a label longer than 32 characters or outside the restricted alphabet
**Then** the write is refused
**And** a confirmed label of at most 32 characters from the restricted alphabet is accepted.

**AC4 (DC-53, I40)**
**Given** every module write path registered in the testbed
**When** the fuzz test drives each path with values outside their declarations
**Then** every such value is refused and the file is unchanged afterwards.

**AC5 (FR-58)**
**Given** the FR-50 action table, which lists no action to confirm a vocabulary label
**When** V0.1 is built
**Then** no surface confirms vocabulary labels, and tests seed confirmed labels through the `vilicus-testbed` binary only.

**Dependencies:**
- Story 3.2 (field declarations in the registry)

**References:**
- `doc/prd.md` FR-58, FR-50
- `doc/architecture-spine.md` AD-6
- `doc/ai-safety.md` I40
- `doc/decisions.md` D98, D104

## Implementation Notes

**What was built**
- `crates/vilicus-module-api/src/value.rs` (the module port, no new dependency):
  - `Value`, one value of a field in one of SQLite's storage classes: `Null`, `Integer`, `Real`, `Text`, `Blob`. `Real` exists so that a floating-point value has a form to be refused in: no field kind accepts it.
  - `Field::check_value(&Value) -> Result<(), ValueError>`: `Null` for an optional field only, then the storage class of the field's kind (`FieldKind::sql_type`), never converted, then the kind's rule:
    - free text: at most `max_len` characters (Unicode scalar values), counted without reading past `max_len + 1`;
    - enumeration: exactly one of the declared values, byte for byte;
    - integer: in `min..=max`;
    - date: `vilicus_types::is_full_date`;
    - timestamp: in the range of `UtcMillis` (years 0000 to 9999);
    - UUID: 16 bytes that `Id::from_bytes` accepts (version 7, RFC 9562 variant);
    - reviewed vocabulary: the form of a label (`check_vocabulary_label`); whether it is confirmed is the Core's check, which needs the file.
  - `ValueError`: `Null`, `StorageClass { expected }`, `NotInEnumeration`, `OutOfRange`, `InvalidDate`, `InvalidUuid`, `TooLong { max_len }`, `InvalidLabel`. No variant carries the value (logging convention).
  - The label form: `VOCABULARY_LABEL_MAX_LEN` (32) characters at most, each a letter of `is_vocabulary_label_letter` (ASCII letters and digits, the precomposed Latin letters of Latin-1 Supplement without `×` and `÷`, Latin Extended-A) or a separator of `VOCABULARY_LABEL_SEPARATORS` (space, hyphen, apostrophe), starting and ending with a letter, never two separators in a row.
- `crates/vilicus-types/src/time.rs`: `is_full_date`, the RFC 3339 `full-date` grammar as a `const fn`, years 0000 to 9999 like `UtcMillis`, reusing the calendar functions already there.
- `crates/vilicus-storage/`:
  - a Core table `_vocabulary (vocabulary, label, confirmed_by, confirmed_at)`, `STRICT, WITHOUT ROWID`, primary key `(vocabulary, label)`, created by `create` beside `_meta`, and named in `CORE_TABLES`, so no module SQL (migration, write handle, trigger body) can write, drop, alter, index or watch it, as for `_meta` (Story 3.1, M1);
  - `Handle<Write>::confirm_vocabulary_label(vocabulary, label, confirmed_by, confirmed_at)`, under the Core policy in one `BEGIN IMMEDIATE` transaction, the write policy restored after; a label confirmed again keeps its first confirmation;
  - `Handle<R: Inspect>::is_confirmed_label(vocabulary, label)`, an exact comparison;
  - `SqlValue` (rusqlite's value, re-exported), `Handle::execute_values` and `Handle::query_values`, so the Core binds and reads values by storage class without depending on `rusqlite` itself (it stays a dev-dependency of the Core).
- `crates/vilicus-core/src/record/` (new, `pub mod record`):
  - `mod.rs`, the row writer every record write goes through:
    - `insert(handle, module, table, envelope, fields)` and `update(handle, module, table, id, envelope, fields)`, crate-private. Each runs in one `BEGIN IMMEDIATE` transaction on the write handle: the envelope columns are checked (each an `ENVELOPE` column, given once, of its SQL type, `NULL` only where the column may be, all of them on insert, never `id` on update), then the fields (each declared, given once, `Field::check_value`, then a reviewed-vocabulary label against `is_confirmed_label` under the write lock; every required field on insert), and only then does the statement run. Any refusal rolls back and returns a typed `RecordError`; nothing is stored. Table and column names in the SQL come from the declaration, never from the caller.
    - `RecordError`: `UnknownTable`, `UnknownColumn`, `DuplicateColumn`, `MissingColumn`, `IdChanged`, `EmptyUpdate`, `Invalid { table, column, error: ValueError }`, `UnconfirmedLabel { table, column, vocabulary }`, `UnknownVocabulary`, `InvalidLabel`, `RecordNotFound`, `Storage`. It names declared tables and columns only; a name the caller gave that matches nothing is not echoed.
    - `confirm_label(handle, module, vocabulary, label, confirmed_by, confirmed_at)`, crate-private: the label's form, and a field of the module that declares the vocabulary, before the storage write.
    - `check_stored_rows(handle, module)`, crate-private: every stored row of every table read back against the declaration, labels against the confirmed ones (Story 3.2's open point on back-fills).
  - `fuzz.rs`, `Registry::fuzz_write_paths(directory, key, seed, rounds) -> Result<WriteFuzzReport, WriteFuzzError>`, public like `verify_migrations`: for each module, creates and migrates its household file in `directory`, confirms four generated labels per vocabulary (one of 32 characters), then for each table:
    - once per field, each value outside the declaration the generator knows for its kind, on the insert and on the update: the field's valid value in each other storage class (`"12"` for an integer, the text of a UUID, a real number), `NULL` for a required field, enumeration neighbours (a suffix, a space, another case, a prefix, the empty text, a random label), the integers on each side of the range and the `i64` ends, a month 13, day 0 or 32, February 30, a date with a time or another separator, the instants on each side of the `UtcMillis` range, UUID bytes of another version, variant or length, free text one character too long, an unconfirmed label (another case, a random one), a label one character too long, a label with `_`, `:`, `.`, `"`, a line feed, NUL, a combining accent, a zero-width space or a bidi override, a separator at an end, the empty label; also a required field left out, a field given twice and an undeclared column;
    - `rounds` random rounds: up to three fields made invalid at once (insert and update), then a valid insert and a valid update;
    - every invalid write must be refused with the error of a rule it breaks (`WrongRefusal` otherwise), and every row of every table of the file, Core and SQLite tables included, must read back unchanged (`Changed` otherwise); every valid write must be accepted (`ValidRefused`), and at the end `check_stored_rows` must pass.
    - The generator is a seeded SplitMix64, so a failure replays from its seed. The report lists every write path driven (insert and update per table) and counts refused and accepted writes.
  - `registry/mod.rs`: the creation and migration of a scratch file, shared by `verify_migrations` and the fuzz test (`create_migrated`).
- `testing/vilicus-testbed/src/registry.rs` (`#[cfg(test)] mod registry;` in `main.rs`): the testbed's `const` registry, empty until Story 3.10 adds the reference module, and `every_registered_write_path_refuses_values_outside_its_declaration`, which runs the fuzz test over it with two seeds and 256 rounds and checks that it drove an insert and an update per table.
- `crates/vilicus/src/registry.rs`: `every_shipped_write_path_refuses_values_outside_its_declaration`, the same over the shipped registry (empty in V0.1).
- No new package, no change to `Cargo.lock`, `ci/`, the workflow or `fuzz/`.

**Decisions and why** (choices the documents leave open; drafted texts under Open points)
- *Where validation lives*: the rule of a value against its declaration is `vilicus-module-api`'s (`Field::check_value`), so the pipeline can hold tool arguments to the same rule (AD-12, Epic 10) and a module can check a value before it writes; the Core runs it on every write, in the write transaction, and adds what needs the file, label confirmation; the storage layer binds values and stores labels and knows no declaration, as Story 3.2 placed it. What it gives up: "the storage layer validates" (D98, AD-6) reads as the Core's write path over `vilicus-storage`, as AD-9 already says ("in the write transaction the Core ... validates each field").
- *Values keep their storage class*: a value of another class is refused even when SQLite's column affinity would convert it (`"12"` into an `INTEGER` column is stored as 12, which the back-fill test observes). This is what "never coerced" means for a non-`STRICT` table, and with `STRICT` not required (Story 3.2), it is the only type guard on writes.
- *The date form* is RFC 3339 `full-date` (`YYYY-MM-DD`), years 0000 to 9999, exactly ten characters, refused rather than normalized; dates are text in storage (Story 3.2) and ISO order sorts them.
- *Maximum lengths*: free text counts Unicode scalar values (Story 3.2 said characters); a structured value's length is bounded by its kind (an enumeration value by its declared values, a date by its form, a UUID at 16 bytes, a label at 32 characters).
- *The restricted alphabet* (D104 names it without defining it): ASCII letters and digits, precomposed letters of Latin-1 Supplement and Latin Extended-A, and three separators, space, hyphen and apostrophe, never at an end and never two in a row. It writes the French and English labels the product needs (FR-110: `Salle de bains`, `Chambre d'Ella`, `Œufs`) and nothing that structures text: no other punctuation, no control, format, bidi, zero-width or combining character, so a decomposed accent is refused, not normalized, and one label has one spelling. Labels compare exactly, case included. What it gives up: labels in other scripts, and the typographic apostrophe U+2019, which a client must map to U+0027 before the label is confirmed, or a decision widens the alphabet.
- *Where confirmed labels live*: a Core table `_vocabulary` in each module file, written under the Core policy. The check then reads the same file in the same transaction (AD-5: no transaction spans two files), the labels are encrypted under the file's key and follow its partition (a member's own tags stay in their personal partition), and they travel with the file's backups and migrations. A label is confirmed per vocabulary and per file: the same text in another vocabulary or another partition is not confirmed. The row keeps who confirmed it and when. What it gives up: a label shared by the household and personal partitions is confirmed in each file.
- *The row writer takes the envelope from its caller*, holding it to its SQL types only: stamping it is Story 3.5's typed record API, which writes through `insert` and `update`. Both are crate-private, so no crate outside the Core can choose an envelope.
- *No surface confirms a label* (AC5): `confirm_label` is crate-private (a `compile_fail` example shows it out of reach, E0603), and the only code that calls it outside unit tests is the fuzz test, on files it creates itself (`create` refuses an existing file). The testbed confirms labels through that test.
- *Stored rows*: `check_stored_rows` reads every row back against the declaration, the answer to Story 3.2's open point that a migration's back-fill writes values no write path checks; the migration runner of Story 3.7 calls it on the migrated copy before it is swapped in.

**Files**
- `crates/vilicus-types/src/`: `time.rs`, `lib.rs`
- `crates/vilicus-module-api/src/`: `value.rs` (new), `lib.rs`
- `crates/vilicus-storage/src/`: `authorizer.rs`, `handle.rs`, `lib.rs`, `tests/mod.rs`, `tests/vocabulary.rs` (new)
- `crates/vilicus-core/src/`: `lib.rs`, `registry/mod.rs`, `record/mod.rs`, `record/fuzz.rs`, `record/tests.rs` (new)
- `testing/vilicus-testbed/src/`: `main.rs`, `registry.rs` (new)
- `crates/vilicus/src/registry.rs`
- `doc/stories/sprint-status.yaml` (3.4 `review`)

**Deviations**
- *AC1 and AC2, "the storage layer"*: the Core's row writer over `vilicus-storage` (Decisions). Every write path that exists today goes through it; the typed record API of Story 3.5, which modules will call, does not exist yet, so the guarantee that a module cannot write around validation is Story 3.5's to keep (Open points). Read and write handles still execute arbitrary SQL for the Core.
- *AC4, "the fuzz test"*: a seeded generator of out-of-declaration values run by `cargo test`, not a coverage-guided libFuzzer target. D142 confines `libfuzzer-sys` to `vilicus-fuzz`, which may depend on `vilicus-proto` only; a target over the Core would change that decision. The generator is systematic per field kind (every case it knows, on every field, on both paths) and random on top.
- *AC4, "every module write path registered in the testbed"*: the testbed registers no module until Story 3.10, so its test drives zero paths today and checks it drove exactly an insert and an update per table, which holds the reference module to the test when it joins. The fuzz test itself is exercised on probe modules in the Core's tests (every field kind, required and optional, two tables, two modules, three seeds), and on the shipped registry.
- *AC4, "the file is unchanged afterwards"*: compared as content, every row of every table of the file (Core tables, `sqlite_schema` and module tables), after each refused write. The file's bytes are not compared: accepted writes change them in the same run.
- *AC5, "through the vilicus-testbed binary only"*: the testbed's labels are confirmed by the fuzz test it runs, in files that test creates; the Core's own unit tests confirm labels through the crate-private function. No public function confirms a label.

**Open points**
- *Design documents* (coordinator):
  - Drafted decision, D146 "Field validation on write and reviewed-vocabulary labels": "Amends AD-6, AD-9, AD-26 and D104. Context: story 3.4 builds the field validation of D98 and the reviewed vocabularies of D104; D104 names a restricted alphabet without defining it, and the documents do not say where confirmed labels are kept. Decision: a field value is checked by `vilicus-module-api` against its declaration (storage class, then closed type or maximum length) and refused, never converted, when it is of another storage class than its kind's, so SQLite's affinity never converts a value; the Core runs that check on every write, in the write transaction, then checks a reviewed-vocabulary label against the labels confirmed in the file. A date is an RFC 3339 `full-date`, years 0000 to 9999; lengths count Unicode scalar values. A reviewed-vocabulary label is 1 to 32 characters from ASCII letters and digits, the precomposed letters of Latin-1 Supplement (without `×` and `÷`) and Latin Extended-A, and the separators space, hyphen and apostrophe, never at an end nor two in a row; labels compare exactly. Confirmed labels live in a Core table `_vocabulary` of each module file (vocabulary, label, confirming member, time), written by the Core only; a label is confirmed per vocabulary and per file. In V0.1 no surface confirms a label (FR-50); the write path fuzz test confirms labels in the files it creates. The fuzz test of D98 is a seeded generator over every write path of a registry, run by `cargo test` on the testbed's and the shipped registries; libFuzzer stays confined to `vilicus-proto` (D142). Consequences: labels in other scripts and the typographic apostrophe need a decision; a label used in several partitions is confirmed in each."
  - AD-6, drafted amendment of the validation sentence: "... and the Core validates every field against its declaration on every write, in the write transaction (its storage class, its closed type and its maximum length, and for a reviewed vocabulary a label confirmed in that file), refusing, never truncating or converting, a value outside it [ADOPTED, D98, D146]."
  - AD-26, drafted amendment of the Core table list: "the Core tables `_meta` (...), `_vocabulary` (the confirmed labels of the file's reviewed vocabularies, D146), `_journal`, ..."
  - `doc/README.md` glossary, **Reviewed vocabulary**: "... at most 32 characters from a restricted alphabet (Latin letters and digits, space, hyphen and apostrophe, D146) ..."; the glossary term stays.
- *Story 3.5*: the typed record API stamps the envelope and writes through `record::insert` and `record::update` (crate-private), so validation stays on every module write; a module must have no handle that executes SQL on a write connection. Its update adds the expected `rev`.
- *Story 3.6*: `_vocabulary` is created by `create` beside `_meta`; when the Core track creates the Core tables, it moves there.
- *Story 3.7*: the runner calls `check_stored_rows` on the migrated copy before swapping it in, so a back-fill that writes a value outside the declaration fails the migration. A second type guard, `STRICT` tables, still needs `quick_check` in the migration policy (Story 3.2); with every value checked by storage class on write and on back-fill, this story does not need it.
- *Story 3.10*: the reference module's reviewed vocabulary joins the testbed registry, whose fuzz test then drives its paths; if its tests need confirmed labels beyond the fuzz test, a testbed-only entry point is added then.
- *Epic 10*: the pipeline holds tool arguments to `Field::check_value` (AD-12); a label in a tool argument is checked against the file the tool writes.
- *A surface to confirm labels*: an adult action, with its row in FR-50 and the capability matrix, after V0.1.

## Result

All commands ran on 2026-10-21 (commit `b47e6c4`) in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch made inside a new Docker volume, with an empty target directory; the volume was removed afterwards. Mutations ran on another clone with its own target directory, never on the working tree. Each intermediate commit (`97f46f6`, `4ce1e7d`, `5e31b16`, `4c0dbcc`) passes clippy with `-D warnings` and the workspace tests.

Gates, as `.github/workflows/ci.yml` runs them:
- `python3 -m unittest discover -s ci`: `Ran 211 tests`, `OK` (unchanged).
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- System OpenSSL: `libssl-dev` `3.5.7-1~deb13u3`, `pkg-config` `3.5.7`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 325 passed, none failed (291 before the story): `vilicus-types` 44 and 9 examples (43 and 8 before), `vilicus-module-api` 36 and 9 examples (27 and 7), `vilicus-storage` 91 (84), `vilicus-core` 55 and 2 examples (44 and 1), `vilicus` 3 (2), `vilicus-testbed` 1 (0).
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`, unchanged.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `cargo tree --workspace -e features -i rusqlite`: `load_extension` appears nowhere (0 lines).
- The fuzz coverage check and the libFuzzer job are not concerned: `vilicus-proto` and `fuzz/` are unchanged; `fuzz/tests/coverage.rs` and `fuzz/tests/regressions.rs` pass in `cargo test`.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (FR-58, DC-53, D98, I40) | **Pass** | `record::tests::a_value_outside_its_closed_type_refuses_the_whole_write`: an unknown enumeration value (and one of another case), a number above and below its bounds, February 30 and a date in another form, an instant past year 9999, a version 4 UUID and a 15-byte one, `"12"` and `12.0` for an integer, the text of a UUID, the bytes of an enumeration value and `NULL` for a required field each refuse the insert with `RecordError::Invalid` naming the table, the field and the rule; every table of the file reads back unchanged after each, and `items` stays empty. `a_write_within_its_declaration_is_stored_as_given` (the accepted values read back byte for byte, optional fields `NULL`). `an_update_is_held_to_the_declaration_too` (the update path). Module API: `value::tests::a_value_of_another_storage_class_is_refused_never_converted`, `null_is_accepted_for_an_optional_field_only`, `an_enumeration_accepts_its_values_exactly`, `integers_and_timestamps_stay_in_their_range`, `dates_are_calendar_dates_in_one_form`, `uuids_are_16_byte_uuidv7_blobs`; types: `time::tests::full_dates_are_the_days_of_the_range` (every day of years 0000 to 9999 accepted, the day after each month's last refused). The storage layer, Deviations. |
| AC2 (FR-58, I40) | **Pass** | `a_value_longer_than_its_maximum_is_refused_never_truncated`: free text of 13 ASCII and of 13 two-byte characters for a maximum of 12, and a label of 33 characters, are refused with `TooLong`, no row (no truncated copy) is stored; 12 two-byte characters and a 32-character label are accepted and read back whole. `free_text_longer_than_its_maximum_is_refused_counted_in_characters` (ASCII, accented, CJK, emoji). `stored_rows_written_by_a_migration_are_checked` (a back-filled label too long is found). |
| AC3 (DC-59, D104, I40) | **Pass** | `only_confirmed_labels_of_the_restricted_alphabet_are_accepted`: three confirmed labels, one of exactly 32 characters with accents, an apostrophe and spaces, are accepted; an unconfirmed label and the confirmed one in another case or cut short are `UnconfirmedLabel`; a trailing space, `:`, a zero-width space, a line feed, `_` and the empty label are `InvalidLabel`; 33 characters are `TooLong`. `a_label_is_confirmed_only_in_its_own_vocabulary_and_file` (a label confirmed in `sides` is refused in `rooms`; one confirmed in a file is refused in another file of the module). `label_confirmation_checks_the_label_and_the_vocabulary` (a malformed or too long label and an undeclared vocabulary are not confirmed, and nothing is written). `labels_are_short_and_from_the_restricted_alphabet` (23 refused forms: separators at an end or doubled, punctuation, quotes, control, zero-width, bidi, a combining accent, `×`, `÷`, a no-break space, U+2019, an emoji, Cyrillic); `the_label_alphabet_holds_latin_letters_and_digits_only` (every character of Unicode: each letter of the alphabet is alphanumeric and at most U+017F). Storage: `tests::vocabulary::a_confirmed_label_is_recorded_once_and_compared_exactly`, `every_vocabulary_statement_is_refused_in_a_migration`, `every_vocabulary_write_is_refused_on_a_write_handle`, `a_trigger_that_confirms_a_label_is_refused_when_it_fires` (with their control `without_the_authorizer_every_vocabulary_statement_runs`), `every_core_table_is_created_strict_and_without_rowid`. |
| AC4 (DC-53, I40) | **Pass**, with a seeded generator rather than libFuzzer (Deviations) | `vilicus-testbed` `registry::tests::every_registered_write_path_refuses_values_outside_its_declaration` (the testbed registry, empty until Story 3.10, two seeds, 256 rounds) and `vilicus` `every_shipped_write_path_refuses_values_outside_its_declaration`. On probe modules: `record::tests::the_write_path_fuzz_refuses_every_value_outside_its_declaration`, two modules, three tables, every field kind required and optional, a full-range integer, three seeds of 64 rounds: the report lists exactly an insert and an update per table, more than 500 writes refused, each with the error of the rule its value breaks and every table of the file unchanged, and more than 100 valid writes accepted, then every stored row passes `check_stored_rows`. `the_fuzz_test_runs_on_files_it_creates` (a second run in the same directory is refused, the file exists). |
| AC5 (FR-58) | **Pass** | `confirm_label` is crate-private: the `compile_fail` example of `vilicus_core::record` (E0603) shows it out of reach of every other crate; no public function of the Core confirms a label. Outside the Core's unit tests, labels are confirmed only by the fuzz test in files it creates, which the testbed runs. Module SQL cannot confirm one (AC3 storage tests). FR-50 is unchanged. |

Mutations, each on the clone at `b47e6c4`, the file restored after each, the named packages tested with `--no-fail-fast`. The unmutated clone passed the same tests in the same setup. 25 of 26 mutations made the named tests fail; the survivor is explained after the list. "Both fuzz tests" are `the_write_path_fuzz_refuses_every_value_outside_its_declaration` and `the_fuzz_test_runs_on_files_it_creates`, which fuzzes before it checks the second run; the testbed and shipped fuzz tests drive no module in V0.1, so no mutation reaches them.
- **Value rules (`vilicus-module-api`, `vilicus-types`):**
  - storage class unchecked: `a_value_of_another_storage_class_is_refused_never_converted`, `uuids_are_16_byte_uuidv7_blobs`, `a_value_outside_its_closed_type_refuses_the_whole_write`, `stored_rows_written_by_a_migration_are_checked`, both fuzz tests;
  - `NULL` accepted for a required field: `null_is_accepted_for_an_optional_field_only`, `a_value_outside_its_closed_type_refuses_the_whole_write`, `an_update_is_held_to_the_declaration_too`, both fuzz tests;
  - enumeration, integer range, date, timestamp range, UUID, each unchecked: its value test, `a_value_outside_its_closed_type_refuses_the_whole_write` and both fuzz tests;
  - free text length unchecked: `free_text_longer_than_its_maximum_is_refused_counted_in_characters`, `a_value_longer_than_its_maximum_is_refused_never_truncated`, `an_update_is_held_to_the_declaration_too`, `stored_rows_written_by_a_migration_are_checked`, both fuzz tests;
  - label length unchecked (128 allowed): `labels_are_short_and_from_the_restricted_alphabet`, `a_value_longer_than_its_maximum_is_refused_never_truncated`, `only_confirmed_labels_of_the_restricted_alphabet_are_accepted`, `label_confirmation_checks_the_label_and_the_vocabulary`, both fuzz tests;
  - any character a label letter, and combining accents and the zero-width space added to the alphabet, each: `labels_are_short_and_from_the_restricted_alphabet`, `the_label_alphabet_holds_latin_letters_and_digits_only`, `only_confirmed_labels_of_the_restricted_alphabet_are_accepted`, `label_confirmation_checks_the_label_and_the_vocabulary`, both fuzz tests;
  - a separator at the end accepted: the same but the alphabet test; separators in a row accepted: `labels_are_short_and_from_the_restricted_alphabet`, both fuzz tests;
  - any day 1 to 31 a full date: `full_dates_are_the_days_of_the_range`, `dates_are_calendar_dates_in_one_form`, `a_value_outside_its_closed_type_refuses_the_whole_write`, both fuzz tests.
- **Row writer (`vilicus-core`):**
  - the field check removed from writes: seven record tests, both fuzz tests among them;
  - label membership unchecked: `only_confirmed_labels_of_the_restricted_alphabet_are_accepted`, `a_label_is_confirmed_only_in_its_own_vocabulary_and_file`, `an_update_is_held_to_the_declaration_too`, `stored_rows_written_by_a_migration_are_checked`, both fuzz tests;
  - required fields not required on insert, a field given twice accepted, undeclared fields ignored, each: `a_write_names_declared_columns_once_and_every_required_one`, `an_update_is_held_to_the_declaration_too`, both fuzz tests;
  - envelope class unchecked: `a_write_names_declared_columns_once_and_every_required_one`;
  - stored rows unchecked: `stored_rows_written_by_a_migration_are_checked`;
  - the label form unchecked at confirmation, an undeclared vocabulary confirmable, each: `label_confirmation_checks_the_label_and_the_vocabulary`.
- **Storage:**
  - labels compared ignoring case: `a_confirmed_label_is_recorded_once_and_compared_exactly`, `only_confirmed_labels_of_the_restricted_alphabet_are_accepted`, the probe fuzz test;
  - `_vocabulary` out of `CORE_TABLES`: the five refusal tests of `tests::vocabulary` (module SQL then writes the table), every record test (the Core policy then cannot confirm a label) and the registry tests that open a file (the table is then a module table no declaration names).
- **Survivor:** a refused write committed instead of rolled back. Every check runs before the write's one statement, so a refusal leaves nothing to commit, and a failing statement is atomic on its own; the rollback is not load-bearing until Story 3.5 adds the journal row to the same transaction, whose tests must then show it.
