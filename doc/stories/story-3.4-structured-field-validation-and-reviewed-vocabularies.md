---
title: 'Structured field validation and reviewed vocabularies'
epic: 3
story: 4
status: done
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

**What was built** (as revised after the review of 2026-10-21, table at the end of Result)
- `crates/vilicus-types/`:
  - `time.rs`: `is_full_date`, the RFC 3339 `full-date` grammar as a `const fn`, years 0000 to 9999 like `UtcMillis`, reusing the calendar functions already there.
  - `label.rs` (review m1, m5): the reviewed-vocabulary label grammar, so the module port and the storage layer hold one rule: `VOCABULARY_LABEL_MAX_LEN` (32), `VOCABULARY_LABEL_SEPARATORS` (space, hyphen, apostrophe U+0027), `is_vocabulary_label_letter` (ASCII letters and digits, the precomposed letters of Latin-1 Supplement without `×` and `÷` and of Latin Extended-A, minus the letters NFKC changes, `Ĳ ĳ Ŀ ŀ ŉ ſ`, and the confusables `ı` and `ĸ`) and `is_vocabulary_label` (1 to 32 characters, letters and separators, a letter at each end, no two separators in a row). A test derives the exclusion from the NFKC tables of `unicode-normalization` (a dev-dependency, the crate and version `vilicus-proto` already uses; `Cargo.lock` gains one line).
  - `source.rs` (review M1): the text form of a `Source`, the spine conventions' notation: `Display` writes `system` or `<kind>(<payload>)` (an id's lowercase hyphenated text, or a module name), `Source::parse` reads exactly that form and nothing else.
- `crates/vilicus-module-api/src/value.rs`:
  - `Value`, one value of a field in one of SQLite's storage classes: `Null`, `Integer`, `Real`, `Text`, `Blob`. `Real` exists so a floating-point value has a form to be refused in.
  - `Field::check_value(&Value) -> Result<(), ValueError>`: `Null` for an optional field only, then the storage class of the field's kind, never converted, then the kind's rule:
    - free text: every character allowed by `is_free_text_character` (review m7), then at most `max_len` characters (Unicode scalar values);
    - enumeration: exactly one of the declared values; integer: in `min..=max`; date: `is_full_date`; timestamp: in the range of `UtcMillis`; UUID: 16 bytes that `Id::from_bytes` accepts;
    - reviewed vocabulary: `check_vocabulary_label`, the `vilicus-types` grammar (`TooLong` past 32 characters, `InvalidLabel` otherwise); whether it is confirmed is the Core's check, which needs the file.
  - `is_free_text_character` (review m7): any Unicode scalar value but NUL and the other C0 controls except tab and line feed (carriage return refused), DEL and the C1 controls, the bidi embedding, override and isolate controls U+202A to U+202E and U+2066 to U+2069, U+200B, U+2060 and U+FEFF. The zero-width joiner and non-joiner stay. Nothing is cleaned: a text holding a refused character is refused.
  - `ValueError`: `Null`, `StorageClass { expected }`, `NotInEnumeration`, `OutOfRange`, `InvalidDate`, `InvalidUuid`, `TooLong { max_len }`, `InvalidLabel`, `InvalidCharacter`. No variant carries the value.
- `crates/vilicus-module-api/src/check.rs` (review m3): `FREE_TEXT_MAX_LEN` (1 Mi characters), above which a free-text declaration is refused (`DeclarationError::FreeTextTooLong`), so every declared maximum can be exceeded by the fuzz test.
- `crates/vilicus-storage/`:
  - a Core table `_vocabulary (vocabulary, label, confirmed_by, confirmed_at)`, `STRICT, WITHOUT ROWID`, primary key `(vocabulary, label)`, created by `create` beside `_meta` and named in `CORE_TABLES`, so no module SQL can write, drop, alter, index or watch it;
  - `Handle<Write>::confirm_vocabulary_label`, under the Core policy in one `BEGIN IMMEDIATE` transaction, refusing a label outside `is_vocabulary_label` with `Error::InvalidVocabularyLabel` before any statement (review m1, defence in depth); a label confirmed again keeps its first confirmation;
  - `Handle<R: Inspect>::is_confirmed_label`, an exact comparison;
  - `SqlValue`, `Handle::execute_values` and `Handle::query_values`, so the Core binds and reads values by storage class without depending on `rusqlite`;
  - `in_transaction`, the runner of the Core's own statements, rolls back when the `COMMIT` fails too (review m2), and `write_meta` uses it.
- `crates/vilicus-core/src/record/` (`pub mod record`):
  - `mod.rs`, the row writer every record write goes through, crate-private (`insert`, `update`, `confirm_label`, `check_stored_rows`):
    - each write runs in one `BEGIN IMMEDIATE` transaction: the envelope columns are checked (each an `ENVELOPE` column, given once, in its stored form, all of them on insert, never `id` on update), then the fields (each declared, given once, `Field::check_value`, then a reviewed-vocabulary label against `is_confirmed_label` under the write lock; every required field on insert); only then does the statement run. Any refusal, and a failed `COMMIT` (review m2), rolls back.
    - `RecordError`: `UnknownTable`, `UnknownColumn`, `DuplicateColumn`, `MissingColumn`, `IdChanged`, `EmptyUpdate`, `Invalid`, `InvalidEnvelope`, `UnconfirmedLabel`, `UnknownVocabulary`, `InvalidLabel`, `RecordNotFound`, `Storage`. It names declared tables and columns only.
    - `check_stored_rows` reads every row back, envelope and fields (review M1).
    - Until Story 3.5 calls the row writer, only the tests and the fuzz test do; a build without either allows `dead_code` in this module, with that reason.
  - `envelope.rs` (review M1): the stored form of each envelope column and its check, by the column's name in `ENVELOPE` (a test fails when a column has no rule): `id` a 16-byte UUIDv7, `author` `NULL` or one; `source` the `Source` text form; `taint` a name of `Taint::ALL` (so never `member`); `data_types` the names of a non-empty subset of the record kind's declared types, each once, in the order of `DataType::ALL`, joined by commas (`data_types_text`); `created_at` and `updated_at` within years 0000 to 9999; `rev` 1 or more.
  - `fuzz.rs`, `Registry::fuzz_write_paths(directory, key, seed, rounds) -> Result<WriteFuzzReport, WriteFuzzError>`, compiled only with the `testing` feature of `vilicus-core` or in its own tests (review m1): for each module, creates and migrates its household file in `directory`, confirms four generated labels per vocabulary (one of 32 characters), then for each table:
    - once per field, each value outside the declaration the generator knows for its kind, on the insert and on the update: the field's valid value in each other storage class, `NULL` for a required field, enumeration neighbours, the integers on each side of the range and the `i64` ends, invalid dates, out-of-range instants, UUID bytes of another version, variant or length, free text one character past its maximum (any maximum, review m3) and free text holding a refused character, an unconfirmed label, a label confirmed only in another vocabulary of the module (review m3), a label too long, with a character outside the alphabet or a separator at an end; a required field left out, a field given twice and an undeclared column;
    - once per envelope column, each value outside its stored form (review m3): another class, `NULL` where required, ids and authors that are not UUIDv7s, out-of-range times, a `rev` below 1, forged sources, taints outside the stored set (`member` included), data types undeclared, duplicated, out of order, unknown or empty; on the update, every value given for `id`, valid or not, is `IdChanged`; and an update of a record the table does not hold (review m3);
    - `rounds` random rounds: up to three fields made invalid at once (insert and update), then a valid insert and a valid update;
    - every invalid write must be refused with the error of a rule it breaks and leave every row of every table of the file unchanged; every valid write must be accepted; at the end `check_stored_rows` must pass. Seeded SplitMix64, so a failure replays from its seed.
  - `registry/mod.rs`: `create_migrated`, shared by `verify_migrations` and the fuzz test; `Registry::open` is crate-private (review m1): a handle executes raw SQL, so outside the Core it would write around validation (`compile_fail` example, E0624).
  - `Cargo.toml`: the `testing` feature.
- `testing/vilicus-testbed/`: the testbed's `const` registry (`#[cfg(test)] mod registry;`), empty until Story 3.10, and `every_registered_write_path_refuses_values_outside_its_declaration` (two seeds, 256 rounds: an insert and an update per table, and, when there is a table, refused and accepted writes, review m3); `vilicus-core` with `features = ["testing"]`.
- `crates/vilicus/`: `every_shipped_write_path_refuses_values_outside_its_declaration`, the same over the shipped registry (empty in V0.1); `vilicus-core` with `testing` as a dev-dependency only, so `cargo build -p vilicus` does not compile the fuzz test (checked: `cargo tree -p vilicus -e features,normal,build -i vilicus-core` lists only `default`).
- `ci/check_packaging.py` (review m1): fails when a release artefact's package, or a crate it links, enables `testing` through a normal or build dependency or in a feature of its own; a dev-dependency may. Three tests in `test_check_packaging.py`.

**Decisions and why** (choices the documents leave open; drafted texts under Open points)
- *Where validation lives*: the rule of a value against its declaration is `vilicus-module-api`'s (`Field::check_value`), so the pipeline can hold tool arguments to the same rule (AD-12, Epic 10); the label grammar is `vilicus-types`', so the storage layer applies it too; the Core runs the checks on every write, in the write transaction, and adds what needs the file, label confirmation and the envelope's stored form; the storage layer binds values and stores labels and knows no declaration, as Story 3.2 placed it. What it gives up: "the storage layer validates" (D98, AD-6) reads as the Core's write path over `vilicus-storage`, as AD-9 already says.
- *Values keep their storage class*: a value of another class is refused even when SQLite's column affinity would convert it (`"12"` into an `INTEGER` column is stored as 12, which the back-fill test observes). With `STRICT` not required (Story 3.2), this is the only type guard on writes.
- *The date form* is RFC 3339 `full-date`, years 0000 to 9999, refused rather than normalized.
- *Maximum lengths*: free text counts Unicode scalar values, at most `FREE_TEXT_MAX_LEN` declared; a structured value's length is bounded by its kind.
- *The character set of free text* (I40 names a character set without defining one for free text): controls, bidi embedding, override and isolate controls and the invisible U+200B, U+2060 and U+FEFF are refused; carriage return too, so a line ends with a line feed alone and clients send LF; the joiners stay for emoji and scripts that need them; the bidi marks U+200E, U+200F and U+061C stay, being marks that reorder nothing around them. Refused, never cleaned.
- *The restricted alphabet* (D104 names it without defining it): ASCII letters and digits, precomposed Latin-1 Supplement and Latin Extended-A letters that NFKC leaves unchanged, without the confusable `ı` and `ĸ`, and three separators; labels are short names, so `& . ° ( /` and every other punctuation stay refused; labels compare exactly. Clients map the typographic apostrophe U+2019 to U+0027 before sending a label. What it gives up: labels in other scripts.
- *Where confirmed labels live*: a Core table `_vocabulary` in each module file, written under the Core policy: the check reads the same file in the same transaction (AD-5), the labels are encrypted under the file's key and follow its partition. A label is confirmed per vocabulary and per file. What it gives up: a label used in several partitions is confirmed in each.
- *The envelope's stored form* (review M1): the Core has written no envelope yet, so this story fixes the forms its check holds them to: the `source` notation of the spine conventions, the `Taint` names, the comma-joined `DataType` names in `DataType::ALL` order. Story 3.5 stamps the envelope in these forms or changes them together with `envelope::check`.
- *Writes closed to other crates* (review m1): the row writer, label confirmation and `Registry::open` are crate-private; the fuzz test, the only public entry that confirms labels (in files it creates), compiles only with the `testing` feature, which `ci/check_packaging.py` keeps out of release artefacts.
- *Stored rows*: `check_stored_rows` reads every row back, envelope included, the answer to Story 3.2's open point on back-fills; the migration runner of Story 3.7 calls it on the migrated copy before it is swapped in.

**Files**
- `crates/vilicus-types/`: `Cargo.toml`, `src/time.rs`, `src/label.rs` (new), `src/source.rs`, `src/lib.rs`; `Cargo.lock`
- `crates/vilicus-module-api/src/`: `value.rs` (new), `check.rs`, `lib.rs`, `tests.rs`
- `crates/vilicus-storage/src/`: `authorizer.rs`, `error.rs`, `handle.rs`, `lib.rs`, `tests/mod.rs`, `tests/vocabulary.rs` (new)
- `crates/vilicus-core/`: `Cargo.toml`, `src/lib.rs`, `src/registry/mod.rs`, `src/record/mod.rs`, `src/record/envelope.rs`, `src/record/fuzz.rs`, `src/record/tests.rs` (new)
- `testing/vilicus-testbed/`: `Cargo.toml`, `src/main.rs`, `src/registry.rs` (new)
- `crates/vilicus/`: `Cargo.toml`, `src/registry.rs`
- `ci/check_packaging.py`, `ci/test_check_packaging.py`
- `doc/stories/sprint-status.yaml` (3.4 `review`)

**Deviations**
- *AC1 and AC2, "the storage layer"*: the Core's row writer over `vilicus-storage` (Decisions). Every write path that exists today goes through it and no crate outside the Core can reach a write handle; the typed record API of Story 3.5, which modules will call, must keep that (Open points).
- *AC4, "the fuzz test"*: a seeded generator of out-of-declaration values run by `cargo test`, not a coverage-guided libFuzzer target: D142 confines `libfuzzer-sys` to `vilicus-fuzz`, which may depend on `vilicus-proto` only. The generator is systematic per field kind and per envelope column, on both paths, and random on top.
- *AC4, "every module write path registered in the testbed"*: the testbed registers no module until Story 3.10, so its test drives no path today; it checks an insert and an update per table and, when there is a table, refused and accepted writes, which holds the reference module to the test when it joins. The fuzz test is exercised on probe modules in the Core's tests.
- *AC4, "the file is unchanged afterwards"*: compared as content, every row of every table of the file (Core tables, `sqlite_schema` and module tables), after each refused write; not as bytes, since accepted writes change them in the same run.
- *AC5, "through the vilicus-testbed binary only"*: no public function confirms a label. The Core's unit tests confirm labels through the crate-private `confirm_label`; outside them, only the fuzz test confirms labels, in the scratch files it creates, and it is compiled only with the `testing` feature, which the testbed and the binary's tests enable and no release artefact may (`ci/check_packaging.py`). Module SQL cannot write `_vocabulary`, and the storage layer refuses a malformed label whoever calls it.

**Open points**
- *Design documents* (coordinator):
  - Drafted decision, D146 "Field validation on write, reviewed-vocabulary labels and the envelope's stored form": "Amends AD-6, AD-9, AD-26 and D104. Context: story 3.4 builds the field validation of D98 and the reviewed vocabularies of D104; D104 names a restricted alphabet and I40 a character set without defining them, the documents do not say where confirmed labels are kept, and its review found that a back-fill could forge a record's envelope. Decision: a field value is checked by `vilicus-module-api` against its declaration (storage class, then closed type, or character set and maximum length for free text) and refused, never converted or cleaned; the Core runs that check on every write, in the write transaction, then checks a reviewed-vocabulary label against the labels confirmed in the file, and holds every envelope column to its stored form: `id` a 16-byte UUIDv7, `author` NULL or one, `source` the conventions' notation (`system`, `<kind>(<id>)`, `module(<name>)`), `taint` `trusted` or `external`, `data_types` a non-empty subset of the record kind's declared types in the order of the closed set, joined by commas, times within years 0000 to 9999, `rev` 1 or more; the same checks read every stored row back after a migration. A date is an RFC 3339 `full-date`. Free text counts Unicode scalar values, declares at most 2^20 of them, and refuses NUL and the other C0 controls but tab and line feed (carriage return included), DEL and the C1 controls, U+202A to U+202E, U+2066 to U+2069, U+200B, U+2060 and U+FEFF; the joiners U+200C and U+200D are allowed. A reviewed-vocabulary label is 1 to 32 characters from ASCII letters and digits and the precomposed letters of Latin-1 Supplement (without `×` and `÷`) and Latin Extended-A that NFKC leaves unchanged, without the confusables U+0131 and U+0138, and the separators space, hyphen and apostrophe U+0027, never at an end nor two in a row; every other punctuation (`& . ° ( /` included) is refused; clients map the typographic apostrophe U+2019 to U+0027 before sending a label; labels compare exactly. Confirmed labels live in a Core table `_vocabulary` of each module file (vocabulary, label, confirming member, time), written by the Core only, which refuses a malformed label; a label is confirmed per vocabulary and per file. In V0.1 no surface confirms a label (FR-50). The fuzz test of D98 is a seeded generator over every write path of a registry, fields and envelope, compiled only with the `testing` feature of `vilicus-core`, which no release artefact enables; libFuzzer stays confined to `vilicus-proto` (D142). Consequences: labels in other scripts need a decision; a label used in several partitions is confirmed in each; Story 3.5 stamps the envelope in these forms."
  - AD-6, drafted amendment of the validation sentence: "... and the Core validates every field against its declaration on every write, in the write transaction (its storage class, its closed type, or its character set and maximum length for free text, and for a reviewed vocabulary a label confirmed in that file), and every envelope column against its stored form, refusing, never truncating, converting or cleaning, a value outside it; the same checks read every row back after a migration [ADOPTED, D98, D146]."
  - AD-26, drafted amendment of the Core table list: "the Core tables `_meta` (...), `_vocabulary` (the confirmed labels of the file's reviewed vocabularies, written by the Core only, D146), `_journal`, ..."
  - `doc/README.md` glossary, **Reviewed vocabulary**: "A run-time list of labels (tags, categories, room, scene, mode or ingredient names) whose every new label an adult confirms, at most 32 characters of Latin letters, digits, spaces, hyphens and apostrophes (see D104, D146); only confirmed labels are structured values".
- *Story 3.5*: the typed record API stamps the envelope in the stored forms of `record::envelope` (or changes them with its check) and writes through `record::insert` and `record::update`; a module gets no handle that executes SQL on a write connection. Its update adds the expected `rev`, and its journal row joins the write transaction, whose rollback then becomes load-bearing.
- *Story 3.6*: `_vocabulary` is created by `create` beside `_meta`; when the Core track creates the Core tables, it moves there.
- *Story 3.7*: the runner calls `check_stored_rows` on the migrated copy before swapping it in. `STRICT` tables (which need `quick_check` in the migration policy) are not needed for type safety with that check.
- *Story 3.10*: the reference module joins the testbed registry, whose fuzz test then drives its paths; a testbed-only seeding entry, behind `testing`, if its tests need labels beyond the fuzz test.
- *Epic 10*: the pipeline holds tool arguments to `Field::check_value` (AD-12).
- *A surface to confirm labels*: an adult action, with its row in FR-50 and the capability matrix, after V0.1.

## Result

All commands ran on 2026-10-21, last after the review fixes (commit `d922033`), in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch made inside a new Docker volume, with an empty target directory; the volume was removed afterwards. Mutations ran on another clone (the tree of `d922033`, committed then as `4e3d212` before the commits were regrouped so that each builds) with its own target directory, never on the working tree. Each intermediate commit (`97f46f6`, `4ce1e7d`, `5e31b16`, `4c0dbcc`, `b47e6c4`, and after the review `fd3ad94`, `64660c6`, `c00a6eb`, `5fd1aa2`) passes clippy with `-D warnings` and the workspace tests.

Gates, as `.github/workflows/ci.yml` runs them:
- `python3 -m unittest discover -s ci`: `Ran 214 tests`, `OK` (211 before; 3 in `test_check_packaging.py`).
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- System OpenSSL: `libssl-dev` `3.5.7-1~deb13u3`, `pkg-config` `3.5.7`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0. Also `cargo clippy -p vilicus-core --lib` and `cargo clippy -p vilicus` without the `testing` feature: clean.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 341 passed, none failed (291 before the story): `vilicus-types` 47 and 11 examples (43 and 8 before), `vilicus-module-api` 36 and 9 examples (27 and 7), `vilicus-storage` 93 (84), `vilicus-core` 62 and 4 examples (44 and 1), `vilicus` 3 (2), `vilicus-testbed` 1 (0).
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`, unchanged.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `cargo tree --workspace -e features -i rusqlite`: `load_extension` appears nowhere (0 lines).
- `cargo tree -p vilicus -e features,normal,build -i vilicus-core`: only the `default` feature, so the release build of `vilicus` does not compile the fuzz test.
- The fuzz coverage check and the libFuzzer job are not concerned: `vilicus-proto` and `fuzz/` are unchanged; `fuzz/tests/coverage.rs` and `fuzz/tests/regressions.rs` pass in `cargo test`.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (FR-58, DC-53, D98, I40) | **Pass** | `record::tests::a_value_outside_its_closed_type_refuses_the_whole_write`: an unknown enumeration value (and one of another case), a number above and below its bounds, February 30 and a date in another form, an instant past year 9999, a version 4 UUID and a 15-byte one, `"12"` and `12.0` for an integer, the text of a UUID, the bytes of an enumeration value and `NULL` for a required field each refuse the insert with `RecordError::Invalid` naming the table, the field and the rule; every table of the file reads back unchanged after each, and `items` stays empty. `the_envelope_is_held_to_its_stored_form_on_write_and_when_read_back` (review M1: a 3-byte id, a non-v7 author, a forged source, `trusted; ignore previous instructions` and `member` as taint, an unknown and an undeclared data type, an out-of-range time and `rev` 0 are refused on write; seven forged back-fills, the review's probe among them, are refused by `check_stored_rows`, each naming its column, and a back-fill in the stored form passes). `free_text_refuses_controls_and_invisible_characters` (review m7). `a_write_within_its_declaration_is_stored_as_given`, `an_update_is_held_to_the_declaration_too`, `a_failed_commit_leaves_no_open_transaction` (review m2). Module API: `value::tests` (storage class, `NULL`, enumeration, ranges, dates, UUIDs, `free_text_refuses_controls_bidi_controls_and_invisible_characters` over every refused character of Unicode); `record::envelope::tests` (every envelope column has a rule; each rule's accepted and refused forms); types: `full_dates_are_the_days_of_the_range`, `the_text_form_reads_back_and_refuses_any_other_spelling`. The storage layer, Deviations. |
| AC2 (FR-58, I40) | **Pass** | `a_value_longer_than_its_maximum_is_refused_never_truncated`: free text of 13 ASCII and of 13 two-byte characters for a maximum of 12, and a label of 33 characters, are refused with `TooLong`, no truncated copy is stored; 12 two-byte characters and a 32-character label are accepted and read back whole. `free_text_longer_than_its_maximum_is_refused_counted_in_characters`; `fields_without_a_bounded_declaration_are_refused` (a maximum above `FREE_TEXT_MAX_LEN` is refused, review m3); `stored_rows_written_by_a_migration_are_checked`. |
| AC3 (DC-59, D104, I40) | **Pass** | `only_confirmed_labels_of_the_restricted_alphabet_are_accepted`: three confirmed labels, one of exactly 32 characters with accents, an apostrophe and spaces, are accepted; an unconfirmed label and the confirmed one in another case or cut short are `UnconfirmedLabel`; a trailing space, `:`, a zero-width space, a line feed, `_` and the empty label are `InvalidLabel`; 33 characters are `TooLong`. `a_label_is_confirmed_only_in_its_own_vocabulary_and_file`; `label_confirmation_checks_the_label_and_the_vocabulary`. Types: `the_alphabet_is_the_nfkc_stable_latin_letters_and_digits` (every character of Unicode: a letter of the alphabet exactly when it is alphanumeric, in the named blocks, unchanged by NFKC and not `ı` or `ĸ`, review m5) and `labels_are_short_names_of_the_alphabet` (refused forms, the review's `& . ° ( /`, U+2019 and NFKC-unstable letters among them, review m6). Storage: `tests::vocabulary` (module SQL in a migration, on a write handle or in a trigger cannot write `_vocabulary`; exact comparison; `a_label_outside_the_form_is_not_confirmed`, review m1). |
| AC4 (DC-53, I40) | **Pass on probe modules; the testbed case is vacuous until Story 3.10** (review m4), with a seeded generator rather than libFuzzer (Deviations) | `record::tests::the_write_path_fuzz_refuses_every_value_outside_its_declaration`: two modules, three tables, every field kind required and optional, a full-range integer, three seeds of 64 rounds; the report lists exactly an insert and an update per table, more than 500 writes refused, each with the error of the rule its value breaks (fields and envelope, review m3) and every table of the file unchanged, more than 100 valid writes accepted, then every stored row passes `check_stored_rows`. `the_fuzz_test_runs_on_files_it_creates`. `vilicus-testbed` `every_registered_write_path_refuses_values_outside_its_declaration` and `vilicus` `every_shipped_write_path_refuses_values_outside_its_declaration` run the same test on registries that hold no module in V0.1, and require refused and accepted writes once a table exists. |
| AC5 (FR-58) | **Pass** | No public function confirms a label: `confirm_label`, `insert` and `Registry::open` are crate-private (`compile_fail` examples, E0603 and E0624). Outside the Core's unit tests, only the fuzz test confirms labels, in the scratch files it creates, and it compiles only with the `testing` feature, which `ci/check_packaging.py` refuses in a release artefact's dependencies (`test_test_feature_through_a_linked_dependency_fails`, `test_test_feature_in_a_feature_of_a_linked_crate_fails`, `test_test_feature_through_a_dev_dependency_passes`); the release build has only `default`. Module SQL cannot write `_vocabulary`, and the storage layer refuses a malformed label from any caller. FR-50 is unchanged. |

Mutations, second round, on the clone of the reviewed tree, each file restored after its mutation, the named packages tested with `--no-fail-fast` (`ci` with `unittest`). The unmutated clone passed the same tests. 45 of 45 made the named tests fail, the 25 killed in the first round rerun at their current place and 20 for the review's rules:
- **Value rules (`vilicus-module-api`, `vilicus-types`):**
  - storage class unchecked: `a_value_of_another_storage_class_is_refused_never_converted`, `uuids_are_16_byte_uuidv7_blobs`, `a_value_outside_its_closed_type_refuses_the_whole_write`, `stored_rows_written_by_a_migration_are_checked`, both fuzz tests;
  - `NULL` accepted for a required field; enumeration, integer range, date, timestamp range, UUID, free text length each unchecked: their value tests, the record tests of AC1 and AC2, both fuzz tests;
  - label length unchecked in the grammar: `labels_are_short_names_of_the_alphabet`; in the value check: six tests, both fuzz tests among them;
  - any character a label letter, and combining marks and U+200B added to the alphabet, each: both label tests of `vilicus-types`, `labels_are_short_and_from_the_restricted_alphabet`, `a_label_outside_the_form_is_not_confirmed` (storage), the label record tests and both fuzz tests;
  - NFKC-unstable and confusable letters kept (review m5): `the_alphabet_is_the_nfkc_stable_latin_letters_and_digits`, `labels_are_short_names_of_the_alphabet`, `labels_are_short_and_from_the_restricted_alphabet`;
  - a separator at the end accepted, separators in a row accepted, each: the label tests and both fuzz tests;
  - any day 1 to 31 a full date: `full_dates_are_the_days_of_the_range`, `dates_are_calendar_dates_in_one_form`, `a_value_outside_its_closed_type_refuses_the_whole_write`, both fuzz tests;
  - free text character set unchecked (review m7): both character set tests and both fuzz tests; bidi controls allowed, carriage return and C0 controls allowed, each: both character set tests;
  - a free-text maximum above `FREE_TEXT_MAX_LEN` accepted (review m3): `fields_without_a_bounded_declaration_are_refused`.
- **Row writer and envelope (`vilicus-core`):**
  - label membership unchecked, the field check removed from writes, required fields not required, a field given twice accepted, undeclared fields ignored, each: the record tests that write and both fuzz tests;
  - stored fields unchecked: `stored_rows_written_by_a_migration_are_checked`; label form unchecked at confirmation, an undeclared vocabulary confirmable, each: `label_confirmation_checks_the_label_and_the_vocabulary`;
  - envelope unchecked on write (review M1): `the_envelope_is_held_to_its_stored_form_on_write_and_when_read_back`, `a_write_names_declared_columns_once_and_every_required_one`, both fuzz tests; stored envelope unchecked: the first of these;
  - any blob an id or author, any integer a time, any integer a `rev`, any text a source, any text a taint, undeclared data types accepted, data types in any order or repeated, each: its `record::envelope::tests` test and both fuzz tests (and the envelope record test but for the last);
  - a source read without its closing parenthesis: `the_text_form_reads_back_and_refuses_any_other_spelling`;
  - `Registry::open` public (review m1): its `compile_fail` example, which then builds;
  - no rollback after a failed `COMMIT`, in the Core's write (review m2): `a_failed_commit_leaves_no_open_transaction`.
- **Storage:** labels compared ignoring case: `a_confirmed_label_is_recorded_once_and_compared_exactly`, `only_confirmed_labels_of_the_restricted_alphabet_are_accepted`; `_vocabulary` out of `CORE_TABLES`: the seven `tests::vocabulary` tests that write or read it; the label form unchecked at confirmation (review m1): `a_label_outside_the_form_is_not_confirmed`; no rollback after a failed `COMMIT` (review m2): `a_failed_commit_ends_the_transaction`.
- **CI:** the `testing` feature not refused in release artefacts (review m1): `test_test_feature_through_a_linked_dependency_fails`, `test_test_feature_in_a_feature_of_a_linked_crate_fails`.
- "Both fuzz tests" are `the_write_path_fuzz_refuses_every_value_outside_its_declaration` and `the_fuzz_test_runs_on_files_it_creates`, which fuzzes before it checks the second run; the testbed and shipped fuzz tests drive no module in V0.1, so no mutation reaches them.
- Not shown by a mutation: a refused write committed instead of rolled back. Every check runs before the write's one statement, so a refusal leaves nothing to commit; the rollback after a failed `COMMIT` is shown above, and the rollback of a refused write becomes load-bearing when Story 3.5 adds the journal row to the same transaction.

**Review of 2026-10-21** (independent review on PR #4, with the coordinator's decisions; each fix carries tests, and a mutation that removes it fails them, above):

| Item | Resolution |
|---|---|
| M1, `check_stored_rows` ignored the envelope | `record/envelope.rs` holds every envelope column to its stored form, on write (the row writer accepted any blob as id, the nit) and when rows are read back; the forms are fixed here for Story 3.5 to stamp (Decisions); the `source` text form is `vilicus-types`'. The review's probe is a case of `the_envelope_is_held_to_its_stored_form_on_write_and_when_read_back`. |
| m1, AC5 evidence and a latent bypass | `Registry::open` crate-private (E0624 example); the fuzz test behind the `testing` feature of `vilicus-core`, enabled by the testbed and the binary's dev-dependency only, refused in release artefacts by `ci/check_packaging.py`, absent from `cargo build -p vilicus`; the storage layer refuses a malformed label itself. AC5 text corrected. |
| m2, a failed COMMIT left the transaction open | Rolled back, in the Core's write and in the storage layer's `in_transaction` (now also `write_meta`'s); forced with a deferred foreign key on both sides. |
| m3, fuzz blind spots | A label confirmed in another vocabulary; envelope values outside their form on both paths, and every id given to an update; free text one character past any maximum, with `FREE_TEXT_MAX_LEN` bounding declarations; an update of a missing record; the testbed and shipped tests require refused and accepted writes once a table exists. |
| m4, AC4 status | "Pass on probe modules; the testbed case is vacuous until Story 3.10". |
| m5, NFKC and confusables | `Ĳ ĳ Ŀ ŀ ŉ ſ` (NFKC) and `ı ĸ` excluded; the test derives the NFKC part from `unicode-normalization`, a dev-dependency of `vilicus-types` already in the lockfile; the label grammar moved to `vilicus-types` so the storage layer shares it. |
| m6, U+2019 and punctuation | Clients map U+2019 to U+0027 (D146 draft); `& . ° ( /` refused and tested. |
| m7, free text character set | `is_free_text_character`: NUL, C0 but tab and line feed (carriage return refused), DEL, C1, U+202A to U+202E, U+2066 to U+2069, U+200B, U+2060, U+FEFF refused; joiners kept; never cleaned. |
| Nits | `MigrationTrack::Core` lists `_vocabulary`; the wrap of `create`'s documentation fixed. |
