---
title: 'Typed record writes with taint and data type stamping'
epic: 3
story: 5
status: review
author: Rwx-G
created: 2026-10-16
implements: [FR-18, FR-20, AD-6, AD-7, D70, D99, D104, D103, I9, I21, I35, I43]
---

# Story 3.5: Typed record writes with taint and data type stamping

As a project maintainer,
I want modules to write only through a typed record API on which the Core stamps the envelope, taint and data types,
So that no module can choose its own provenance label and derived data never launders into `trusted`.

**Acceptance Criteria:**

**AC1 (FR-18, AD-6)**
**Given** the typed record API of `vilicus-module-api`
**When** a module inserts, updates by id with an expected `rev`, or deletes by id
**Then** the Core stamps `id`, `source`, `author`, `created_at`, `updated_at` and bumps `rev` in the write transaction
**And** an update whose expected `rev` differs from the stored one is refused.

**AC2 (AD-7, I9)**
**Given** a write by a non-member principal deriving a record
**When** it does not declare its input record ids
**Then** it is refused
**And** when it declares them, the stored taint is the maximum of the inputs' taints, any `member` or `external` input storing `external`.

**AC3 (D103, I43)**
**Given** a derived record
**When** it is written
**Then** its stored `data_types` is the union of its inputs' sets, computed by the Core
**And** a write declaring a smaller set is refused (storage property test over random input sets).

**AC4 (FR-20, D70, D99, I35)**
**Given** a write a member makes or explicitly approves
**When** it is stored
**Then** its structured fields are stored `trusted` with that member as `author` and provenance to its inputs
**And** free text drafted in a tainted session stays `external` even when edited, while text the member wrote in full in an empty field is stored `trusted`.

**AC5 (D104, I35)**
**Given** a member-written field that contains 8 or more consecutive words of the assistant's draft
**When** it is stored
**Then** it is stored `external`, by a verbatim word-sequence test and not an edit ratio.

**AC6 (AD-6, AD-7, I21)**
**Given** any write
**When** it is stored
**Then** stored taint is never `member`
**And** a write whose principal is `Plugin` is stored `external` whatever taint the plugin claims.

**Dependencies:**
- Story 3.4 (field validation runs in the same write transaction)

**References:**
- `doc/prd.md` FR-18, FR-20
- `doc/architecture-spine.md` AD-6, AD-7
- `doc/ai-safety.md` P5, I9, I21, I35, I43
- `doc/decisions.md` D70, D99, D103, D104

## Implementation Notes

**What was built**
- `crates/vilicus-types/`:
  - `rev.rs`: `Rev`, a record's revision, 1 at insert (`Rev::FIRST`) and one more at each update (`next`, `None` past `i64::MAX`); `Rev::new` refuses a value below 1, and the envelope check reads `rev` through it.
  - `taint.rs`: `EffectiveTaint::for_viewer(stored, author, viewer)`, the read-time view of `doc/architecture.md` section 5.4 rule 4 (a `trusted` record authored by a member other than the viewer reads as `member`; with no viewer, every member-authored `trusted` record does), which a derivation applies to its inputs (AD-7) and Story 10.5 reuses for reads.
- `crates/vilicus-module-api/src/records.rs`, the module port (AD-9):
  - `trait Records`: `insert(table, fields, inputs) -> Written`, `update(table, id, expected: Rev, fields, inputs) -> Written`, `delete(table, id)`. A module gives the values of declared fields and the ids of the records the write is derived from; no method takes an envelope value, and none runs SQL. `Written { id, rev }`.
  - `WriteError`, what module code learns of a refusal, naming the declaration's tables and columns only: the field and table refusals of Story 3.4, `RecordNotFound`, `StaleRevision`, `MissingInputs`, `UnknownInput`, `UndeclaredDataType`, `CallRefused` (an earlier write of the call was refused) and `Failed` (a failure inside the Core).
  - `Id` and `Rev` re-exported, so a module crate needs no other dependency.
- `crates/vilicus-core/src/record/`:
  - `call.rs`: `run_call(handle, module, call, stamper, body)`, one call of a module in one `BEGIN IMMEDIATE` transaction on the module file's write handle; `body` receives a `&mut dyn Records`. The call commits only when `body` returns `Ok` and no write was refused; the first refused write ends the call (every later write gets `CallRefused`, and the call returns that refusal whatever `body` returns), and an error of `body`'s own is `RecordError::Aborted`; both roll back. `Call { principal, source, session, authority, read }`, built by the pipeline (Epic 10): `session` is the taint of what the call already consumed; `Authority::OwnAction { member }`, `Approved { member, written, drafts }` or `Unapproved { author, acting_for }`; `read` holds the provenance of records of other files the call read. `check_call` refuses an authority that does not fit the principal (`InconsistentCall`): an own action only from `Member` or `Cli`, which always act so, an approval only for `AiTask` or `Plugin`. `Stamper` supplies the time and the random bits of a new UUIDv7. `CallOutcome { value, changes }`, each `RecordChange { table, id, before, after, inputs }` being what Story 3.6 journals.
  - Per write: insert stamps `id` (UUIDv7 of the stamped time), `source` (the `Source` text form), `taint`, `data_types`, `author`, `created_at` = `updated_at` = now, `rev` 1; update reads the stored row in the transaction, refuses a stale `expected` (`StaleRevision`) or a missing record, and restamps `source`, `taint`, `data_types`, `author`, `updated_at` and `rev` + 1, never `id` or `created_at`; delete reads the stored `rev` and deletes. Inputs are resolved by the Core, each id once: a record of the file is read in the transaction, in whichever of the module's tables holds it, its envelope held to its stored form; otherwise a record of `Call::read`; otherwise `UnknownInput`. Everything then goes through the row writer of Story 3.4.
  - `provenance.rs`, the stamp:
    - taint: a `Plugin` or `Adapter` principal stores `external`, whatever else holds; an own action stores `trusted`; an approval stores the most restrictive label of its free-text values, a value being `trusted` when the session is not tainted, or when it equals a text the member wrote in full and repeats no run of `DRAFT_RUN_WORDS` (8) words of a draft, and `external` otherwise (a draft, an edited draft, any other text); structured fields count as `trusted`; an unapproved write stores the most restrictive of the session taint and of each input as `acting_for` sees it, `member` and `external` storing `external`, and an update counts the record it changes as one more input. An own-action or approved update keeps at least the record's old label while a field it does not give holds a value.
    - `copies_draft`: words are the maximal runs of alphanumeric characters, compared in lowercase; a run is taken within one draft.
    - data types: the union of the inputs' sets, or the table's declared set when the write has no input; an update adds the record's stored set; a type the table does not declare is refused (`UndeclaredDataType`).
    - author: the member for an own action or an approval; for an unapproved write, the author the call gives.
    - inputs: required (`MissingInputs`) for an unapproved write of any principal but `Plugin` and `Adapter`, on insert and update.
  - `mod.rs`: the row writer split into `insert_row` and `update_row`, which run inside a transaction their caller holds, and `insert` and `update`, which keep a transaction of their own for the tests and the write path fuzz test. Both take the union of the write's inputs' data types and refuse an envelope whose `data_types` misses one of them, or leaves `data_types` out (`DataTypesBelowInputs`), whoever computed the envelope. `in_write_transaction` returns the body's value. New `RecordError` variants: `StaleRevision`, `MissingInputs`, `UnknownInput`, `UndeclaredDataType`, `DataTypesBelowInputs`, `InconsistentCall`, `Aborted`.
  - `envelope.rs`: its documentation now says the typed API stamps these forms; `rev` checked through `Rev::new`.
  - `tests_call.rs`, the tests of this story; `tests.rs` exposes its helpers to it and wraps the row writer for its own tests; `fuzz.rs` passes no input to the row writer.
- No dependency and no crate graph edge added: `vilicus-module-api` and `vilicus-core` already depend on `vilicus-types`; `Cargo.lock` is unchanged.

**Decisions and why** (choices the documents leave open; drafted texts under Open points)
- *One taint per record* (D99, I35 and AC4 speak per field; the envelope has one `taint` column, frozen by D144): a record stores the most restrictive label of its parts. An approved write whose free text was drafted in a tainted session is stored `external` as a whole, its structured fields with it; one of structured fields and member-written text only is `trusted`. Why: one column cannot hold two labels, and storing `trusted` would launder the draft. What it gives up: the structured fields of such a record read as `external`, so reading them taints a session (more taint creep, R7); per-field labels need an envelope column, a decision of their own.
- *An update keeps the label of what it keeps*: a member's own or approved update leaves at least the record's old label while a field it does not give holds a value, so editing one field of an imported record does not promote its text (D45 keeps promotion at the host CLI); an unapproved update counts the record it changes as an input, so an assistant cannot turn another member's text into `trusted` for its own member by touching one field. A member who rewrites every field that holds a value makes the record `trusted` (co-authoring stays possible, AD-6).
- *Which writes must declare inputs* (AC2 says "a non-member principal deriving a record"): every insert and update of a call no member made or approved, except a plugin's and a device adapter's, whose writes are content from outside the household, stored `external` whatever their inputs (AD-7, I21). A declaration is at least one id; an update may name the record itself. What it gives up: an `AiTask` cannot create a record from nothing, which matches "conversation turns record their provenance" (AD-7) but means the AI double of Epic 10 declares an input.
- *Where inputs come from*: the module names ids; the Core reads each one's taint, author and data types, from the written file in the transaction, or from `Call::read`, the provenance the Core kept when it served the call a record of another file (no transaction spans two files, AD-5). An id the Core does not know is refused, so a module cannot invent a lower-labelled input.
- *Effective taint of inputs*: an input reads as the member the call acts for sees it (`acting_for`), the read-time view of section 5.4; with no such member (an adapter, a display), every member-authored `trusted` input reads as `member` and stores `external`.
- *The author of an unapproved write* is the pipeline's (`Unapproved::author`): the conventions name it for `Member`, `Cli`, rules, displays and adapters; for an AI task, the member it acts for, so its writes read as `member` to the other adult, like that member's own data.
- *Data types without inputs*: the table's declared set (a member typing a new record holds whatever the kind may hold); an update adds its inputs' set, or the declared set when it has none, to the stored one, so a set only grows; a computed set outside the declaration is refused rather than narrowed.
- *The approval's texts*: `written` are the texts the member wrote in full in an empty field, `drafts` the model's texts as drafted; a free-text value is `trusted` only when it equals one of `written` and repeats no 8-word run of a draft. A value the module derived from them in any other way keeps the session's label.
- *The verbatim test* (D104 says "8 consecutive words", "verbatim"): words are maximal runs of Unicode alphanumeric characters, compared in lowercase, so spacing, punctuation and case do not hide a copy; a run lies within one draft. What it gives up: a copy with one word changed every 7 words passes, which is the threshold D104 chose.
- *One transaction per call*: AD-9 has handlers run on the writer thread and a panic roll back "the transaction"; Story 10.7 undoes every record one write changed. A refused write therefore ends the call, even when module code swallows the error, so a call never commits half of its writes.
- *Clock and ids*: the Core has no durable clock (AD-30, Story 5.2) nor a random source yet, so `run_call` takes a `Stamper`; `vilicus-types` stays pure (`Id::new_v7` takes both).
- *Where it lives*: the port in `vilicus-module-api`, the implementation and the provenance rules in `vilicus-core` (AD-1: the Core decides). `run_call` is public but needs a `Handle<Write>`, which only the Core opens, so no crate outside the Core can write a row.

**Files**
- `crates/vilicus-types/src/`: `rev.rs` (new), `taint.rs`, `lib.rs`
- `crates/vilicus-module-api/src/`: `records.rs` (new), `lib.rs`, `declaration.rs`
- `crates/vilicus-core/src/`: `lib.rs`, `record/mod.rs`, `record/call.rs` (new), `record/provenance.rs` (new), `record/envelope.rs`, `record/fuzz.rs`, `record/tests.rs`, `record/tests_call.rs` (new)
- `doc/stories/sprint-status.yaml` (3.5 `review`)

**Deviations**
- *AC4, "its structured fields are stored `trusted`"*: true of a record without free text drafted in a tainted session; a record holding such text is stored `external` as a whole, its structured fields with it (Decisions, one taint per record). The stored label never claims more trust than the least trusted part. Story 10.6 AC5 and the I35 test read the same way until a decision says otherwise (Open points).
- *AC4, "provenance to its inputs"*: the call's outcome lists, for each record, the inputs its write declared (`RecordChange::inputs`), which the tests check; storing them is the `_journal` row of Story 3.6 (AD-26).
- *AC3, "a write declaring a smaller set is refused"*: no module and no model can declare a set, since the port has no such parameter (I43, "never declared by a module or a model"); the refusal is the row writer's, for an envelope any Core code computes, shown by the property test on insert and update.
- *AC6, "whatever taint the plugin claims"*: a plugin has no way to claim one: the port takes no envelope value, and an envelope column given as a field is refused (`UnknownColumn`). The stored label of a plugin's write is `external` even when its call is approved, its session clean and its inputs `trusted`.
- *AC1, "deletes by id"*: without an expected `rev`, as AD-9 writes it; the deleted record's `rev` is in the call's outcome for the journal.
- *AC2, "a non-member principal"*: read as a call no member made or approved; a member's approval of an AI task's request is a member's write (AC4), and plugins and adapters write content from outside the household rather than derive it (Decisions).

**Open points**
- *Design documents* (coordinator):
  - Drafted decision, D147 "Typed record writes: one transaction per call, provenance computed by the Core": "Amends AD-6, AD-7, AD-9, D99 and D103. Context: story 3.5 builds the typed record API; the documents state taint per field for approved writes while a record has one `taint` column (D144), and do not say which writes must declare inputs, where an input's provenance is read, what a record without inputs holds in `data_types`, or what a word of the verbatim test is. Decision: a module writes through `Records` of `vilicus-module-api` (insert, update by id with the expected `rev`, delete by id), giving field values and input record ids only; all writes of one call run in one `BEGIN IMMEDIATE` transaction, and a refused write rolls the whole call back. The Core stamps `id`, `source`, `author`, `created_at`, `updated_at` and `rev`, and computes `taint`: `external` for a `Plugin` or `Adapter` principal whatever else holds; `trusted` for a member's own action (`Member`, `Cli`); for an approved request of an `AiTask` or `Plugin`, the most restrictive label of its free text, a text being `trusted` when the session is not tainted or when it is a text the member wrote in full in an empty field and repeats no 8 consecutive words of a draft, and `external` otherwise; for any other call, the most restrictive of its session taint and of each input as the member the call acts for sees it, `member` and `external` storing `external`. A record stores one label, the most restrictive of its parts, so the structured fields of a record holding an approved draft from a tainted session read `external`. An update keeps at least the record's old label while it leaves a field holding a value, and an unapproved update counts the record it changes as an input. Every insert and update of a call no member made or approved declares at least one input, except a plugin's and an adapter's; the Core reads each input's taint, author and data types from the written file in the transaction, or from the provenance it kept when it served the call a record of another file, and refuses an id it does not know. `data_types` is the union of the inputs' sets, or the record kind's declared set without inputs; an update adds to the stored set; a set outside the kind's declaration is refused, and the row writer refuses any envelope whose set misses a type of the write's inputs. A word of the verbatim test is a maximal run of alphanumeric characters, compared in lowercase, and a run lies within one draft. The author is the member for an own action or an approval, otherwise the one the conventions give the principal, the member an AI task acts for included. Consequences: the structured fields of a record holding an approved draft taint a session that reads them; an AI task's write declares an input; per-field labels would need a new envelope column."
  - AD-6, drafted addition after the D104 verbatim-test clause: "... a verbatim test, not an edit ratio, over words that are maximal runs of alphanumeric characters compared in lowercase [ADOPTED, D104, D147]; a record stores one `taint`, the most restrictive label of its parts, and an update keeps at least the old label of the content it does not rewrite [D147]."
  - AD-7, drafted addition after "a module that derives a record declares its inputs and never chooses the label": "; every insert and update of a call no member made or approved declares at least one input, except a plugin's or an adapter's, and the Core reads each input's provenance itself, from the written file or from the provenance it kept when it served the call, refusing an input it does not know; an update counts the record it changes as an input [D147]".
  - AD-9, drafted amendment of the Writes sentence: "**Writes:** modules write only through the typed record API of `vilicus-module-api` (insert, update by id with the expected `rev`, delete by id), giving field values and input record ids, implemented by the Core over `vilicus-storage`; the writes of one call share one transaction, which a refused write rolls back whole [D147]."
  - Conventions, `source` vocabulary row, `author`: "... empty for `Display` and `Adapter`, and the member an AI task acts for when no member approved its write [D147]."
- *Story 3.6*: the `_journal` rows join `run_call`'s transaction, one per `RecordChange` (table, id, revisions and declared inputs; the before and after images read in the same transaction, the wrapped record key excluded, its decision task); the `call_id` check runs before `body`.
- *Story 3.9*: `run_call` has no unwind guard: a panic in `body` leaves the transaction open on the handle. The `catch_unwind` boundary of AD-9 rolls it back and marks the module faulted.
- *Story 3.10*: the reference module writes through `Records`; its testbed tests build a `Call` per principal.
- *Epic 10* (10.3, 10.5, 10.6, 10.7): the pipeline builds the `Call`: the principal, the `source` (the Core does not check that it fits the principal), the session taint, the authority with the approval screen's `written` and `drafts`, and `read`, the provenance of the records it served the call from other files. The durable clock (Story 5.2) and the Core's random source implement `Stamper`. Story 10.5 reuses `EffectiveTaint::for_viewer`. An undo (10.7) restores through the row writer with its journaled inputs' data types, so it can never lower a set.
- *Data types of an AI session* (needs a decision): `data_types` follows the inputs a module declares (AD-7); a model that read a type in its session and drives a write declaring other inputs can narrow the set of what it writes. Recommended: for `AiTask` and `Plugin` calls, the pipeline adds the data types the token read to every write, like session taint; what it gives up: records carry wider sets, and a write is refused when its kind does not declare a type the session read.
- *Per-field taint* (needs a decision if wanted): storing the structured fields of an approved draft as `trusted`, as D99 and I35 word it, needs a second label in the envelope (D144 freezes it), for example the label of the record's free text beside the record's.
- *The write path fuzz test* of Story 3.4 drives the row writer, which the typed path calls with the same field checks; the typed path's own refusals are the tests of this story.
- *`Display`* writes must declare inputs under this story's rule; the home milestone confirms it with the display's tools.

## Result

All commands ran on 2026-10-21 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch at `a98c4a7` made inside a new Docker volume, with an empty target directory; mutations ran on another clone of the same commit with its own target directory, never on the working tree; both volumes were removed afterwards. Each commit of the story (`2d415c6`, `94cf5db`, `a98c4a7`) builds and passes clippy with `-D warnings` and the workspace tests.

Gates, as `.github/workflows/ci.yml` runs them:
- `python3 -m unittest discover -s ci`: `Ran 214 tests`, `OK`.
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- System OpenSSL: `libssl-dev` `3.5.7-1~deb13u3`, `pkg-config` `3.5.7`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0. Also `cargo clippy -p vilicus-core --lib` and `cargo clippy -p vilicus` without the `testing` feature: clean.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 369 passed, none failed (341 before the story): `vilicus-core` 85 (62 before: 17 in `record::tests_call`, 6 in `record::provenance`), `vilicus-types` 49 and 13 examples (47 and 11), `vilicus-module-api` 36 and 10 examples (36 and 9); every other crate unchanged.
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`, unchanged.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `cargo tree --workspace -e features -i rusqlite`: `load_extension` appears nowhere (0 lines); `cargo tree -p vilicus -e features,normal,build -i vilicus-core`: only the `default` feature.
- `Cargo.lock` unchanged; no dependency or crate graph edge added. The fuzz coverage check and the libFuzzer job are not concerned: `vilicus-proto` and `fuzz/` are unchanged.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (FR-18, AD-6) | **Pass** | `the_core_stamps_the_envelope_of_an_insert`: an own-action insert giving two fields reads back with the stamped UUIDv7 (the stamper's time and random bits), `member(<id>)`, `trusted`, the table's data types, the member as author, both times at the stamped instant and `rev` 1, and in its stored form (`check_stored_rows`); the call's outcome lists the change. `an_update_bumps_rev_and_a_stale_one_is_refused`: an update by another member a minute later keeps `id` and `created_at`, restamps `source`, `author`, `updated_at` and sets `rev` 2; updates expecting `rev` 1 or 3 are `StaleRevision` and every table is unchanged. `a_delete_by_id_removes_the_record` (and `RecordNotFound` for a second delete and an update of the deleted record). `a_module_cannot_give_an_envelope_value`: each envelope column given as a field, on insert and update, is `UnknownColumn` with nothing changed. "In the write transaction": `a_refused_write_rolls_back_the_whole_call` (a refused second write rolls back the first even when module code returns `Ok`, later writes get `CallRefused`, an error of the code's own is `Aborted`, a clean call commits both writes); `a_call_whose_authority_does_not_fit_its_principal_is_refused` over every principal and authority. Types: `revisions_start_at_one_and_only_grow`. |
| AC2 (AD-7, I9) | **Pass** | `a_derived_write_without_inputs_is_refused`: for every principal but `Member`, `Cli`, `Plugin` and `Adapter`, an unapproved insert and update without inputs are `MissingInputs` and nothing changes; a plugin's or adapter's write needs none and is stored `external`; with an input, the change lists it. `a_derived_record_stores_the_most_restrictive_taint_of_its_inputs`: every non-empty subset of four inputs (`trusted` by the member the call acts for, `trusted` without author, `trusted` by the other member, `external`) in a clean and a tainted session stores `trusted` exactly when the session is clean and no input is the other member's or `external`; the author is the call's; an unknown input is `UnknownInput`. `inputs_of_other_files_and_the_updated_record_count`: an input of another file, from `Call::read`, counts as the other member's; an unapproved update of the other member's record stores `external`. Types: `another_members_trusted_record_reads_as_member`. |
| AC3 (D103, I43) | **Pass** | `a_derived_record_holds_the_union_of_its_inputs_data_types`, the storage property test: 96 seeded rounds of one to four inputs with random non-empty data type sets, each a record of the file or one the call read; the stored `data_types` is exactly their union; an update with one more input stores the union with the old set; in every round whose union holds two types or more, an insert and an update through the row writer whose set is a random strict subset of the union (more than 100 writes, asserted) are `DataTypesBelowInputs` with every table unchanged. `a_record_holds_only_data_types_its_table_declares`: without inputs, the table's set; an input of a type the table does not declare is `UndeclaredDataType`. Unit: `the_union_is_in_the_order_of_the_closed_set`. The set is never declared by a module (Deviations). |
| AC4 (FR-20, D70, D99, I35) | **Pass, one taint per record** (Deviations) | `a_member_write_is_stored_trusted_with_the_member_as_author`: an own action derived from an `external` record stores `trusted`, the member as author, the input in the change; an approved update of structured fields only, from a tainted session with an `external` input, stores `trusted` with the approver as author and `ai_task(<id>)` as source. `an_approval_does_not_launder_drafted_free_text`: from a tainted session the draft as drafted and an edited draft are `external`, a text the member wrote in full is `trusted`; from a clean session the approved draft is `trusted`. `an_update_keeps_the_label_of_the_content_it_does_not_rewrite`: a member editing one field of an `external` record leaves it `external`; rewriting every field that holds a value makes it `trusted`. |
| AC5 (D104, I35) | **Pass** | `a_member_written_field_repeating_eight_words_of_the_draft_is_external`: member-written text holding 8 consecutive words of the draft, and a text rewritten around one such run, are `external`; 7 words are `trusted`. Unit: `eight_consecutive_words_of_a_draft_are_a_copy`, `a_run_is_compared_word_for_word` (case, spacing and punctuation do not break a run, a changed or moved word does), `the_test_is_not_an_edit_ratio` (11 of 12 words kept with no run of 8 is no copy; mostly rewritten text with one run is), `a_run_does_not_span_two_drafts`, `non_latin_words_are_words`. |
| AC6 (AD-6, AD-7, I21) | **Pass** | `a_plugin_or_adapter_write_is_stored_external_whatever_it_claims`: a plugin's approved call from a clean session with a `trusted` input, an unapproved plugin call and an adapter call each store `external`, and `taint` given as a field is `UnknownColumn`. `stored_taint_is_never_member`: 200 seeded calls of random principals, authorities, sessions and inputs, each an insert and an update, all commit, every stored taint is `trusted` or `external`, and every row passes `check_stored_rows`. `Taint` has no `member` member (Story 2.4) and the envelope check refuses the text. |

Mutations, on the clone of `a98c4a7`, each file restored after its mutation, `vilicus-core --lib` tested with `--no-fail-fast` (and `vilicus-types` for its mutations); the unmutated clone passed. 40 of 40 made named tests fail:
- **Stamping (`call.rs`)**: `source` not stamped on insert: `the_core_stamps_the_envelope_of_an_insert`; not restamped on update: `an_update_bumps_rev_and_a_stale_one_is_refused`, `a_member_write_is_stored_trusted_with_the_member_as_author`; `author` not stamped on insert: four tests, the stamp test among them; not restamped on update, `created_at` restamped, `updated_at` not restamped, `rev` not bumped, the expected `rev` unchecked, each: `an_update_bumps_rev_and_a_stale_one_is_refused`; an id not from the stamper: nine tests; a delete that deletes nothing: `a_delete_by_id_removes_the_record`.
- **The call's transaction**: a refusal not kept for the call: eight tests, `a_refused_write_rolls_back_the_whole_call` among them; writes after a refusal accepted: `a_refused_write_rolls_back_the_whole_call`; **a refused call committed instead of rolled back** (`COMMIT` in place of `ROLLBACK`): `a_refused_write_rolls_back_the_whole_call` and `a_failed_commit_leaves_no_open_transaction`. This is the property the mutations of Story 3.4 could not show: a call now holds several writes, so a refusal after an accepted write leaves something to roll back. The authority not checked against the principal: `a_call_whose_authority_does_not_fit_its_principal_is_refused`.
- **Inputs and taint (`provenance.rs`)**: an unknown input ignored: four tests; inputs the call read ignored: the data type property test and `inputs_of_other_files_and_the_updated_record_count`; inputs never required: `a_derived_write_without_inputs_is_refused`; the inputs' taint ignored, the member's view of inputs ignored, each: the subset test and the other-files test; the session taint ignored: the subset test; the updated record not counted: `inputs_of_other_files_and_the_updated_record_count`; plugins and adapters not forced `external`: `a_plugin_or_adapter_write_is_stored_external_whatever_it_claims`, `a_derived_write_without_inputs_is_refused`; adapters alone: the latter; drafted approved text `trusted`: both approval tests; any approved text `trusted` as written in full: `an_approval_does_not_launder_drafted_free_text`; the draft run not checked: `a_member_written_field_repeating_eight_words_of_the_draft_is_external`; the kept content's label ignored: `an_update_keeps_the_label_of_the_content_it_does_not_rewrite`; the unapproved author dropped: the subset test; the member author dropped: four tests.
- **Data types**: the declared set whatever the inputs: the property test and `a_record_holds_only_data_types_its_table_declares`; an update forgetting the stored set, the row writer accepting a set below the inputs', each: the property test; undeclared types accepted: `a_record_holds_only_data_types_its_table_declares`.
- **Verbatim test**: a run of 9 words: four unit tests; words compared with their case: `a_run_is_compared_word_for_word`, `non_latin_words_are_words`; words split on spaces only: `a_run_is_compared_word_for_word`, `eight_consecutive_words_of_a_draft_are_a_copy`.
- **Types**: `for_viewer` ignoring the author: `another_members_trusted_record_reads_as_member` and two record tests; no viewer reading every record `trusted`: the former; `Rev::next` not growing: three tests; `Rev::new` accepting 0: five tests, both write path fuzz tests among them.
