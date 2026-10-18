---
title: 'Shared vocabulary in vilicus-types'
epic: 2
story: 4
status: review
author: Rwx-G
created: 2026-10-16
implements: [FR-68, AD-6, AD-8, AD-48, D103, D113, FR-27, FR-12]
---

# Story 2.4: Shared vocabulary in vilicus-types

As a project maintainer,
I want every closed vocabulary and confirmed V0.1 value defined once in `vilicus-types`,
So that the Core, modules, adapters and clients cannot disagree on identifiers, taint, principals, data types or limits.

**Acceptance Criteria:**

**AC1 (AD-6)**
**Given** the identifier and time conventions of the spine
**When** a record identifier or timestamp is created
**Then** identifiers are UUIDv7, stored as a 16-byte blob and rendered as lowercase hyphenated text at the edges, and times are UTC integer milliseconds in storage and RFC 3339 at the edges
**And** no code parses meaning out of an identifier.

**AC2 (AD-6, AD-8)**
**Given** the `Taint`, tier, `Principal` and `source` types
**When** they are serialized or matched
**Then** stored taint has only the values `trusted` and `external`, with `member` available only as a read-time view type that cannot be stored
**And** `Principal` is the closed enum `Member`, `Cli`, `AiTask`, `Plugin`, `Event`, `Rule`, `Display`, `Adapter`, `Playbook`, and `source` is the closed vocabulary of the spine conventions.

**AC3 (FR-68, D103)**
**Given** the data type set
**When** it is enumerated
**Then** it contains exactly `health`, `journal`, `budget`, `meals`, `meal_plan`, `stock`, `shopping_list`, `presence`, `home_state`, `alarm_state`, `calendar`, `child`, `mail_raw`, `household_other`, `personal_other`
**And** a test fails if a member is added or removed without updating the test, so the set is enumerated in this crate only.

**AC4 (AD-48)**
**Given** the I13 exception classes
**When** they are enumerated
**Then** the closed set is exactly `reversible_external_state`, `restorable_physical`, `own_account_delivery`.

**AC5 (D113, FR-27, FR-12)**
**Given** the confirmed V0.1 values
**When** code needs them
**Then** they are named constants: capability token lifetime 10 minutes, token budget 50 tool calls, unlock window maximum 24 hours and default 12 hours, undo journal retention 30 days
**And** only the backup schedule, the certificate alert lead time and the audit spool size are read from `vilicus.toml`, with every other security delay and cap compiled in.

**AC6 (AD-6)**
**Given** an error crossing a crate boundary
**When** it is returned to a client
**Then** it carries a stable error code, a message key and a retry class from `retryable`, `not_retryable`, `unknown_outcome`.

**Dependencies:**
- Story 2.1 (crate exists)

**References:**
- `doc/architecture-spine.md` AD-6, AD-8, AD-48, Consistency Conventions
- `doc/prd.md` FR-12, FR-27, FR-68, section 12
- `doc/decisions.md` D103, D113

## Implementation Notes

**What was built**
- `crates/vilicus-types/src/`, one module per vocabulary, re-exported from `lib.rs`:
  - `id.rs`: `Id`, a UUIDv7 (RFC 9562 section 5.7) held as 16 bytes. `Id::new_v7(created_at, random)` lays out the identifier from a `UtcMillis` and 10 random bytes passed in by the caller (the Core's clock, the CSPRNG of `vilicus-crypto`); `from_bytes` and `to_bytes` are the stored form; `parse`, `FromStr` and `Display` the lowercase hyphenated text; serde uses the text. `IdError` refuses a time before the Unix epoch, malformed text, a version other than 7 and a variant other than RFC 9562's.
  - `time.rs`: `UtcMillis`, UTC integer milliseconds over years 0000 to 9999 (`MIN`, `MAX`, `UNIX_EPOCH`, `from_millis`, `as_millis`), with `parse_rfc3339` and a `Display` that always writes `YYYY-MM-DDTHH:MM:SS.mmmZ`; serde uses that text. Calendar arithmetic is Howard Hinnant's `days_from_civil` and its inverse, as `const fn`.
  - `taint.rs`: `Taint` (stored: `trusted`, `external`) and `EffectiveTaint` (view: `trusted`, `member`, `external`, ordered in that sequence, `doc/architecture.md` section 5.4 rule 4).
  - `tier.rs` (`Tier`), `principal.rs` (`Principal`), `exception_class.rs` (`ExceptionClass`), `data_type.rs` (`DataType`).
  - `source.rs`: `Source`, the `source` vocabulary, and `ModuleName`, the payload of `module(name)`.
  - `error.rs`: `RetryClass`, `ErrorCode`, `MessageKey`, `ClientError` and the trait `ClientFacingError`.
  - `limits.rs`: the confirmed values as constants, `OperatorSetting`, and the defaults of the three settings.
  - `name.rs`: the grammars of module names and dotted names, and `NameError`.
  - `test_support.rs` (tests only): a minimal JSON writer to drive `Serialize`, and helpers over serde's value deserializers to drive `Deserialize`, since the crate depends on no format.
- `lib.rs` declares the `closed_set!` macro. A closed set is written once, as `Variant => "name"`, and the macro derives from that one list the enum, `ALL`, `as_str`, `Display`, `Serialize` and `Deserialize`, so `ALL` cannot miss a variant and a serialized name cannot differ from `as_str`. Deserialization accepts exactly one of the names, as a string.
- Dependency: `serde` 1.0.229 (spine Stack table) with feature `derive`, declared in `[workspace.dependencies]` and used by `vilicus-types` only. `Cargo.lock` gains 7 packages and `vendor/` holds them, as `cargo vendor --versioned-dirs vendor` writes it: `serde` 1.0.229, `serde_core` 1.0.229, `serde_derive` 1.0.229, `proc-macro2` 1.0.107, `quote` 1.0.47, `syn` 3.0.9, `unicode-ident` 1.0.27. Nothing in the crate does I/O, reads a clock or a random source, or touches a key or storage.
- `ci/build_time_code.toml`: five entries, each with its reason: `serde` and `serde_core` (build scripts that run `rustc --version`, print cfg flags and write a module to `OUT_DIR`), `serde_derive` (procedural macro), `proc-macro2` (build script that also compiles a probe into `OUT_DIR`) and `quote` (build script). `syn` and `unicode-ident` have no build-time target.
- `supply-chain/`: `imports.lock` now holds the imported google and mozilla audits that vet `quote` 1.0.47. The other six crates have no imported audit at these versions, so `config.toml` exempts each one at its exact version, with a note saying it was not reviewed here and naming the delta audit cargo-vet proposes; `syn` 3.0.9 has no audited base, so it needs a full review (68 605 lines). `cargo vet fmt` drops comments from `config.toml`, so the reasons are in the `notes` fields.

**Decisions and why**
- *Exemptions, not `[[trusted]]` for dtolnay.* isrg, mozilla and bytecode-alliance trust that publisher, and a trust entry would vet these crates with no exemption, but it would also vet every later version he publishes, unreviewed. An exemption pins one version, so any update fails `cargo vet --locked` until someone audits or exempts it again. What it gives up: six entries to revisit on each serde update. No audit was certified: an audit records that a named person reviewed the code, and nobody did.
- *serde now.* AC2 asks for the names as they are serialized, and `deny_unknown_fields` is a derive attribute. Only `ClientError` derives `Deserialize`, and `Source` derives `Serialize`. The closed sets, `Id`, `UtcMillis`, `ModuleName`, `ErrorCode` and `MessageKey` implement serde by hand, so each one is exactly one string and nothing else.
- *`Source` is read by hand.* The derived `Deserialize` accepted an integer variant index (`{0: id}` read as `member`), a byte-string tag, `{"system": ()}` as a second encoding of `system`, and dropped a second map entry silently. The manual impl accepts `system` as a string only, and every other kind as a map with exactly one entry, whose key is read by a string-only visitor over the private closed set `SourceKind`; a further key is refused.
- *`member` cannot be stored.* `Taint` has no `member` variant and refuses `"member"` when deserializing. `EffectiveTaint` converts from `Taint` and not back, and implements neither `Serialize` nor `Deserialize`. Three `compile_fail` doctests check those refusals, next to a doctest where the same lines compile for `Taint`, so each refusal comes from `EffectiveTaint` alone. A client screen that shows the view value can use `as_str`; adding `Serialize` would be a deliberate change.
- *Serialized names.* `Taint`, `DataType`, `ExceptionClass` and `RetryClass` use the lowercase names of the spine and the PRD, and `Source` the `snake_case` names of the conventions (`{"member": "<id>"}`, `"system"`). `Principal` keeps the spine's spelling (`Member`, `AiTask`, ...), and `Tier` uses the capability matrix's `0`, `1`, `2`, `H`.
- *Ids.* Only the canonical text is accepted: uppercase digits, braces or `urn:uuid:` are refused rather than normalized, so one identifier has one text, which matters for deduplication on `call_id` (AD-28) and for hashing. A stored blob that is not version 7 with the RFC 9562 variant is refused. `Id` implements no ordering and has no accessor for its time or random bits; a `compile_fail` doctest checks that `id < id` does not compile. Of the 80 random bits passed in, the layout uses 74; which bits are dropped is documented on `new_v7` and tested.
- *RFC 3339 profile.* The parser accepts the full `date-time` of RFC 3339 section 5.6: `T` or `t`, `Z` or `z`, numeric offsets (applied to give UTC, `-00:00` read as UTC) and any number of fraction digits. It refuses, never rounds: second 60 (`LeapSecond` when the UTC result is 23:59:60, since a leap second has no Unix time; `InvalidField` at any other minute, where no leap second exists), a non-zero digit below the millisecond, a field out of range, and an instant outside years 0000 to 9999 once the offset is applied. Output is always `Z` with three fraction digits, so one instant has one text.
- *`source` payloads.* Each `(id)` of the vocabulary is an `Id`, `event(call id)` included (`call_id` is a UUIDv7, AD-28). `module(name)` takes a `ModuleName`: a lowercase letter, then lowercase letters and digits, at most `ModuleName::MAX_LEN` (32). That fits every module scope of `.claude/rules/vilicus-git.md` and the `reference` module; the bound is my choice, not a documented value.
- *AC6 placement.* The spine puts "one error enum per crate boundary in `vilicus-proto`". This crate holds the shape every one of those enums must produce: `ClientError` (`deny_unknown_fields`) and the trait `ClientFacingError`, whose `to_client_error` is built from the code, the message key and the retry class alone. `ErrorCode` and `MessageKey` are dotted names (lowercase segments, no space, at most 64 characters, also my choice), so neither can carry an internal message. `from_static` checks the grammar in a `const` context, so a bad literal in a `const` item fails the build.
- *AC5, operator settings.* `OperatorSetting` is the closed set of the three `vilicus.toml` keys (`backup_schedule`, `certificate_alert_lead_time`, `audit_spool_size`). Those key names, and the model of the backup schedule as an interval (`DEFAULT_BACKUP_INTERVAL`, a `Duration`), are introduced by this story: no document names them, and Story 12.2 must confirm both; every other value is a `pub const` with no setter and no `Deserialize`. The defaults are constants too (`DEFAULT_BACKUP_INTERVAL` daily, `DEFAULT_CERTIFICATE_ALERT_LEAD_TIME` 14 days, `DEFAULT_AUDIT_SPOOL_ENTRIES` 10 000), from the PRD section 12 assumptions of FR-53, FR-65 and FR-31, and their doc comments say so. **Where the rule is enforced:** in the `vilicus.toml` loader of Story 5.1 (AC4), not here. That loader should deserialize the file into a struct with `deny_unknown_fields` whose keys are `OperatorSetting::ALL`, with a test comparing the two, so that a security delay written into the file fails at startup.
- *Constant shapes.* Durations are `std::time::Duration`; the token budget and the spool size are `u32`. A `const` assertion checks at build time that the default unlock window does not exceed the maximum.

**Files**
- `Cargo.toml`, `Cargo.lock`, `crates/vilicus-types/Cargo.toml`
- `crates/vilicus-types/src/lib.rs`, `data_type.rs`, `error.rs`, `exception_class.rs`, `id.rs`, `limits.rs`, `name.rs`, `principal.rs`, `source.rs`, `taint.rs`, `test_support.rs`, `tier.rs`, `time.rs`
- `vendor/` (7 crates, new)
- `ci/build_time_code.toml`, `supply-chain/config.toml`, `supply-chain/imports.lock`
- `doc/stories/sprint-status.yaml` (2.4 to `review`)

**Open points**
- *Owner approval of the six cargo-vet exemptions.* They record that nobody here reviewed serde 1.0.229 and its macro stack. Replacing them means certifying the delta audits cargo-vet proposes (small for `serde`, `serde_core` and `proc-macro2`, larger for `serde_derive` and `unicode-ident`) and a full review of `syn` 3.0.9. A `[[trusted]]` entry for dtolnay is the alternative the owner may prefer.
- *Values of PRD section 12 not in AC5.* Section 12 and D113 also name the reference host and the languages (FR-110) as named constants of this crate, and D113 names the I11 caps. AC5 lists only the four values built here, so the others were left out; they belong here when the story that uses them lands, or in a follow-up.
- *Backup schedule format and key names.* `DEFAULT_BACKUP_INTERVAL` is a `Duration` (daily), and the three `vilicus.toml` key names are this story's. Story 12.2 confirms both; if it expresses the schedule as a systemd `OnCalendar=` expression, the type of that setting changes there.
- *Device capabilities have no owner.* The spine's conventions place the closed set of device capabilities in `vilicus-types`, and no story owns it yet. It is not built here.
- *Taint in storage.* The storage layer must bind `Taint` through a typed conversion (a `ToSql`/`FromSql` impl over `Taint`, reading back only `trusted` or `external`), never as free text, so that no other value, `member` included, can be written or read as a stored label.
- *`ClientError` field identifiers.* Its derived `Deserialize` still accepts an integer field index in formats that carry one. The closed-type check of the wire lives in `vilicus-proto` on `dcbor` (AD-12, AD-13, Story 2.5) and should refuse that form; otherwise `ClientError` needs a hand-written impl like `Source`.
- *Mail as a source.* `doc/architecture.md` section 5.4 lists "a mail account" among the producers of a record, while the spine's closed vocabulary, which that section defers to, has no `mail` entry, so a mail record is `plugin(id)` or `import(id)`. Not a conflict, but worth a sentence in the spine when the mail module is designed.
- *Data type descriptions.* D103 names the data types without defining them; the one-line doc comments on `DataType`'s variants are descriptive only.

## Result

All commands ran on 2026-10-18 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2, on a copy of the repository made inside the container without the root `.cargo/` directory. Each mutation ran on its own fresh copy, never on the working tree.

Gates, as `.github/workflows/ci.yml` runs them:

- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`: exit 0.
- `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: `vilicus-types` 41 unit tests passed (43 after the review fixes, run with `cargo test -p vilicus-types`), then 4 doctests and 4 `compile_fail` doctests passed; the other crates have none. Exit 0.
- `python3 -m unittest discover -s ci`: `Ran 123 tests`, `OK`.
- `python3 ci/check_workspace.py`: `workspace checks passed: 12 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 19 packages`. Before the five allowlist entries it named `proc-macro2`, `quote`, `serde`, `serde_core` (build scripts) and `serde_derive` (procedural macro), exit 1.
- `python3 ci/check_supply_chain.py --vendor`: `vendor check passed`.
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (1 fully audited, 6 exempted)`. Before the `supply-chain/` changes: `Vetting Failed!`, `7 unvetted dependencies`.
- `cargo audit --deny warnings`: `Scanning Cargo.lock for vulnerabilities (19 crate dependencies)`, no finding, exit 0.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (AD-6) | **Pass** | Ids: `id::tests::rfc9562_uuidv7_example` (the RFC 9562 appendix A.6 inputs give its bytes and the text `017f22e2-79b0-7cc3-98c4-dc0c0c07398f`), `layout_sets_version_and_variant_and_keeps_74_random_bits`, `time_field_spans_the_whole_range_after_the_epoch` (a time before the epoch refused), `stored_form_must_be_uuidv7` (other versions and variants, nil and max refused), `text_form_is_lowercase_hyphenated_only` (uppercase, no hyphens, braces, URN, trailing space, wrong length or hyphen position, non-hex and non-ASCII digits refused), `text_round_trips`, `serialized_as_text`. The `compile_fail,E0369` doctest on `Id` checks that `id < id` does not compile, and `Id` has no accessor for its time or random bits. Time: `time::tests::rfc3339_section_5_8_examples` (`1985-04-12T23:20:50.52Z` is 482 196 050 520 ms, `1996-12-19T16:39:57-08:00` is 851 042 397 000 ms, `1937-01-01T12:00:27.87+00:20` renders as `1937-01-01T11:40:27.870Z`, both leap-second examples refused as `LeapSecond`, while second 60 at `12:00` UTC or at `23:59-08:00` is `InvalidField`), `known_instants` (the RFC 9562 example's time, parsed from its RFC 3339 form, is `0x017F22E279B0`), `range_is_years_0000_to_9999` (`MIN`, `MAX` and their neighbours, `i64::MIN` and `i64::MAX`, an offset pushing a valid local text out of range, a five-digit year), `leap_years` (2000, 2024, 1600, 0000 and 9996 accepted; 1900, 2023, 2100 and 9999 refused), `year_boundaries`, `every_day_of_the_range_round_trips` (every day from 0000-01-01 to 9999-12-31 against a day-by-day calendar walk), `rendering_parses_back`, `accepted_syntax`, `refused_syntax` (24 refusals, each with its error), `serialized_as_rfc3339_text`. |
| AC2 (AD-6, AD-8) | **Pass** | `taint::tests::stored_taint_is_trusted_or_external_only`, `member_is_refused_as_stored_taint`, `view_keeps_the_stored_label_and_adds_member`, `view_order_is_trusted_member_external`. Three `compile_fail,E0277` doctests on `EffectiveTaint`: it is not `Serialize`, not `DeserializeOwned`, and does not convert into `Taint`; the sibling doctest compiles the same lines for `Taint`. `principal::tests::principal_is_the_closed_enum_of_ad_8`: `Principal::ALL` is AD-8's nine names, in order, each serialized and read back; `member`, `ai_task`, `ScheduledTask` and `Root` refused. `source::tests::source_vocabulary_is_the_spine_conventions` (the twelve names of the conventions), `sources_serialize_under_their_vocabulary_name` (each kind serialized and read back), `unknown_or_malformed_sources_are_refused`, `only_the_string_tag_of_a_single_entry_is_accepted` (an integer tag, a byte-string tag, a second entry and an empty map refused), `system_has_one_encoding` (`{"system": ()}` refused), `module_names_are_checked`. `tier::tests::tiers_use_the_capability_matrix_names`. Mutations: a `Member` variant added to `Taint` does not compile (`E0004`, non-exhaustive match in `From<Taint> for EffectiveTaint`); a `Mail(Id)` kind added to `Source` does not compile the tests (`E0004` in `vocabulary_name`). |
| AC3 (FR-68, D103) | **Pass** | `data_type::tests::data_type_set_is_exactly_d103`: `DataType::ALL`, in order, equals the D103 list retyped in the test, with no duplicate; `data_types_serialize_by_name`. Mutation, `Pets => "pets"` added: the test fails, `left` ends with `"pets"`, `test result: FAILED. 40 passed; 1 failed`. Mutation, `Child` removed: the same test fails, `left` lacks `"child"`, `40 passed; 1 failed`. `DataType` is the only data type enumeration in the code base. |
| AC4 (AD-48) | **Pass** | `exception_class::tests::exception_classes_are_the_closed_set_of_i13`: exactly `reversible_external_state`, `restorable_physical`, `own_account_delivery`; `system_notification` and other spellings refused. |
| AC5 (D113, FR-27, FR-12) | **Pass** | `limits::tests::confirmed_values_of_d113`: `CAPABILITY_TOKEN_LIFETIME` 10 minutes, `CAPABILITY_TOKEN_DEFAULT_BUDGET` 50 tool calls, `UNLOCK_WINDOW_MAX` 24 hours, `UNLOCK_WINDOW_DEFAULT` 12 hours, `UNDO_JOURNAL_RETENTION` 30 days; a `const` assertion checks default <= maximum at build time. `operator_settings_are_the_three_of_d113`: `OperatorSetting::ALL` is `backup_schedule`, `certificate_alert_lead_time`, `audit_spool_size`. `operator_setting_defaults_of_prd_section_12`. `vilicus.toml` loading is not built here; the rule that only these keys are read is enforced by the loader of Story 5.1 (AC4), as described in Implementation Notes. |
| AC6 (AD-6) | **Pass** | `error::tests::retry_classes_are_the_spine_conventions` (`retryable`, `not_retryable`, `unknown_outcome`). `client_error_carries_code_key_and_retry_class_only`: a sample error's `to_client_error` serializes as `{"code":"policy.denied","message_key":"error.policy.denied","retry_class":"not_retryable"}`, without its internal reason. `client_error_deserializes_closed`: an extra `message` field, a missing field, a sentence as code, an uppercase code, a key with spaces and an unknown retry class are each refused. `codes_and_keys_follow_the_dotted_grammar`, `invalid_static_code_panics`, and the `ClientError` doctest (an enum implementing `ClientFacingError`). |
