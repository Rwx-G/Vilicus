---
title: 'Tool declarations and capability matrix check'
epic: 3
story: 3
status: review
author: Rwx-G
created: 2026-10-16
implements: [FR-22, FR-60, FR-21, I13, I18, AD-9, AD-48, D46, DC-13]
---

# Story 3.3: Tool declarations and capability matrix check

As a project maintainer,
I want every module tool declared with its tier, network effect and capability matrix row, checked at build against `doc/capability-matrix.md`,
So that no tool exists without a reviewed row, no tier 2 action ships in V0.1 and no human-only action becomes a tool.

**Acceptance Criteria:**

**AC1 (FR-22, AD-9)**
**Given** a tool declared by a module
**When** the registry is built
**Then** the declaration carries name, schema, tier, a mandatory `network_effect` field, at most one exception class and its capability matrix row
**And** a tool without `network_effect` fails the build.

**AC2 (FR-22, I13, I18)**
**Given** the registry's exported tool table and `doc/capability-matrix.md`
**When** the CI matrix check compares them
**Then** it fails on a tool without a matrix row and on a matrix row of a shipped module without a tool, naming each difference.

**AC3 (FR-60, FR-21, D46, DC-13)**
**Given** a V0.1 tool declared tier 2, including any write moving or copying a record across partitions
**When** the registry is built
**Then** the build fails, so cross-partition writes stay unregistered in V0.1.

**AC4 (I13, AD-48)**
**Given** a tool declaring a network effect
**When** the registry is built
**Then** it fails unless the tool is tier 2 or declares exactly one exception class from the closed set and is tier 1
**And** it fails when a `reversible_external_state` or `own_account_delivery` tool does not require light confirmation, or when any exception-class tool has no undo handler.

**AC5 (I18)**
**Given** the H actions of the capability matrix (pairing, recovery, rights changes, token creation, plugin install, provider configuration and the others listed in I18)
**When** the static registry check runs
**Then** none of them is reachable as a tool, and a test registering one fails the build.

**Dependencies:**
- Story 3.2 (registry)

**References:**
- `doc/prd.md` FR-21, FR-22, FR-60
- `doc/architecture-spine.md` AD-9, AD-48
- `doc/ai-safety.md` I13, I18, section 3.1
- `doc/capability-matrix.md` Legend, section 12
- `doc/decisions.md` D46

## Implementation Notes

**What was built**
- `crates/vilicus-module-api/` (no new dependency):
  - `src/tool.rs`: a module declares each tool as a `Tool`, plain `'static` data in its `ModuleDeclaration`:
    - `name`, an identifier unique in the module; the registry names it `<module>.<name>`;
    - `arguments`, the tool's schema: `Field`s under the rules of a table's fields (structured or free text with a maximum length, no envelope or rowid name);
    - `tier` (`vilicus_types::Tier`), `network_effect: bool` (mandatory: a struct literal without it does not compile; true when a call changes state outside the instance's own files, in a third-party system, an account or a device, so a read that only fetches declares none, review M2), `exception_class: Option<ExceptionClass>` (at most one, from the closed set of `vilicus-types`);
    - `confirmation: Confirmation` (`None` or `Light`, named as the matrix's Confirmation column, `Confirmation::ALL`);
    - `crosses_partitions: bool`, true for a write that moves or copies a record into another partition;
    - `undo_handler: Option<&'static str>`, the name of the module's undo handler;
    - `matrix_row: MatrixRow { section, action }`: the section number as its heading writes it (`2`, `10a`) and the Action cell, exactly.
  - `ModuleDeclaration` gains `matrix_sections` (the matrix sections the module implements) and `tools`, and `tool(name)`.
  - `src/check.rs`, the `const fn` rules `validate` and `assert_valid` apply, in this order for each tool:
    - name and arguments (identifier grammar, field rules, unique);
    - tier H refused (`HumanOnlyTool`, I18, AD-8);
    - `crosses_partitions` refused at every tier (`CrossPartitionTool`, FR-21, D46);
    - with an exception class: tier 1 only (`ExceptionClassOutsideTier1`), a network effect required (`ExceptionClassWithoutNetworkEffect`), light confirmation for `reversible_external_state` and `own_account_delivery` (`ExceptionClassWithoutLightConfirmation`), an undo handler (`ExceptionClassWithoutUndoHandler`) (I13, AD-48);
    - without one: a network effect below tier 2 refused (`NetworkEffectBelowTier2`, I13);
    - tier 2 refused (`Tier2BeforeNativeApp`, D46, FR-60);
    - light confirmation outside tier 1 refused; an undo handler on a tier 0 tool refused, its name an identifier;
    - the row's section is one the module claims, and its action text is one a matrix cell can hold (not empty, no white space at either end, no `|`, no control character);
    - the module's sections follow the section grammar (`is_matrix_section`, at most `MATRIX_SECTION_MAX_LEN`), are claimed once and never include `CORE_MATRIX_SECTION`, section 1, the Core's (`CoreMatrixSection`, review minor 3); tool names are unique.
  - `compile_fail` examples: a tool without `network_effect` (E0063), an exception class outside the set (E0599), a tier H tool and a tier 2 tool in a `const` item (E0080).
- `crates/vilicus-core/src/registry/`:
  - `mod.rs`: `Registry::tools()` is the registry's exported tool table (`RegisteredTool { module, tool }`, `qualified_name()`); `Registry::new` also refuses two modules claiming one matrix section (`RegistryError::DuplicateMatrixSection`).
  - `matrix/mod.rs`, the capability matrix check:
    - `CapabilityMatrix::parse(text)` reads `doc/capability-matrix.md`, or a fixture in its format: each `## <number>. <title>` heading opens a section (a closing sequence of `#` is not part of the title), each table whose first header cell is exactly `Action` is a table of actions with `Tier`, `Confirmation` and `Exception class` columns, and `MatrixSection::has_actions` records whether a section has one; other tables (caps, review log) are not read, but every table needs its separator. A form it does not recognise is a `MatrixError` naming the line: a row not framed by `|`, a header without its separator (a lone row included), a separator of another width, a table with a `Tier` column not led by `Action`, a missing column, another cell count, an empty or repeated Action in a section, two sections of one number, a table of actions outside a numbered section, and, inside a numbered section, an indented table row or a table row in a fenced code block (review minor 2). The Exception class cell reads strictly as `RowClass`: `none`, `unsettled` or a member of `ExceptionClass::ALL`, anything else `UnknownExceptionClass`; a class only on a tier `1` row (`ExceptionClassOutsideTier1`), and `reversible_external_state` and `own_account_delivery` only with light confirmation (`ExceptionClassWithoutLightConfirmation`), AD-48 held by the matrix itself.
    - `MatrixEntry::row_tier()` reads the Tier cell: `0` and `1` are `Registrable`; `2` and `2 (D<n>)` `Irreversible`; `H` `HumanOnly`; `n/a` `NotApplicable`; anything else `NotOneTier`. `tool_confirmation()` reads the first term of the Confirmation cell (before a comma, a semicolon or ` (`) as one of `Confirmation::ALL`, or none.
    - `differences(&registry)` lists, in both directions and every difference of each tool rather than the first: `SectionMissing` (a claimed section the matrix lacks or that has no table of actions), `ToolWithoutRow`, `RowNotATool` (a tool naming an H, `n/a`, tier 2 or `NotOneTier` row), `ToolOnUnsettledRow`, `TierMismatch`, `ConfirmationMismatch`, `ExceptionClassMismatch` and `NetworkEffectMismatch` (a row's class, and only a class, comes with a network effect below tier 2; review M1), `RowWithoutTool` (a `0` or `1` row of a claimed section that no tool of the module names), `RowWithoutOneTier` and `RowWithUnsettledClass` (claimed rows the check cannot assign). Each names the tool or the module, the section and the row. Several tools may implement one row, each compared with it.
    - `CapabilityMatrix::check(text, &registry)` is the gate's entry point: `Ok`, or `MatrixCheckError` listing every difference one per line, or the reading error.
- `crates/vilicus/src/registry.rs` (`#[cfg(test)] mod registry;` in `main.rs`): the binary's registry, `const REGISTRY: Registry = Registry::new(&[])`, V0.1 shipping no module, `the_shipped_tool_table_matches_the_capability_matrix`, which runs `CapabilityMatrix::check` on `doc/capability-matrix.md`, and `the_registry_is_the_binary_s_only_use_of_the_core_while_it_is_test_only` (review minor 1): no other source of the binary builds a registry, and while the registry is test-only none names `vilicus_core`.
- `doc/capability-matrix.md` (review M1, the coordinator's decision): an `Exception class` column after Confirmation in every table of actions, a Legend paragraph explaining it, and a review log row; no other value changed. Values, taken only from what each row's Tier and Notes already state:
  - `reversible_external_state`: 6 `Prepare a cart through a store connector` (Notes: "I13 exception class: reversible external state");
  - `own_account_delivery`: 8 `Send a mail to the member's own address (a digest, a report, a reminder)`, 10c `Deposit a file in the member's dedicated folder` and 10c `Create or edit a blog post draft, its tags and images` (Notes: "I13 exception class `own_account_delivery`");
  - `restorable_physical`: 10a `Restorable physical action on a device that is not safety-relevant: ...` (Notes: "I13 exception class for restorable physical actions");
  - `unsettled`, where guessing would decide the design: rows that follow another row, 8 `Act on a message from a bound sender on a secondary channel` (as the target row), 10 `Call a plugin write operation` (per manifest), 10b `Run a scheduled task` (as the target rows) and 10b `Run a playbook step` (as the target row); device commands at tier 1 with no class in their Notes (review M2), 10a `Apply a scene`, `Safe-direction command on a safety-relevant device: lock, arm, close, camera on`, `Change a mode that concerns no safety-relevant device`, and the mixed rows `Turn a camera off` and `Change a mode that concerns a safety-relevant device`;
  - `none` everywhere else, including 8 `Raise an alert about an important mail`, which goes out through the system notification path I13 excepts without a class.
- No new package, no change to `Cargo.lock`, `ci/` or the workflow.

**Decisions and why** (choices the documents leave open; drafted texts under Open points)
- *The check is Rust, run by `cargo test`*, not a Python script under `ci/`. The tool table is `const` Rust data; a Python check would need an export format and a Rust program to write it, two surfaces to keep in step. A Rust test reads the matrix directly, and Story 3.10's testbed calls the same `CapabilityMatrix::check` on its fixture. It runs in `build-and-test`, the job that already runs the workspace tests; no job was added. What it gives up: a step named after the gate in the workflow; a failure is a test named after it instead.
- *Row identity is section number plus Action text*, exactly as written. A module claims whole sections, and one section belongs to one module, which the registry enforces. The row direction of AC2 is read as: every row of a claimed section whose Tier cell is `0` or `1` needs a tool. Tier 2 rows (marked `D46` or `D69`, or not, like the out-of-scope payment row), H rows and `n/a` rows never do. A claimed row of no single tier (`0 or 1`, `per manifest`, `1; H when ...`) is a difference, because the check cannot tell whether it needs a tool. What it gives up: a section shared by several modules (10c today) must be split before the first of them ships, and a mixed-tier row must become rows of one tier each.
- *Tier, confirmation, exception class and network effect are compared*, AD-9's "any difference": a tool's tier is its row's exactly, its confirmation is the first term of the row's Confirmation cell (`light, in the app` is light), its class is the row's Exception class cell, and it declares a network effect exactly when the row has a class (below tier 2 only a class allows one, I13). A row whose confirmation no tool can declare (`spoken`, `provider policy`, `light to grant ...; none to revoke`) or whose class is `unsettled` cannot be claimed by a tool. The first version did not compare the class, which the matrix held only in Notes, so a cart tool could omit its class, its network effect and its undo handler and pass (review M1); the class is now a column the check reads.
- *Fields beyond AD-9's list*: `confirmation` (AD-48 and I13 require light confirmation of two classes, which a declaration must state to be checked), `crosses_partitions` (FR-21 at build time: a tool says whether it writes into another partition, and saying so is refused before the native app), `undo_handler` (I13 requires one per exception-class tool) and `matrix_sections` on the module (the row direction of AC2).
- *A network effect is a change of state outside the instance's own files* (review M2, the coordinator's decision): in a third-party system, an account or a device. A read that only fetches is not one; what it may reach is the egress proxy's and the sandbox's (I4). The rules are unchanged: a tier 0 tool declares none, a tier 1 tool only with a class, and a class always comes with one. Tier 1 device commands without a class (scene, safe-direction command, mode change) cannot register without mislabelling under I13 as written; no rule is invented for them, their rows are `unsettled` and the check names them (Open points).
- *Light confirmation is tier 1 only, and a read names no undo handler*: the Legend gives light confirmation to tier 1 rows and signed to tier 2, and a read changes nothing. `Confirmation` has no `Signed` member while no tier 2 tool can be registered (D46); it joins with the native app.
- *Undo handlers are named, not bound*: no handler signature exists before the typed record API and the handler boundary (Stories 3.5, 3.9). A name is what the declaration can carry now; binding it to the module's function, and refusing a name with no function, is Story 3.9's.
- *The binary's registry is compiled with its tests only*, until `main` starts the Core with it. Naming `vilicus_core` in the executable links SQLCipher and the system `libcrypto` into it (observed: 160 `sqlite3_` text symbols and a `libcrypto.so.3` dependency in the debug build), which nothing in V0.1's binary uses yet and which the VM smoke test would then need on the guest. CI builds and runs the test target on every change, so a shipped module the registry refuses still fails CI, and every module crate also checks its own declaration in its build (`assert_valid`). What it gives up: a plain `cargo build -p vilicus` does not evaluate the registry; it will once the Core runs from `main`.

**Files**
- `crates/vilicus-module-api/src/`: `tool.rs` (new), `check.rs`, `declaration.rs`, `lib.rs`, `tests.rs`
- `doc/capability-matrix.md` (review)
- `crates/vilicus-core/src/registry/`: `mod.rs`, `matrix/mod.rs` and `matrix/tests.rs` (new), `tests.rs` (the new fields in its declarations)
- `crates/vilicus/src/`: `main.rs`, `registry.rs` (new)
- `doc/stories/sprint-status.yaml` (3.3 `review`)

**Deviations**
- *AC1, "a tool without `network_effect` fails the build"*: the field has no default, so such a declaration does not compile (`compile_fail`, E0063), which is earlier than registration, as Story 3.2 did for data types.
- *AC2, "the CI matrix check"*: a Rust test, not a separate job (Decisions). V0.1 ships no module, so on `doc/capability-matrix.md` the shipped check proves the document reads back and that no tool exists; the comparison in both directions is exercised on a fixture and, with probe modules, on every section of the real document.
- *AC3, cross-partition writes*: a static check sees what the declaration says. A tool that declares `crosses_partitions` is refused at every tier; a handler that writes into another partition without declaring it is refused at run time by partition isolation (Story 10.4), not by this check.
- *AC4, "has no undo handler"*: checked as "names none"; the name is bound to a function in Story 3.9.
- *AC4, I13's "takes no destination argument"* for `own_account_delivery`: not checked. Nothing in a field's declaration says that it is a destination; the Core resolves the destination from the member's account, and the pipeline (Epic 10) must refuse an argument that would carry one.
- *AC5, "none of them is reachable as a tool"*: a tier H tool does not build, and a tool naming an H or `n/a` row of the matrix, at any tier it can declare, fails the matrix check. A tool that performs an H action while naming a tier 1 row of its own module cannot be detected statically; the review of the module's rows covers it (`doc/capability-matrix.md`, section 12, point 2).

**Open points**
- *Design documents* (coordinator):
  - Drafted decision, D145 "Tool declarations and the capability matrix check": "Amends AD-9 and AD-48. Context: story 3.3 builds the tool declarations and the capability matrix check; its review found that a tool could omit its exception class, which the matrix held only in Notes. Decision: a tool declares, as `const` data in `vilicus-module-api`, its name, its schema (arguments under the field rules of FR-58), its tier, a mandatory `network_effect`, at most one exception class, its confirmation (none or light), whether it crosses partitions, the name of its undo handler and its matrix row, named by section number and Action text; a module claims the matrix sections it implements, one section belongs to one module, and no module claims section 1, the Core's. A network effect is a change of state outside the instance's own files, in a third-party system, an account or a device; a read that only fetches is not one, its egress being the egress proxy's and the sandbox's (I4). The build refuses a tier H tool, a tier 2 tool and a tool crossing partitions before the native app, a network effect below tier 2 without an exception class, an exception class outside tier 1, without a network effect or without an undo handler, and a `reversible_external_state` or `own_account_delivery` tool without light confirmation; light confirmation is tier 1 only. `doc/capability-matrix.md` carries an Exception class column: `none`, a member of the closed set (tier 1 only, the two classes above with light confirmation), or `unsettled` for a row whose class the design has not settled. The capability matrix check is a Rust test over the registry's tool table and `doc/capability-matrix.md` (a fixture under `testing/` for the testbed): it fails on a tool without its row, on a tool naming a row of tier H, `n/a`, tier 2, no single tier or an unsettled class, on a tier, confirmation, class or network effect different from the row's, on a claimed section that has no table of actions, and on a row of a claimed section at tier 0 or 1 without a tool, of no single tier or of an unsettled class; it reads the matrix fail-closed. Consequences: a matrix section shared by several modules, a row of mixed tier and an unsettled row are settled before their module ships; tier 1 device commands without a class (scene, safe-direction command, mode change) cannot register until the home milestone settles them between D56, AD-39 and I13."
  - AD-9, drafted amendment of the declaration sentence: "tools (name, schema, tier, `network_effect`, exception class if any per DC-11, confirmation, whether the tool crosses partitions, the name of its undo handler, capability matrix row), the capability matrix sections the module implements (one module per section, never section 1), event topics, and undo handlers"; and of the check sentence: "A CI check compares the registry's exported tool table with `doc/capability-matrix.md` (tier, confirmation, exception class and the network effect a class implies) and fails on any difference in either direction, and on a claimed row it cannot assign to a tool". The CI list's "capability matrix check (AD-9)" is the test `the_shipped_tool_table_matches_the_capability_matrix`.
  - AD-48, drafted addition: "A network effect is a change of state outside the instance's own files: a third-party system, an account or a device; a read that only fetches is not one. A class always comes with a network effect, and light confirmation is tier 1 only. The capability matrix states each row's class in its Exception class column, which the build check compares with the tool's."
  - `doc/capability-matrix.md`, section 12: "the module registry loads tool definitions from the same table in code" reads as the tool table compared with the matrix, which is what is built. The Exception class column and its Legend paragraph are in the document (review M1).
- *Rows the check cannot assign to a tool today* (found by running it on every section), each to settle in the matrix before its module ships:
  - no single tier: `Act on a message from a bound sender on a secondary channel` (8), `Call a plugin write operation` (10), `Turn a camera off` and `Change a mode that concerns a safety-relevant device` (10a), `Run a scheduled task`, `Create or validate a playbook` and `Run a playbook step` (10b);
  - a confirmation no tool declares: `Compute travel time with an external routing provider` (4), `Grant or revoke a standing approval for own-account delivery by a playbook` (10b), and in section 1, which no module claims, `Approve an elevated tier 1 request by voice` and `Call a remote AI provider with household data`;
  - an unsettled class: the rows listed under What was built, `doc/capability-matrix.md`.
  - Section 10c holds rows of several activatable modules.
  - *Design question for the home milestone* (review M2): `Apply a scene`, `Safe-direction command on a safety-relevant device: lock, arm, close, camera on` and `Change a mode that concerns no safety-relevant device` are tier 1 device commands whose Notes give no class; I13 as written makes a device command without a class tier 2, while D56 and AD-39 make the safe direction tier 1. Settling it (a class, a new class, or tier 2) is a design decision, not this story's.
- *Story 3.9*: bind each `undo_handler` name to the module's function and refuse a name with none.
- *Story 3.10*: the testbed's `const` registry with the reference module, which claims the sections of a fixture under `testing/` (a tier 0 and a tier 1 row), checked by `CapabilityMatrix::check`; `doc/capability-matrix.md` gets no reference row.
- *Epic 10*: the pipeline (Story 10.3) reads tier, confirmation and exception class from the declaration, so the policy engine and the matrix agree through this check; `own_account_delivery` destinations (above); the Core's own tools (section 1 rows such as `Read own profile and permissions`, Story 10.7's undo) join the tool table, with section 1 claimed by the Core; plugin manifests declare `network_effect` for the kill switch (AD-11), in their own form.
- *The binary*: when `main` starts the Core, `crates/vilicus/src/registry.rs` leaves `#[cfg(test)]`, and SQLCipher and `libcrypto` are linked into `vilicus` from then on.

## Result

All commands ran on 2026-10-21, last after the review fixes (commit `f6268be`), in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, with cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch made inside a new Docker volume, with an empty target directory; the volume was removed afterwards. Mutations ran on another clone with its own target directory, never on the working tree. Each intermediate commit (`11d2470`, `dabfd78`, `d9a0f8e`, `7da6c60`, `3aa73f7`) builds, passes clippy and passes the module API, Core and binary tests.

Gates, as `.github/workflows/ci.yml` runs them:
- `python3 -m unittest discover -s ci`: `Ran 211 tests`, `OK` (unchanged).
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 93 packages`; `--vendor`: `vendor check passed`.
- `python3 ci/check_sqlcipher_source.py`: `sqlcipher source check passed: 3 files match SHA256SUMS`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- System OpenSSL: `libssl-dev` `3.5.7-1~deb13u3`, `pkg-config` `3.5.7`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 291 passed, none failed (255 before the story, 283 before the review fixes): `vilicus-module-api` 27 (15 before) and 7 examples (3 before), `vilicus-core` 44 (26 before) and 1 example, `vilicus` 2 (0 before).
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (16 fully audited, 4 partially audited, 54 exempted)`, unchanged.
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.
- `cargo tree --workspace -e features -i rusqlite`: `load_extension` appears nowhere (0 lines).
- The `vilicus` executable links no SQLCipher: 0 `sqlite3_` text symbols, no `libcrypto` in `ldd`.
- The fuzz coverage check is not concerned: `vilicus-proto` is unchanged.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (FR-22, AD-9) | **Pass** | `a_declaration_with_tools_that_meet_every_rule_is_accepted`: a module whose tools carry name, schema, tier, network effect, exception class, confirmation and matrix row is accepted, and each field reads back. The `assert_valid` examples: the valid example builds a module with a tool in a `const` item; a tool without `network_effect` does not compile (`compile_fail`, E0063); an exception class outside the closed set does not compile (`compile_fail`, E0599). `tool_names_arguments_and_undo_handlers_are_checked` (names, duplicate tools, arguments under the field rules, envelope names refused for each `ENVELOPE` column), `matrix_sections_and_rows_are_checked`, `every_tool_error_names_its_rule_and_its_tool`. Registry: `Registry::tools()` lists the tool table (`a_registry_that_matches_the_matrix_has_no_difference`). |
| AC2 (FR-22, I13, I18) | **Pass** | The gate: `vilicus` `registry::tests::the_shipped_tool_table_matches_the_capability_matrix` (no shipped module in V0.1), guarded by `the_registry_is_the_binary_s_only_use_of_the_core_while_it_is_test_only`. On the fixture: `a_tool_without_a_row_and_a_row_without_a_tool_are_each_named` (a misnamed row gives `ToolWithoutRow` and `RowWithoutTool`, each named in the check's message; missing tools give each row named); `a_section_the_matrix_lacks_is_named` (an absent section and one without a table of actions); `a_tool_takes_its_rows_tier_and_confirmation` (every difference of a tool reported); `a_tool_takes_its_rows_exception_class_and_network_effect`; `two_tools_may_implement_one_row`; `claimed_rows_need_a_tool_one_tier_and_a_settled_class` (a section no module claims needs no tool); `two_modules_cannot_claim_one_section`; `no_module_claims_the_core_section`; `an_unreadable_matrix_is_refused` (twenty-two forms, each with its line, and a fence outside the numbered sections skipped); `exception_class_cells_read_strictly`; `tier_and_confirmation_cells_read_as_the_legend_writes_them`. On `doc/capability-matrix.md`: `the_capability_matrix_document_reads_back` (every row kind and every class present); `every_document_section_needs_a_tool_for_each_tool_row` claims each section but the Core's in turn with one tool per row a tool can implement, at the row's tier, confirmation and class, gets no difference except the rows the check cannot assign (Open points), then removes each tool in turn and gets its row named; `every_document_row_with_a_class_needs_it_declared`. |
| AC3 (FR-60, FR-21, D46, DC-13) | **Pass** | `a_tier_2_tool_is_refused_before_the_native_app` (with and without a network effect); `a_cross_partition_tool_is_refused_at_every_tier` (tiers 0, 1 and 2); the `assert_valid` example of a tier 2 tool in a `const` item (`compile_fail`, E0080). A tool naming a tier 2 row of the matrix is a `RowNotATool` difference (`a_tool_cannot_implement_a_row_that_is_not_a_tools`). How the static check sees a cross-partition write: Deviations. |
| AC4 (I13, AD-48) | **Pass** | `a_network_effect_needs_tier_2_or_an_exception_class_at_tier_1`: a network effect at tier 0 or 1 without a class is refused; each class at tier 0 or 2 is refused; each class without a network effect is refused; each class at tier 1 with a network effect, light confirmation and an undo handler is accepted. `exception_classes_require_their_confirmation_and_an_undo_handler` reads AD-48's sentence in the spine to know which classes require light confirmation, checks that it places every class of `ExceptionClass::ALL`, then: without light confirmation, `reversible_external_state` and `own_account_delivery` are refused and `restorable_physical` accepted; without an undo handler, every class is refused. `confirmation_and_undo_handler_follow_the_tier`; `a_read_that_fetches_declares_no_network_effect`. Against the matrix (review M1): a tool that omits its row's class, and with it the network effect and the undo handler, fails the check (`a_tool_takes_its_rows_exception_class_and_network_effect`; `every_document_row_with_a_class_needs_it_declared` for the cart, own-account delivery and restorable physical rows of the document), and the matrix itself holds AD-48 (`exception_class_cells_read_strictly`). |
| AC5 (I13, AD-48 / I18, AD-8) | **Pass** | `a_tier_h_tool_is_refused` (with and without a network effect, each class); the `assert_valid` example of a tier H tool in a `const` item (`compile_fail`, E0080). `no_h_action_of_the_document_is_reachable_as_a_tool`: for every H and `n/a` row of `doc/capability-matrix.md`, a tool of tier 0 or 1 naming it is a `RowNotATool` difference, and a tool of tier H naming it is refused by `Registry::new` with `HumanOnlyTool`; it also checks that the actions AC5 names (pairing, recovery, token creation, provider configuration, plugin install, plugin rights) are such rows. `a_tool_cannot_implement_a_row_that_is_not_a_tools` on the fixture. |

Mutations, each on the clone at `f6268be`, with the file restored after each, the module API, Core and binary tests rerun with `--no-fail-fast`. The unmutated clone passed the same tests in the same setup. Each mutation made the named tests fail, 55 of 55 (53 by a script over the source and the matrix document, 2 on the binary by hand); the first round's 33 reran on the revised code:
- **Declaration rules (`vilicus-module-api`):**
  - tier H accepted: `a_tier_h_tool_is_refused`, the tier H `compile_fail` example (which then builds), and `no_h_action_of_the_document_is_reachable_as_a_tool` (Core);
  - tier 2 accepted: `a_tier_2_tool_is_refused_before_the_native_app` and the tier 2 `compile_fail` example;
  - `crosses_partitions` accepted: `a_cross_partition_tool_is_refused_at_every_tier`;
  - a network effect below tier 2 without a class: `a_network_effect_needs_tier_2_or_an_exception_class_at_tier_1`, `a_read_that_fetches_declares_no_network_effect`; a class outside tier 1, a class without a network effect, each: the first of these;
  - light confirmation not required, undo handler not required, each: `exception_classes_require_their_confirmation_and_an_undo_handler`;
  - light confirmation outside tier 1, an undo handler on a read, each accepted: `confirmation_and_undo_handler_follow_the_tier`;
  - a row outside the module's sections, an invalid action text, each: `matrix_sections_and_rows_are_checked`; unchecked sections: the same, `no_module_claims_the_core_section`, `no_h_action_of_the_document_is_reachable_as_a_tool`;
  - the Core section claimable (review): `matrix_sections_and_rows_are_checked`, `no_module_claims_the_core_section`, `no_h_action_of_the_document_is_reachable_as_a_tool`;
  - arguments unchecked, duplicate tools accepted, each: `tool_names_arguments_and_undo_handlers_are_checked`.
- **Registry and matrix check (`vilicus-core`):**
  - one section claimed by two modules: `two_modules_cannot_claim_one_section`;
  - a tool without its row not reported: `a_tool_without_a_row_and_a_row_without_a_tool_are_each_named`, `a_section_the_matrix_lacks_is_named`;
  - a row without a tool not reported: the same first test, `claimed_rows_need_a_tool_one_tier_and_a_settled_class`, `every_document_section_needs_a_tool_for_each_tool_row`;
  - H, `n/a` and tier 2 rows taken as tool rows: `a_tool_cannot_implement_a_row_that_is_not_a_tools`, `no_h_action_of_the_document_is_reachable_as_a_tool`;
  - `H` read as tier 1, `n/a` read as tier 0, each: nine or more matrix tests, `no_h_action_of_the_document_is_reachable_as_a_tool` among them;
  - tier unchecked: `a_tool_takes_its_rows_tier_and_confirmation`, `two_tools_may_implement_one_row`; confirmation unchecked: the first;
  - a missing section not reported: `a_section_the_matrix_lacks_is_named`; a section without a table of actions claimable (review): the same;
  - a row of no single tier not reported: `claimed_rows_need_a_tool_one_tier_and_a_settled_class`, `every_document_section_needs_a_tool_for_each_tool_row`;
  - any confirmation cell starting with `none` or `light` read as that confirmation: `tier_and_confirmation_cells_read_as_the_legend_writes_them`;
  - a repeated action, a repeated section, a missing Tier column, an unchecked cell count, each accepted by the reader: `an_unreadable_matrix_is_refused`.
- **Review fixes (`vilicus-core`):**
  - exception class not compared, network effect not compared, each: `a_tool_takes_its_rows_exception_class_and_network_effect`, `every_document_row_with_a_class_needs_it_declared`;
  - `unsettled` read as `none`: five tests, `claimed_rows_need_a_tool_one_tier_and_a_settled_class` and `the_capability_matrix_document_reads_back` among them; a tool on an unsettled row accepted: `a_tool_cannot_implement_a_row_that_is_not_a_tools`; a claimed unsettled row not reported: `claimed_rows_need_a_tool_one_tier_and_a_settled_class`, `every_document_section_needs_a_tool_for_each_tool_row`;
  - an unknown class read as `none`, a class outside tier 1 in the matrix, a light-confirmation class without light, each accepted: `exception_class_cells_read_strictly`;
  - the Exception class column optional, an indented row, a table row in a fence, fences not tracked, a misplaced Action column, a separator of another width, a header without separator in the text and at the end, each accepted: `an_unreadable_matrix_is_refused`;
  - a closing `##` kept in a title: `the_fixture_reads_back_into_its_sections_and_rows`;
  - only the first difference of a tool reported: `a_tool_takes_its_rows_tier_and_confirmation`.
- **The binary (`vilicus`):**
  - `doc/capability-matrix.md` with its section 2 Tier header renamed: `the_shipped_tool_table_matches_the_capability_matrix` fails with the reading error;
  - `main.rs` naming `vilicus_core`, and `main.rs` building a registry, each: `the_registry_is_the_binary_s_only_use_of_the_core_while_it_is_test_only`;
  - by hand, a probe module in `REGISTRY` (the binary given a dependency on `vilicus-module-api`, built `--offline` since `Cargo.lock` then changes) claiming section 2 with one tool on a misnamed row: the shipped test fails and names the tool without its row and each of the five tier 0 and 1 rows of section 2 without a tool;
  - by hand, the same module with a tier H tool: the binary's test build stops (E0080, `a tool is tier H, which is never a tool`); the plain `cargo build -p vilicus` passes, the registry being compiled with the tests only (Decisions).
- Not shown by a mutation: that `network_effect` has no default, which is a property of the type; the E0063 `compile_fail` example shows it.

**Review of 2026-10-21** (independent review on PR #4, with the coordinator's decisions; each fix carries tests, and a mutation that removes it fails them, above):

| Item | Resolution |
|---|---|
| M1, a tool could omit its exception class | The coordinator's decision: an `Exception class` column in every table of actions of `doc/capability-matrix.md`, filled only from what each row states (What was built), explained in the Legend. The reader takes it strictly (`RowClass`) and holds AD-48 on the matrix itself; the check compares each tool's class with its row's and its network effect with the one the class implies. The review's probes, the cart row of section 6 and the own-address mail row of section 8 without a class, are now `ExceptionClassMismatch` and `NetworkEffectMismatch` (`a_tool_takes_its_rows_exception_class_and_network_effect`, and `every_document_row_with_a_class_needs_it_declared` on every row of the document with a class). |
| M2, the meaning of `network_effect` | The coordinator's decision: a change of state outside the instance's own files (a third-party system, an account or a device); a read that only fetches is not one. Docs and error texts follow; the rules did not need to change (`a_read_that_fetches_declares_no_network_effect`). Tier 1 device commands without a class are `unsettled` rows the check names, and a design question in Open points. |
| 1, the test-only binary registry | `the_registry_is_the_binary_s_only_use_of_the_core_while_it_is_test_only`: no source of the binary but `registry.rs` builds a registry, and while `mod registry` is `#[cfg(test)]` none names `vilicus_core`. |
| 2, the reader fail-closed | An indented table row and a table row in a fenced code block of a numbered section, a table with a `Tier` column not led by exactly `Action`, a separator of another width and a header without its separator (the review's lone row after a blank line) are refused, each with its line (`an_unreadable_matrix_is_refused`); a fence outside the numbered sections is skipped. |
| 3, claims | A claimed section without a table of actions (11, 12, 13) is `SectionMissing`; no module claims section 1 (`CORE_MATRIX_SECTION`, `CoreMatrixSection`), whose title the module API test reads from the document. |
| Nits | Every difference of a tool is reported (`a_tool_takes_its_rows_tier_and_confirmation`); two tools on one row allowed and documented (`two_tools_may_implement_one_row`); doc lines over 100 characters wrapped; a closing `##` stripped from a heading; `sprint-status.yaml` `last_updated` set to the actual time. |
