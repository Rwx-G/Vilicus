---
title: 'vilicus-testbed binary and testing tree'
epic: 2
story: 6
status: review
author: Rwx-G
created: 2026-10-16
implements: [FR-109, AD-3, D102, D141]
---

# Story 2.6: vilicus-testbed binary and testing tree

As a project maintainer,
I want a never-packaged `vilicus-testbed` binary and a `testing/` tree for the reference module and test doubles,
So that release gates needing a module or a double run against defined artefacts without test code reaching the shipped binary.

**Acceptance Criteria:**

**AC1 (FR-109, D102)**
**Given** the repository
**When** a maintainer looks under `testing/`
**Then** it holds `vilicus-mod-reference` and one directory per test double (plugin, AI process, channel, model connector), each double built as a separate executable
**And** each crate there is excluded from the shipped package's dependency closure by the check of Story 2.1.

**AC2 (FR-109, AD-3, D141)**
**Given** the workspace
**When** CI builds it
**Then** it produces both `vilicus` and `vilicus-testbed` from the same crates, `vilicus-testbed` additionally linking the reference module
**And** the test doubles are built as separate executables that ship beside `vilicus-testbed` in the testbed artefact and are started by it, not linked into it (D141).

**AC3 (FR-109, D102)**
**Given** every artefact CI marks as part of a release
**When** the packaging check runs
**Then** it fails if `vilicus-testbed`, `vilicus-mod-reference` or any double appears in it.

**AC4 (FR-109)**
**Given** a release-gate test
**When** it is declared
**Then** it carries a target tag, `testbed` for gates that need a module or a double and `package` for every other gate
**And** the CI runner executes each gate against the artefact its tag names, failing on an untagged gate.

**Dependencies:**
- Story 2.1 (workspace and crate graph check)
- Story 2.3 (Debian 13 VM harness that runs the tagged gates)

**References:**
- `doc/prd.md` FR-109
- `doc/architecture-spine.md` AD-3
- `doc/decisions.md` D102, D141

## Implementation Notes

**What was built**
- `testing/`, now a workspace member directory (`members = ["crates/*", "testing/*"]`), with six crates, each with crate-level `//!` documentation stating its role, that it is never packaged, and which story gives it behaviour:
  - `vilicus-mod-reference`, a library depending on `vilicus-module-api` only. It declares nothing yet; Story 3.10 fills it.
  - Four test doubles, each a bin-only crate, so each is a separate executable: `vilicus-double-plugin`, `vilicus-double-ai`, `vilicus-double-channel` and `vilicus-double-model-connector`. Each `main` is empty, so it starts and exits 0 until Stories 10.1, 10.12 and 10.10 give it behaviour, and its doc says so. They have no dependency yet (see Open points).
  - `vilicus-testbed`, a binary depending on `vilicus-core` and `vilicus-mod-reference`, placed under `testing/` as the spine's source tree puts it. Its `main` is empty and its doc says so.
  - The reference module and the doubles carry `#![forbid(unsafe_code)]` and inherit the workspace lints, where `unsafe_code` is forbidden (D140).
- `ci/crate_graph.toml`: the `testing` and `testbed` nodes are now `required`. The `testing` node also matches the pattern `vilicus-double-*`, so a double stays dev-only wherever its directory is, as the reference module does. `vilicus-double-*` joins the `forbid_attribute` patterns. The edges are unchanged, so `SpineAgreementTest` still passes against the AD-3 flowchart. `Cargo.toml` gains the `vilicus-mod-reference` path entry, and `Cargo.lock` gains the six workspace packages and no third-party package.
- `ci/check_workspace.py`: `_linked_closure` was renamed `linked_closure` so that the packaging check can reuse it. The docstring now names test double crates among those that need the forbid attribute.
- AC3: `ci/release_artefacts.toml` and `ci/check_packaging.py`. The data file lists the release artefacts (`[artefact.<name>]`, a bin target of a workspace package; today only `vilicus`). Its `never_packaged` key names the graph nodes whose crates never reach a release (`testing`, `testbed`). The check fails when an artefact is built from a never-packaged crate, carries the name of a testbed executable, or links a never-packaged crate through normal or build edges at any depth of `cargo metadata` (the path is printed). It also fails on an artefact whose package or binary does not exist, and on a malformed data file. `--contents FILE` checks a release file listing, one path per line, and fails on any path naming a never-packaged crate or target, in either spelling (`-` or `_`). Tests: `ci/test_check_packaging.py`.
- AC4: `ci/release_gates.toml` (the declarations) and `ci/release_gates.py` (the runner), with tests in `ci/test_release_gates.py`. The runner has three commands:
  - `check` validates the declarations. A gate without `target`, with a target other than `package` or `testbed`, with an unknown key (so a `tag = ...` typo), without `checks` or `command`, or with a malformed name fails, naming the gate.
  - `build` runs one vendored, frozen `cargo build` per artefact: the shipped packages first, then every never-packaged crate that has a bin target.
  - `run --out DIR` validates the declarations, then runs the packaging check, then works in the guest. It empties `~/release-gates/`, then for each target, package first, copies that artefact into `~/release-gates/<target>/` and runs its gates from there. Each gate runs inside `vm_harness.guarded`, between two reads of `kernel.core_pattern`, and writes `DIR/<gate>.log`. A failing gate fails the run, and the other gates still run.
  - The package artefact is the `[artefact.*]` binaries. The testbed artefact is every bin target of a never-packaged crate, derived from `cargo metadata`, not listed anywhere.
- Three trivial gates prove both tags. `package-executables-start` runs every shipped executable. `package-sees-no-testbed-artefact` runs `test ! -e ../testbed`, which shows in the guest that package gates run before the testbed artefact arrives. `testbed-executables-start` runs `vilicus-testbed` and every double.
- `.github/workflows/ci.yml`:
  - `workspace-policy` gains `python3 ci/check_packaging.py` and `python3 ci/release_gates.py check`.
  - In `vm-smoke`, `python3 ci/release_gates.py build` replaces `cargo build --package vilicus`. A new step after the smoke, `python3 ci/release_gates.py run --out "$VM_RESULTS/release-gates"`, runs under the smoke's condition (`!cancelled() && steps.up.outcome == 'success'`) with a 15-minute timeout, and its logs go up with the `vm-smoke-results` artefact.
  - `build-and-test` is unchanged: `cargo build --workspace` builds `vilicus` and `vilicus-testbed` from the same crates (AC2).
  - `WorkflowAgreementTest` pins the new commands, the booted-VM condition and the timeout. `rg.cargo_build_commands` is added to the vendored-configuration test.
- `ci/vm/README.md`: a "Release gates" section, and the job steps and results artefact updated.

**Decisions and why**
- *Declaration mechanism: one TOML manifest under `ci/`, not a naming convention.*
  - With a required `target` key, "untagged" has a precise meaning: an entry without the key. Both the static check and the runner refuse it before anything runs.
  - A naming convention cannot tell a misnamed gate from a file that is not a gate, so an untagged gate would be silently skipped rather than failed.
  - The manifest is language-neutral. Later gates (Story 14.1) will be Rust tests, Python or shell, and each gate becomes one guest command.
  - What it gives up: a gate's command and its declaration live apart from the test code they invoke, and a gate run as a workflow step outside the runner is not seen. Story 14.1 should keep every release gate behind the runner.
- *Separate builds per artefact.* With resolver 3, one cargo invocation selecting `vilicus` and the testbed crates would unify dependency features across them. The shipped executable could then differ from the one a release builds alone. `build` runs one invocation per artefact.
- *Ordering as isolation.* Package gates finish before the testbed artefact is copied, and the guest directory is emptied at the start of every run. A package gate therefore cannot reach a testbed file, even on a reused VM: the second local run passed `package-sees-no-testbed-artefact` although a previous testbed directory existed.
- *Never-packaged set derived, then pinned.* The set of forbidden crates comes from the graph classification: a new double needs no list update. The `never_packaged` node ids are pinned by a test to the AD-3 flowchart labels "(dev only)" and "(never packaged)".
- *The testbed links the reference module and starts the doubles (D141).* D102 and AD-3 first said the testbed "links" the doubles, while FR-109 makes each double a separate executable, and cargo cannot link a bin-only package (it warns and ignores the dependency). D141 settles it: the doubles ship beside the testbed in the testbed artefact and are started by it, as Story 10.1's "started by `vilicus-testbed`" reads. AC2 was reworded to match. The testbed's doc states this.
- *Known gap, "the same crates as `vilicus`" (FR-109).* The testbed links `vilicus-core` (and through it proto, module-api, crypto, storage and types) and the reference module, from the same workspace sources as `vilicus`. AD-3 draws no edge from the testbed to the Gateway, audit, egress or AI crates, so it cannot link them. The gap stays open until AD-3 gives the testbed those edges (Story 10.1 or 14.1; see Open points). The AC2 repository test checks that the testbed links a crate of every node AD-3 points it to.
- *Python rule deviation*, as in Story 2.1: standard library and `unittest`, no new dependency.

**Review fixes (2026-10-20)**
1. *Shipped sources.* `ci/check_workspace.py` gains `check_shipped_sources`: for every crate in the shipped closure (each shipped crate and what it links through normal and build edges), it fails on a target whose source file is outside the package directory (a `[[bin]] path = "../../testing/..."`), on a `path = "..."` in an attribute (`#[path]`, `cfg_attr` included) or an `include!`, `include_str!` or `include_bytes!` literal that resolves outside the package, on any `include!`-family call with a computed path, which cannot be resolved statically, and on a symbolic link inside the package that points outside it. Comments are ignored. A `#[path]` is resolved from the directory of the file that holds it; inside an inline module the compiler resolves it deeper, so this errs towards failing, never towards passing. `Crate` gains `targets`, the source file of every target. Tests: `ShippedSourcesTest`.
2. *Path-only classification.* A crate that matches a node by its directory only (under `testing/`, neither listed in `crates` nor matching the node's `vilicus-double-*` pattern) fails, so no crate there escapes the checks keyed on names (the forbid attribute, the one-executable test). Tests: `PathOnlyTest`.
3. *Binary named like a double.* `ci/check_packaging.py` fails when an artefact's binary matches the name pattern of a never-packaged node, even when a shipped crate builds it (`vilicus-double-mail` in `crates/vilicus`). Test: `test_artefact_named_by_the_pattern_of_a_never_packaged_node_fails`.
4. *Per-gate timeout.* A gate may declare `timeout`, in whole seconds (`DEFAULT_GATE_TIMEOUT`, 300 s, otherwise); anything but a positive integer fails the declaration. The runner runs the command as `timeout --kill-after=10 <timeout> bash -c '<command>'` from the target directory. Exit 124 is reported as `timed out after <n> s`, the gate fails, and the next gates run. Tests: `test_every_gate_runs_under_its_timeout_or_the_default`, `test_timed_out_gate_fails_naming_the_timeout_and_the_next_gates_run`, and three malformed `timeout` cases.
5. *AC2 reworded to cite D141*, which the owner records: the testbed links the reference module and starts the doubles, which ship beside it.

**What Epic 5 must wire (Story 5.7)**
1. The cargo-deb assets must ship exactly the `[artefact.*]` binaries. Either derive `ci/release_artefacts.toml` from `packaging/` or add a test that compares them.
2. The CI package job must pass `dpkg-deb --contents` paths, one per line, to `python3 ci/check_packaging.py --contents <listing>` (Story 5.7 AC5). Before that, `--contents` must match names case-insensitively (it is case-sensitive today), and the job must also compare the SHA-256 of every packaged file against the files of the testbed artefact, so that a renamed testbed or double executable is still caught.
3. In `ci/release_gates.py`, the package artefact must become the built `.deb`, installed in the guest before the package gates run, instead of the cargo-built executable. The testbed build must stay a separate invocation.

**Files**
- `Cargo.toml`, `Cargo.lock`
- `testing/vilicus-mod-reference/`, `testing/vilicus-testbed/`, `testing/vilicus-double-plugin/`, `testing/vilicus-double-ai/`, `testing/vilicus-double-channel/`, `testing/vilicus-double-model-connector/` (each `Cargo.toml` and `src/lib.rs` or `src/main.rs`)
- `ci/crate_graph.toml`, `ci/check_workspace.py`
- `ci/release_artefacts.toml`, `ci/check_packaging.py`, `ci/test_check_packaging.py`
- `ci/release_gates.toml`, `ci/release_gates.py`, `ci/test_release_gates.py`
- `.github/workflows/ci.yml`, `ci/test_check_supply_chain.py`, `ci/vm/README.md`

**Open points**
- *AD-3 edges for the doubles and the testbed.* The `testing` node reaches only `core` and what it reaches. A plugin double built on `vilicus-plugin-sdk`, or an AI double on `vilicus-ai` or the MCP client, needs the dashed edges `testing -.-> sdk` and `testing -.-> ai` in AD-3 first (Story 10.1). A testbed that runs the Gateway, audit and egress roles for UJ-1 to UJ-3 in the VM needs `testbed --> gw`, `aud`, `egr` and `ai`. I recommend adding them in the spine when Story 10.1 or Story 14.1 first needs them, not now, since nothing links them yet. This is a design change to AD-3, then to `ci/crate_graph.toml`.
- *Story 10.10 AC1* says the AI double uses the connector double "through the interface". FR-109 makes the model connector double a separate executable. Story 10.10 should state whether the connector double is a process the AI double talks to, or a library, which would change this crate's shape.
- *CI test key (D102)*, accepted by the testbed only: not built. It belongs to Story 13.1.
- *The testbed links the reference module through the manifest edge only.* Neither crate has code yet, so nothing of the reference module reaches the testbed's object code until Story 3.10 gives the module a contract and the testbed uses it. The graph check and the packaging check reason on the manifest edge, which is what they must keep out of the shipped closure.
- *Not merge-blocking.* `vm-smoke`, and with it the release gates, does not block a merge until the owner protects `main` and requires its check ("Debian 13 VM smoke test (AD-33)"). The packaging check and `release_gates.py check` run in `workspace-policy`, which blocks only once it is required too.
- *GitHub run:* the workflow changes have not run on GitHub.

## Result

All commands ran on 2026-10-18 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), `rustc 1.99.0 (b940084d7 2026-09-28)`, on a copy of the repository made inside the container without the root `.cargo/` directory. Each mutation ran on its own fresh copy. The VM ran locally from Git Bash through `ci/vm_harness.py`, with the Linux executables built in the same image. `actionlint` 1.7.7 reports no finding on the workflow.

Gates, as `.github/workflows/ci.yml` runs them:

- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`: exit 0, no warning.
- `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0; it compiles `vilicus`, `vilicus-testbed` and the four doubles.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: exit 0.
- `python3 -m unittest discover -s ci`: `Ran 153 tests`, `OK`, none skipped (the repository tests ran on real `cargo metadata`). After the review fixes, on 2026-10-20 in the same image: `cargo fmt --all --check`, `cargo clippy ... -- -D warnings` and `cargo build --workspace` exit 0, `Ran 162 tests`, `OK`, and `check_workspace.py`, `check_packaging.py` and `release_gates.py check` pass. No Rust source changed in the review, so `cargo test` and the VM run were not repeated.
- `python3 ci/check_workspace.py`: `workspace checks passed: 18 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 25 packages`.
- `python3 ci/check_supply_chain.py --vendor`: `vendor check passed`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- Not run here: `cargo deny`, `cargo vet`, `cargo audit`. No third-party package was added, and the new crates are unpublished workspace members.

| Criterion | Result | Command and observed outcome |
|---|---|---|
| AC1 (FR-109, D102) | **Pass** | `testing/` holds `vilicus-mod-reference` and one directory per double. `RepositoryTest.test_each_test_double_is_its_own_executable`: each `vilicus-double-*` crate has exactly one bin target, named after it. Mutation, `vilicus-mod-reference.workspace = true` in `crates/vilicus/Cargo.toml`: `graph: forbidden edge vilicus -> vilicus-mod-reference (normal dependency; AD-3 has no path bin -> testing)` and `graph: dev-only crate vilicus-mod-reference is linked into shipped crate vilicus`, exit 1. Mutation, `vilicus-double-ai` moved to `crates/` and made a dependency of `vilicus`: the same two lines for `vilicus-double-ai`, exit 1, since the pattern keeps it dev-only. Mutation, `testing/vilicus-testbed` moved out: `graph: required node testbed (vilicus-testbed) has no workspace crate`, exit 1. Mutation, an `unsafe {}` block in `vilicus-double-plugin`: `cargo build` fails, exit 101. Mutation, the forbid attribute removed from `vilicus-double-channel`: `unsafe: crate root ... of vilicus-double-channel lacks #![forbid(unsafe_code)]`, exit 1. Unit tests: the derived `GraphTest` (two crates of the pattern node) and `UnsafeTest` (forbid attribute per pattern) cases now cover `vilicus-double-*`. Review fixes, each on a fresh copy: `stray-helper` under `testing/`, listed nowhere: `graph: crate stray-helper (testing/stray-helper) matches node testing by its directory only; ...`, exit 1. |
| AC2 (FR-109, AD-3, D141) | **Pass** as reworded for D141; FR-109's "same crates as `vilicus`" is a known gap until AD-3 gives the testbed edges to `gw`, `aud`, `egr` and `ai` | `cargo build --workspace` builds `vilicus` and `vilicus-testbed` in one run from the same crates. `python3 ci/release_gates.py build`: `cargo build --frozen --config ci/cargo-vendored.toml --package vilicus`, then the same with `--package` for the four doubles and `vilicus-testbed`, exit 0, and all six executables are in `target/debug/`. `RepositoryTest.test_testbed_links_what_ad3_draws`: on real metadata, `vilicus-testbed` links a crate of each node AD-3 points it to (`core`, `testing`). |
| AC3 (FR-109, D102) | **Pass** | Repository: `packaging check passed`. Mutation, `[artefact.testbed]` with package and binary `vilicus-testbed`: `is built from vilicus-testbed, a crate of never-packaged node testbed (D102)`, `carries the name of testbed executable vilicus-testbed`, and `links vilicus-mod-reference ... (vilicus-testbed -> vilicus-mod-reference; D102)`, exit 1. Mutation, the reference module as a dependency of `vilicus`: `release artefact vilicus (vilicus, binary vilicus) links vilicus-mod-reference, a crate of never-packaged node testing (vilicus -> vilicus-mod-reference; D102)`, exit 1. `--contents` with `/usr/bin/vilicus` and a doc path: `2 release files clean`, exit 0. With `/usr/libexec/vilicus/vilicus-double-plugin` and `/usr/bin/vilicus-testbed` added: one `release file ... names never-packaged ...` line each, exit 1. Unit tests: `ArtefactTest` (every never-packaged crate as the artefact, as a normal or build dependency of it, linked at depth with the path named, as a dev-dependency (passes), a name clash, an unknown package or binary), `ConfigTest`, `ContentsTest`, `SpineAgreementTest`, and `RepositoryTest` (the testbed artefact is exactly the executables under `testing/` and shares none with the package). Review fixes, each on a fresh copy: `[[bin]] path = "../../testing/vilicus-testbed/src/main.rs"` in `crates/vilicus`: `shipped: a target of vilicus compiles .../testing/vilicus-testbed/src/main.rs, outside its package`, exit 1. `#[path = "../../../testing/vilicus-testbed/src/main.rs"] mod testbed;` in `vilicus`: `takes a module from ..., outside its package`, exit 1. `include_str!` of a double's source in `vilicus-core` (linked by `vilicus`): `calls include_str!(...), outside its package`, exit 1. A symbolic link `crates/vilicus/src/testbed` to `testing/vilicus-testbed/src`: `links to ..., outside its package`, exit 1. A `src/bin/vilicus-double-mail.rs` in `vilicus` listed as an artefact: `matches vilicus-double-*, the name pattern of never-packaged node testing (D102)`, exit 1. |
| AC4 (FR-109) | **Pass** | Debian 13 VM (`vm_harness.py up`: systemd 257 as PID 1, guest Debian 13 on x86_64; `smoke`: `RESULT PASS`), then `python3 ci/release_gates.py run`. Package first: `PASS package_artefact_copied`, then `PASS gate package-executables-start` (log `./vilicus exited 0`) and `PASS gate package-sees-no-testbed-artefact`. Then `PASS testbed_artefact_copied` and `PASS gate testbed-executables-start`, whose log shows each of the four doubles and `vilicus-testbed` exiting 0. `core_pattern` was unchanged around every gate, `RESULT PASS`, exit 0. A second run on the same VM passed again, including `package-sees-no-testbed-artefact`. Negative cases in the VM: a manifest with an added `exit 4` package gate gives `FAIL gate package-fails: target package, exited 4`, the other gates pass, `RESULT FAIL`, exit 1. A manifest with an untagged gate gives `gates: gate untagged: it has no target tag; ...` and `RESULT FAIL: no gate was run`, exit 1, before the guest is touched; `check` gives the same. Unit tests: `DeclarationTest` (the untagged gate fails every command before the guest, cargo metadata or cargo is called; an unknown target, a `tag` key and other malformed declarations fail; the repository has gates of both tags), `ArtefactTest` (one frozen, vendored build per target; the package build holds no never-packaged crate), `RunnerTest` (package gates run before the testbed copy; each gate runs in its own target directory with that target's executables; a target without gates is not copied; a failing gate fails the run while the others run; a target with no executable fails; a change of `core_pattern` fails). Review fix: every gate now runs under `timeout` (unit tests only; the VM run above predates it). |
