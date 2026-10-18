---
title: 'Merge gates: format, lint and supply chain'
epic: 2
story: 2
status: done
author: Rwx-G
created: 2026-10-16
implements: [AD-33, D28, D29, NFR-6, D61, D120]
---

# Story 2.2: Merge gates: format, lint and supply chain

As a project maintainer,
I want formatting, linting and supply-chain checks to block every merge,
So that no unreviewed dependency, incompatible licence or lint warning reaches the main branch.

**Acceptance Criteria:**

**AC1 (AD-33)**
**Given** a pull request on GitHub Actions
**When** the merge workflow runs
**Then** `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` must pass for the merge to be allowed
**And** a deliberately unformatted file or a clippy warning makes the workflow fail.

**AC2 (D29, NFR-6)**
**Given** `deny.toml` with a licence allowlist limited to licences compatible with Apache-2.0
**When** `cargo deny check` runs
**Then** it passes on the workspace
**And** adding a dependency under a licence outside the allowlist fails the check.

**AC3 (D28, NFR-6)**
**Given** two major versions of the same cryptographic crate in the dependency tree
**When** `cargo deny check bans` runs
**Then** it fails unless the duplicate is listed in `deny.toml` with the dependency that forces it and the reason.

**AC4 (D28, NFR-6)**
**Given** the workspace dependencies
**When** `cargo vet` and `cargo audit` run
**Then** both must be clean for the merge to be allowed
**And** an unvetted new crate or a crate with an open advisory fails the workflow.

**AC5 (D28)**
**Given** the allowlist of crates permitted to have a `build.rs` or to be procedural macros
**When** a dependency outside the allowlist with a build script or a procedural macro enters the tree
**Then** the check fails naming the crate
**And** builds run with `--locked` against vendored dependencies.

**AC6 (D61, D120, AD-33)**
**Given** the HPKE spike package `spikes/hpke-review/` and the first CI workflow of the repository
**When** a push or pull request changes a path under `spikes/hpke-review/**`
**Then** a job on a Linux runner with Docker runs `bash spikes/hpke-review/run.sh` (the RFC 9180 vector of the AD-18 suite, the 10 000-case two-way cross-test against `hpke-rs` 0.8.0 with its RustCrypto and libcrux providers, the error paths, the sender substitution test, the `zeroize` features and the dependency tree) and fails the merge when the script exits non-zero
**And** the same job runs `cargo audit` on `spikes/hpke-review/Cargo.lock`, which `run.sh` does not do (gate HPKE-3)
**And** the link to the job's first green run is added to the HPKE item of `doc/research-notes.md` section 4, which completes the D120 gate (the GitHub Actions shape is in Story 1.2, Result, "Not run here, CI").

**Dependencies:**
- Story 2.1 (workspace and CI workflow exist)
- Story 1.2 (the HPKE spike package and its `run.sh`)

**References:**
- `doc/architecture-spine.md` AD-33, Consistency Conventions (Dependencies)
- `doc/decisions.md` D28, D29, D61, D120
- `doc/prd.md` section 7 (Supply chain)
- `doc/qa/gates/1.2-hpke-internal-review-and-cross-test.yml` (HPKE-1, HPKE-3)

## Implementation Notes

**What was built**
- `.github/workflows/ci.yml` gets four jobs next to the three of Story 2.1, one gate per job: `deny` (`cargo deny --locked check`), `vet` (`cargo vet --locked`), `audit` (`cargo audit --deny warnings`) and `hpke-review`. The workflow also runs on `merge_group` (the merge queue), on `workflow_dispatch`, and weekly on `schedule`, so that an advisory published after a merge fails a run without waiting for a change. `lint` and `build-and-test` now use `--frozen` (`--locked` without the network) and `--config ci/cargo-vendored.toml`, so a third-party crate can only come from `vendor/`.
- `.github/actions/cargo-tool/action.yml`, a local composite action that builds one cargo tool with `cargo install --locked <tool>@<version>` and caches the binary with `actions/cache` v6.1.0, pinned by commit SHA.
- `deny.toml`: a licence allowlist, every duplicate denied, advisories (unmaintained, unsound and yanked count as errors), and crates.io as the only source.
- `supply-chain/` (`config.toml`, `audits.toml`, `imports.lock`), from `cargo vet init` and `cargo vet import` of five audit sets of the cargo-vet registry.
- `ci/check_supply_chain.py`, with its data file `ci/build_time_code.toml` (empty) and tests `ci/test_check_supply_chain.py`. It checks build-time code (AC5) and the duplicate exceptions of `deny.toml` (AC3). With `--vendor`, it compares `vendor/` with a fresh `cargo vendor --locked --versioned-dirs`. The same test file holds `WorkflowAgreementTest`, which pins each gate job, its check name, its commands with their flags, and the triggers.
- `ci/must_run.py` and `ci/test_must_run.py`: the change detection of the `hpke-review` job, tested on a real git repository.
- `ci/check_audit_report.py` and `ci/test_check_audit_report.py`, with `spikes/hpke-review/audit-exceptions.toml`: the advisory gate on the spike lockfile.
- `ci/cargo-vendored.toml`, which replaces crates.io with the directory source `vendor/`. CI passes it with `--config` to every workspace cargo command that builds, tests, lints or vendors: the `clippy`, `build` and `test` steps, and the `cargo metadata` and `cargo vendor` runs of the two Python checks. `vendor/` does not exist yet: there is no third-party crate, and `cargo vendor` writes nothing ("There is no dependency to vendor in this project").
- Changes to Story 2.1's check in `ci/check_workspace.py`:
  - Story 2.1's rule stands unchanged: any `.cargo/config` or `.cargo/config.toml` at the root or under `crates/` or `testing/` fails, whatever it contains, including the vendored replacement itself.
  - A new check requires `ci/cargo-vendored.toml` and refuses it unless its parsed content is exactly the source replacement.
  - Files under `vendor/` are exempt from the SPDX header scan, since third-party sources keep their own headers.
  - Every workspace crate must be `publish = false`.
  - The tree holds no path package other than the workspace members, and the root manifest has no `[patch]` or `[replace]` table. Either one could swap a registry crate for local code that every other gate would wave through: cargo-deny reports `sources ok`, and cargo-vet treats the crate as first-party.
- `.gitignore`: `!/vendor/**`, so that no root pattern (`.env.*`, `*.db`, `__pycache__/`, `*.rs.bk` and others) drops a vendored file.
- `.gitattributes`: `vendor/** -text`, because vendored files are checked against the checksums `cargo vendor` records, and `spikes/*/vectors/** -text`, because vectors are compared byte for byte (see Open points).

**Decisions and why**
- *Tool install: `cargo install --locked` at the Stack version, not release binaries.*
  - Why: the tool's source and every one of its dependencies are fetched from crates.io and verified against the checksums of the tool's own published `Cargo.lock`. That is the same anchor the workspace trusts, and no hash has to be recorded and refreshed in this repository. A release binary with a recorded SHA-256 would only prove that the file is unchanged since someone downloaded it once.
  - What it gives up: a cold build costs a few minutes per tool. The binary is therefore cached by tool, version, toolchain channel and runner OS.
  - The build runs in `runner.temp`, with `RUSTUP_TOOLCHAIN` set to the channel of `rust-toolchain.toml`, so the repository's source replacement never applies to the tool's dependencies.
  - Cache safety: a cache entry written by a pull request is visible to that pull request only, so a pull request cannot poison the binary `main` uses.
  - The only third-party action is `actions/cache`, GitHub's own, like `actions/checkout`.
  - `WorkflowAgreementTest` fails when a tool version in the workflow differs from the spine's Stack table.
- *Licence allowlist:* the permissive licences of the Apache Software Foundation's Category A (https://www.apache.org/legal/resolved.html, read on 2026-10-18). Their only conditions are notices and disclaimers.
  - Allowed: `0BSD`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `BSL-1.0`, `CC0-1.0` (ASF lists it under public domain), `ISC`, `MIT`, `MIT-0` and `Zlib`.
  - `Unicode-3.0` and `Unicode-DFS-2016` are two versions of the Unicode, Inc. licence that ASF lists. Mapping that licence to these SPDX identifiers is my reading.
  - `Apache-2.0 WITH LLVM-exception` is allowed because the exception only removes conditions.
  - Refused: MPL-2.0, which ASF ranks in Category B. Also refused: OpenSSL and CDLA-Permissive-2.0, which are not in Category A as ASF names it. Either is added only when a dependency that needs it is approved.
  - `unused-allowed-license = "allow"`, because the list is a policy, not an inventory.
  - Workspace crates are checked too.
- *Duplicates: `multiple-versions = "deny"` for every crate, not a list of cryptographic crates.*
  - Why: a list of which crates count as cryptographic would drift, and a crate missing from it would pass silently.
  - What it gives up: a non-cryptographic duplicate also needs a listed reason.
  - cargo-deny accepts any `skip` entry, even one without a reason, so `ci/check_supply_chain.py` enforces the AC3 shape:
    - each entry is `{ crate = "<name>@<x.y.z>", reason = "forced by <name>@<version>: <why>" }`;
    - the forcing package must be in the tree and depend on that exact version;
    - the skipped version must exist beside another one;
    - `skip-tree` is refused, because it hides a whole subtree.
  - `multiple-versions-include-dev = true`: a version that only tests pull in is still a crate to vet and to vendor twice.
- *Graph:* no `targets`, so every platform is judged. A crate pulled in only for another platform never ships on Debian 13, but it is vendored all the same, so its licence and advisories matter. `all-features = true`, so an optional dependency is judged before any feature enables it. The build-time code check judges the same set: every platform, with `cargo metadata --all-features`.
- *Advisories:*
  - The D130 `paste` exception is not added. The tree has no `dcbor` yet, so the exception belongs to Story 2.5.
  - `cargo audit --deny warnings` on the workspace, to match cargo-deny's strictness on unmaintained and yanked crates.
  - On the spike lockfile, the gate is `cargo audit --deny warnings` with reasoned exceptions:
    - Every vulnerability fails, and so does every warning that `spikes/hpke-review/audit-exceptions.toml` does not list. Advisory warnings are listed by id, yanked crates as `"<name>@<version>"`, each with its reason.
    - An exception that matches nothing fails, so the file cannot outlive the lockfile.
    - cargo-audit can ignore an advisory id (`--ignore`), but it cannot except a single yanked crate: `--deny` takes only a kind, and `--no-yanked` turns off every yanked check. The narrowest option is therefore to judge `cargo audit --json` with `ci/check_audit_report.py`. A crashed cargo-audit leaves no JSON, and the check fails.
    - The two exceptions, both in the dev-only `hpke-rs` 0.8.0 chain of the cross-test, are traced with `cargo tree -i`:
      - RUSTSEC-2026-0173: `proc-macro-error2` 2.0.1, unmaintained, a build-time dependency of `hax-lib-macros` under `libcrux-intrinsics`.
      - Yanked `inout` 0.2.3: reached through `aead` 0.6.1 and `aes-gcm` 0.11.1 of `hpke-rs-rust-crypto`. `hpke` 0.13.0 uses `aes-gcm` 0.10.3 and `inout` 0.1.4, and `cargo tree -e normal -i inout@0.2.3` shows no normal path.
    - The spike's `Cargo.lock` is unchanged; removing an exception means updating it, which reopens the review (D120).
- *cargo vet imports:*
  - The five sets: bytecode-alliance (Wasmtime), google (Chromium, Android and Fuchsia audits, with broad RustCrypto coverage), isrg (Let's Encrypt and Divvi Up, cryptography-heavy), mozilla (Firefox) and zcash (cryptographic crates).
  - Why these: large organisations that publish audits under the shared `safe-to-deploy` and `safe-to-run` criteria. Importing a set means trusting that organisation's auditors, so the list is limited to the organisations whose audits cover the Stack's crates.
  - Policy: the default is kept, `safe-to-deploy`, and `safe-to-run` for dev-dependencies.
  - Workspace crates need no `[policy]` entry. cargo-vet treats `publish = false` crates as first-party, which is equivalent to `audit-as-crates-io = false`. That is why the manifest check now fails on a publishable crate.
  - CI runs `cargo vet --locked`, which uses `imports.lock` and fetches nothing. Refreshing the imports is a reviewed change to `supply-chain/`.
- *Vendoring shape:*
  - `vendor/` is committed. It is written by `cargo vendor --versioned-dirs vendor`, which ignores the `[source]` replacement and also updates `Cargo.lock`.
  - `ci/cargo-vendored.toml` holds the replacement and nothing else, and is passed with `--config`.
  - Why not a root `.cargo/config.toml`: cargo applies one to every directory below it, so it would also point every spike under `spikes/` at the root `vendor/`. That breaks `cargo` there, including the Debian VM runs that sync the whole repository; it was observed with `cargo metadata --locked` in `spikes/canonical-cbor` (`failed to read root of directory source`). A `--config` file applies only where it is passed.
  - Path resolution: cargo resolves the file's `directory = "vendor"` against the parent of the file's directory, that is the repository root, whatever the working directory. A build from `crates/vilicus-types` with `--config ../../ci/cargo-vendored.toml` reads `<root>/vendor`, and a copy of the crates only under `ci/vendor/` is not found.
  - What it gives up: a local build without the flag reads crates.io instead of `vendor/`. CI cannot miss the flag: `WorkflowAgreementTest` fails on any workspace `cargo build`, `test`, `clippy`, `check`, `run`, `doc`, `vendor` or `metadata` line of the workflow without it, and on either script losing it.
  - Why vendor at all: this is the only way D28's "vendoring with `--locked`" holds offline. The reviewed sources are the bytes in the repository, and a `--frozen` build cannot reach crates.io.
  - What fails: the `workspace-policy` job, when `vendor/` differs from what `cargo vendor --locked` writes from `Cargo.lock`; and the Rust build itself, on any edited vendored file (checksum) or on a crate missing from `vendor/`.
  - To add a dependency:
    1. Edit the manifest.
    2. Run `cargo vendor --versioned-dirs vendor`.
    3. Commit the lockfile and `vendor/`, together with the changes the dependency needs in `deny.toml`, `supply-chain/` and `ci/build_time_code.toml`.
- *Build-time code allowlist:*
  - Entries are keyed by package name, each with a reason.
  - Every package with a `custom-build` or `proc-macro` target counts, workspace members included, since a first-party `build.rs` also runs at build time.
  - An entry that matches no such package fails, so the list cannot outlive the crate it was written for.
  - A new version of an allowlisted crate passes this check, but `cargo vet` still requires that version's audit.
- *`hpke-review` job: path filter inside the job, not a workflow-level `paths:` filter.*
  - Why: AC6 says the job "fails the merge", so it must be a required check. A required check whose workflow is skipped by `paths:` stays pending, which would block every pull request that does not touch the spike.
  - How:
    - The job always runs and checks out the full history.
    - `ci/must_run.py` compares the event's base with `HEAD` over the watched paths: `spikes/hpke-review`, `.github/workflows/ci.yml`, `.github/actions/cargo-tool`, `ci/must_run.py` and `ci/check_audit_report.py`. The base is the pull request base, `merge_group.base_sha` in the merge queue, or `before` on a push.
    - The steps after it run only on a change, on `workflow_dispatch` or `schedule` (any event that compares nothing), or when the base is empty, unknown to the clone, or cannot be compared, which fails safe.
    - Without a change, the job passes in seconds.
    - The steps are `bash spikes/hpke-review/run.sh`, run with the Docker of `ubuntu-24.04` and the spike's own pinned `rust:1.94-trixie` image, then the advisory gate on the spike lockfile.
- *Workflow pinned by a test:* `WorkflowAgreementTest` checks that each gate job exists with its check name and its command lines, whole: `-D warnings`, `--frozen`, `--locked` and `--deny warnings` included. It also checks that no gate step carries `continue-on-error` or an `if:` (outside the HPKE steps, which must all depend on the detection), and that all five triggers are present. The table in the test is written by hand on purpose: it is the independent statement of what the workflow must keep.

**Files**
- `.github/workflows/ci.yml`, `.github/actions/cargo-tool/action.yml`
- `deny.toml`, `ci/cargo-vendored.toml`, `supply-chain/config.toml`, `supply-chain/audits.toml`, `supply-chain/imports.lock`
- `ci/check_supply_chain.py`, `ci/build_time_code.toml`, `ci/test_check_supply_chain.py`
- `ci/must_run.py`, `ci/test_must_run.py`, `ci/check_audit_report.py`, `ci/test_check_audit_report.py`, `spikes/hpke-review/audit-exceptions.toml`
- `ci/check_workspace.py`, `ci/test_check_workspace.py` (Cargo configuration, vendor SPDX exemption, `publish = false`, path packages, `[patch]` and `[replace]`)
- `.gitattributes`, `.gitignore`

**Open points**
- *AC6, last clause:* once the job has run green on GitHub, add the link to that first run to the HPKE item of `doc/research-notes.md` section 4. That completes D120. It can run through `workflow_dispatch` on this branch, or on the pull request, since this change touches `ci.yml`. The link is not added here.
- *Required checks:* branch protection is an admin setting and was not changed. The check names to require are in Result.
- *Spike lockfile exceptions:* `inout` 0.2.3 (yanked, new since Story 1.2) and RUSTSEC-2026-0173 (already recorded in Story 1.2) are listed in `spikes/hpke-review/audit-exceptions.toml`. Removing them means updating the spike lockfile, which reopens the review (D120); that is left to the owner.
- *Owner action, before commit:* delete `.cargo/config.toml` and then the empty `.cargo/` directory at the repository root. They are left over from the first shape of this story, and `rm` is denied in this workspace. Nothing in CI or in the tests reads them, and the verification above ran on a copy without them. Until they are deleted, `python3 ci/check_workspace.py` on the working tree fails with `unsafe: <root>/.cargo/config.toml exists`, which is Story 2.1's rule working as intended.
- *Story 3.1 conflicts with Story 2.1's rule:* its AC plans `LIBSQLITE3_FLAGS` in "the workspace `.cargo/config.toml` `[env]`", which `ci/check_workspace.py` refuses. That story needs another carrier for the flags, such as a build-time environment set by the CI step or a second `--config` file under `ci/` with its own check, decided when it is built.
- *Windows checkout of the spike vectors:* with `core.autocrlf=true` (Git for Windows' system default), the files in `spikes/hpke-review/vectors/` were checked out with CRLF, so `run.sh` failed `vectors-subset-sha256` on this working tree. The `-text` attribute added here prevents that from the next checkout of those files on; an existing working copy keeps its CRLF until then. GitHub's Linux runners are not affected.
- *Not used:* cargo-deny's `[bans.build]` (build-script allowlist and executable detection). Its allowlist would duplicate `ci/build_time_code.toml` for build scripts and does not cover procedural macros. Its executable detection could be added later.
- `.claude/rules/vilicus-rust.md` still names the Story 2.1 jobs only. It should point at the jobs of `ci.yml` without listing them; that edit is left to the owner.

## Result

All commands ran on 2026-10-18 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), with `rust-toolchain.toml` active (`rustc 1.99.0 (b940084d7 2026-09-28)`). The tools were cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2, built with `cargo install --locked`. Commands ran on a throwaway copy of the repository made inside the container, without the root `.cargo/` directory for the final shape, and each mutation on a fresh copy, never on the working tree. A mutation that adds a dependency is followed by `cargo vendor --versioned-dirs vendor` in that copy, as the developer flow above prescribes. `actionlint` 1.7.7 reports no finding. The workflow has not run on GitHub yet.

Baseline on the change as committed:

- `python3 -m unittest discover -s ci`: `Ran 90 tests`, `OK`, none skipped.
- `python3 ci/check_workspace.py`: `workspace checks passed: 12 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 12 packages`.
- `python3 ci/check_supply_chain.py --vendor`: `vendor check passed`.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`, `cargo build --workspace --frozen --config ci/cargo-vendored.toml` and `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: exit 0 each.
- `cargo metadata --locked` inside `spikes/canonical-cbor`: exit 0.
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet --locked`: `Vetting Succeeded (because you have no third-party dependencies)`.
- `cargo audit --deny warnings`: no finding, exit 0.
- `cargo audit --file spikes/hpke-review/Cargo.lock --json`, judged by `python3 ci/check_audit_report.py spikes/hpke-review/audit-exceptions.toml`: `audit report passed: no vulnerability, 2 warning(s), each a listed exception`, exit 0.

| Criterion | Result | Command and observed outcome |
|---|---|---|
| AC1 (AD-33) | **Pass** | Jobs `lint` ("Format and lint"). Mutation, `pub   fn  x( ){ }` appended to `vilicus-types/src/lib.rs`: `cargo fmt --all --check` prints the diff (`+pub fn x() {}`), exit 1. Mutation, a documented `pub fn one() -> u8 { return 1; }`: `cargo fmt` passes, and `cargo clippy --workspace --all-targets --frozen -- -D warnings` fails with `error: unneeded \`return\` statement`, exit 101. Workflow mutations, each on a copy of `ci.yml`, make `WorkflowAgreementTest` fail: ` -- -D warnings` dropped, `--frozen` dropped from the build, `--locked` dropped from `cargo vet`, `--deny warnings` dropped from `cargo audit`, `merge_group` removed, the `lint` check renamed, and `continue-on-error` added to an HPKE step. The unmodified copy passes. |
| AC2 (D29, NFR-6) | **Pass** | Job `deny`. Baseline `licenses ok`. Mutation, `option-ext = "=0.2.0"` (MPL-2.0) in `vilicus-types`, vendored: `cargo deny --locked check licenses` gives `error[rejected]: failed to satisfy license requirements` on `license = "MPL-2.0"`, `licenses FAILED`, exit 4. In the same copy, `cargo build --workspace --frozen` builds from `vendor/` (exit 0), and both Python checks pass, so only the licence gate fails. Mutation, the same crate under `[target.'cfg(windows)'.dependencies]` only, vendored: `licenses FAILED`, exit 4, since `deny.toml` judges every platform. |
| AC3 (D28, NFR-6) | **Pass** | Job `deny`, plus the duplicate-exception check of `workspace-policy`. Mutation, `rand_core = "=0.6.4"` and `rand_chacha = "=0.2.2"` (which needs `rand_core` 0.5.1) in `vilicus-crypto`, vendored: `cargo deny --locked check bans` gives `error[duplicate]: found 2 duplicate entries for crate 'rand_core'`, `bans FAILED`, exit 2. With `skip = [{ crate = "rand_core@0.5.1", reason = "forced by rand_chacha@0.2.2: rand_chacha 0.2 depends on rand_core 0.5" }]`: `bans ok`, exit 0, and `check_supply_chain.py` reports no bans violation. With the reason naming `vilicus-crypto@0.0.0` instead: `bans: skip entry rand_core@0.5.1 says it is forced by vilicus-crypto@0.0.0, which does not depend on rand_core@0.5.1 in the tree`, exit 1. With a bare `skip = ["rand_core@0.5.1"]`: cargo-deny passes (`bans ok`), and `check_supply_chain.py` fails with `must be a table with exactly \`crate = "<name>@<version>"\` and \`reason\``, exit 1. The same copy also shows AC5: `zerocopy` (build script), `zerocopy-derive` (procedural macro), `proc-macro2` and `quote` (build scripts) are each named. Mutation, `rand_core` 0.6.4 as a normal dependency and `rand_chacha` 0.2.2 as a dev-dependency only: `error[duplicate]: found 2 duplicate entries for crate 'rand_core'`, `bans FAILED`, exit 2 (`multiple-versions-include-dev = true`). Unit tests: `DuplicateExceptionTest`; `WorkflowAgreementTest` pins `multiple-versions = "deny"`. |
| AC4 (D28, NFR-6) | **Pass** | Jobs `vet` and `audit`. Mutation, `itoa = "=1.0.15"`, vendored: `cargo vet --locked` gives `Vetting Failed!`, `1 unvetted dependencies: itoa:1.0.15 missing ["safe-to-deploy"]`, exit 255. Mutation, `smallvec = "=1.6.0"`, vendored: `cargo audit --deny warnings` reports `RUSTSEC-2021-0003`, `Buffer overflow in SmallVec::insert_many`, `error: 1 vulnerability found!`, exit 1. `cargo deny --locked check advisories` on the same copy gives `error[vulnerability]`, `advisories FAILED`, exit 1. Mutation, `itoa = "1"` patched by `[patch.crates-io] itoa = { path = "third_party/itoa" }` in the root manifest: `cargo build --frozen` passes, `cargo deny --locked check` gives `advisories ok, bans ok, licenses ok, sources ok`, `cargo vet --locked` says `Vetting Succeeded (because you have no third-party dependencies)`, and `cargo audit` finds nothing. `python3 ci/check_workspace.py` closes that gap with `source: itoa 1.0.99 (/w/third_party/itoa/Cargo.toml) is a path package that is not a workspace member` and `the root Cargo.toml has a [patch] table`, exit 1. Mutation, a `[replace]` table: `the root Cargo.toml has a [replace] table`, exit 1. Unit tests: `SourceTest` (path package, `[patch]` and `[replace]` tables), and an end-to-end `[patch.crates-io]` test on real `cargo metadata` that runs without the network. |
| AC5 (D28) | **Pass** | Checks of `workspace-policy` and the `--frozen` builds. Mutation, `serde_derive = "=1.0.228"`, vendored: `python3 ci/check_supply_chain.py` names `proc-macro2 1.0.107 has a build script (custom-build target)`, `quote 1.0.47 has a build script` and `serde_derive 1.0.228 has a procedural macro (proc-macro target)`, each `not on the allowlist of ci/build_time_code.toml`, exit 1. With the three entries added: `supply-chain checks passed: 17 packages`, and `cargo build --workspace --frozen` passes from `vendor/`. Vendored path: a vendored file edited makes `--vendor` report `vendor/option-ext-0.2.0/src/lib.rs differs from what cargo vendor writes` (exit 1), and `cargo build --frozen` fails with `the listed checksum of .../vendor/option-ext-0.2.0/src/lib.rs has changed` (exit 101). A dependency added without `cargo vendor`: `cargo build --frozen` fails with `failed to get \`option-ext\` as a dependency`, exit 101. Ignore rules: `.env.example`, `data.db`, `Thumbs.db`, `__pycache__/a.pyc` and `src.rs.bk` under `vendor/x-1.0.0/` are all listed by `git status` as files to add. With the `.gitignore` of `HEAD`, without `!/vendor/**`, all of them are ignored. Unit tests: `BuildTimeCodeTest`, `VendorTest`, `EndToEndTest` (a real `cargo metadata` with a `build.rs` crate and a `proc-macro` crate, both named), and in `ci/test_check_workspace.py` the configuration tests: a `.cargo/config` or `.cargo/config.toml` at the root or under `crates/` or `testing/` failing whatever it holds, the vendored replacement included; and for `ci/cargo-vendored.toml`, a missing file, an extra `[build]` or `[env]`, another directory or replacement, an extra source, a partial table and invalid TOML each failing. An SPDX header under `vendor/` passes. Configuration shape, on a copy without the root `.cargo/`: a root `.cargo/config.toml` holding exactly the vendored replacement fails with `unsafe: /w/.cargo/config.toml exists`, exit 1; `[build] rustflags` appended to `ci/cargo-vendored.toml` fails with `must hold only the replacement`, exit 1; a build with the flag and a cold cargo home passes from `vendor/`; with `vendor/` removed it fails with `failed to get` on `option-ext`, exit 101; and without the flag and with a cold cargo home it fails with `no matching package named` for `option-ext`, exit 101. |
| AC6 (D61, D120, AD-33) | **Pass locally, GitHub run pending** | Job `hpke-review`. `bash spikes/hpke-review/run.sh` on an LF export of `HEAD` (`git -c core.autocrlf=false -c core.eol=lf archive`): 12 `PASS` lines, including `cross-test-10000` (10 000 cases per provider in both directions, `byte-identical seals 10000`), then `all checks passed`, exit 0. The same export with one byte of `vectors/SHA256SUMS` changed: `FAIL vectors-subset-sha256`, `1 check(s) failed`, exit 1, so the job step fails. `cargo audit --file spikes/hpke-review/Cargo.lock --json` (179 crate dependencies) reports no vulnerability, plus two warnings: `RUSTSEC-2026-0173` (`proc-macro-error2`, unmaintained) and `inout` 0.2.3, yanked. Both are listed exceptions, so `ci/check_audit_report.py` passes, exit 0. With the `inout@0.2.3` line removed: `audit: inout@0.2.3 has a yanked warning that the exceptions file does not list`, exit 1. With an extra `"foo@1.0.0"` entry: `exception [yanked] foo@1.0.0 matches nothing in the report`, exit 1. An empty report (cargo-audit crashed): exit 1. Unit tests: `JudgeTest` (each warning kind, a second yanked crate, another version, stale and unreasoned exceptions). `ci/must_run.py`, through `MustRunTest` on a real git repository, gives `false` for `pull_request`, `merge_group` and `push` touching `crates/` only, and `true` when a watched path changes under each of those events. It also gives `true` for `workflow_dispatch`, `schedule` and an unknown event, and for an empty, all-zero, unknown or malformed base. The `doc/research-notes.md` link is not added: it needs the first green run on GitHub. |

Checks to require on `main` (check run names, the `name:` of each job; branch protection was not changed):

| Job id | Check name |
|---|---|
| `workspace-policy` | Crate graph, manifests and unsafe code (AD-3, D29) |
| `lint` | Format and lint |
| `build-and-test` | Build and test |
| `deny` | Licences, duplicates, advisories and sources (cargo deny) |
| `vet` | Audited dependencies (cargo vet) |
| `audit` | Security advisories (cargo audit) |
| `hpke-review` | HPKE spike vectors and cross-test (D61, D120) |
