---
title: 'Cargo workspace and crate graph check'
epic: 2
story: 1
status: review
author: Rwx-G
created: 2026-10-16
implements: [AD-3, AD-33, D1, D29, D140]
---

# Story 2.1: Cargo workspace and crate graph check

As a project maintainer,
I want a Cargo workspace laid out as the spine's source tree, with a CI check that enforces the crate dependency graph,
So that no module, adapter or test crate can ever link key, storage or policy code it must not see.

**Acceptance Criteria:**

**AC1 (AD-3, D1)**
**Given** a fresh clone of the repository
**When** `cargo build --workspace --locked` runs with the pinned toolchain (Rust 1.99.0, edition 2024)
**Then** every crate of the spine's Structural Seed (`vilicus`, `vilicus-types`, `vilicus-proto`, `vilicus-crypto`, `vilicus-storage`, `vilicus-module-api`, `vilicus-core`, `vilicus-gateway`, `vilicus-audit`, `vilicus-egress`, `vilicus-ai`, `vilicus-plugin-sdk`) compiles as a library or binary with its crate-level documentation stating its role
**And** the toolchain version is pinned in `rust-toolchain.toml`.

**AC2 (D29)**
**Given** any `Cargo.toml` in the workspace
**When** the manifest check runs in CI
**Then** each manifest declares `license = "Apache-2.0"`
**And** no source file carries an SPDX header.

**AC3 (AD-3, AD-33)**
**Given** the dependency graph of AD-3 encoded as an allowlist of edges
**When** the crate graph check runs over `cargo metadata`
**Then** it passes on the workspace as built
**And** a test that adds a forbidden edge (for example `vilicus-gateway` depending on `vilicus-storage`) makes the check fail with the offending edge named.

**AC4 (AD-3)**
**Given** the `vilicus` binary crate
**When** the crate graph check inspects its non-dev dependencies
**Then** it fails if `vilicus-mod-reference` or any crate under `testing/` is a normal or build dependency of `vilicus`
**And** `vilicus-crypto` and `vilicus-storage` are dependencies of `vilicus-core` only.

**AC5 (AD-3, D140)**
**Given** a module or adapter crate (`vilicus-mod-*`, `vilicus-plugin-*`)
**When** it is compiled
**Then** it carries `#![forbid(unsafe_code)]`
**And** a CI lint fails on any `unsafe` block outside the four crates D140 lists (`vilicus-crypto`, `vilicus-storage`, `vilicus-core`, `vilicus-gateway`), where `unsafe_code` is denied at crate level and every block needs a local allow and a `// SAFETY:` comment.

**Dependencies:**
- None.

**References:**
- `doc/architecture-spine.md` AD-3, AD-33, Structural Seed, Stack
- `doc/decisions.md` D1, D29

## Implementation Notes

**What was built**
- A virtual Cargo workspace (`Cargo.toml`, resolver 3) with the twelve crates of AC1 under `crates/`, as the spine's source tree places them. Each crate is an empty skeleton whose crate-level `//!` documentation states its role and points at the AD that governs it; `vilicus` is a binary (`src/main.rs`, an empty `main`), the others are libraries. No third-party dependency; `Cargo.lock` holds the workspace crates only.
- `rust-toolchain.toml` pins channel 1.99.0 with `rustfmt` and `clippy`; the workspace `rust-version` is the same value, and the manifest check fails when they differ.
- `ci/check_workspace.py`, a Python 3.11+ standard-library script over `cargo metadata --format-version 1 --locked`. Its checks: dependency sources, crate graph (AC3, AC4), manifests and SPDX headers (AC2), unsafe code and Cargo configuration (AC5). It prints every violation and exits 1; on an older Python it exits with a message naming the version it needs.
- `ci/crate_graph.toml`, the only machine encoding of the AD-3 graph (with the required nodes of AC1), plus the unsafe-code policy: the crates D140 allows to hold unsafe code, held there once, and the name patterns that must carry the forbid attribute.
- `ci/test_check_workspace.py`, `unittest` tests: synthetic metadata fixtures built on disk, a hand-written table of forbidden edges, and an end-to-end test on a real `cargo metadata`.
- `.github/workflows/ci.yml`, the first workflow, with three jobs: workspace policy (the script's tests, then the script), format and lint (`cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`) and build and test.

**Decisions and why**
- *Edges are allowed by reachability, not only as drawn* (adopted in D140). A crate may depend directly on any crate it already reaches through the AD-3 edges (for example `vilicus-core` on `vilicus-types`, which it reaches through `vilicus-proto`); a direct edge to something already visible widens nothing. What it would widen is closed by two node attributes: `private` (crypto and storage accept their direct dependents only) and `dev_only` (the `testing/` node).
- *Dev edges:* a dev-dependency must still be an allowed edge, or target a `dev_only` crate from a crate that already reaches everything that crate depends on. The testing node depends on `vilicus-core`, so only `vilicus-core`, `vilicus` and `vilicus-testbed` may take a test crate as a dev-dependency; a test of `vilicus-gateway` cannot pull the Core and its keys in. The rule is derived from the graph, not from a list of crates.
- *Two crates of one pattern node may not depend on each other* (`vilicus-mod-a` on `vilicus-mod-b`): the graph has no `mods -> mods` edge. This matches Story 3.2 AC6.
- *Shipped closure:* independently of the edge check, the normal and build closure of every `shipped` crate (`vilicus`) must hold no `dev_only` crate; a test shows this second guard fires even when the allowlist is edited to admit the edge.
- *Classification:* a crate matches a node by exact name, then by manifest directory (`testing/`), then by name pattern. `vilicus-mod-reference` is named in the `testing` node so it stays dev-only wherever it is placed; a crate that matches no node fails the check, so a new crate needs a graph entry first. Each AC1 node is `required`: deleting a seed crate fails the check.
- *Dependency sources:* the graph sees only edges between members, so every other way to bring workspace code in is refused: a `path` dependency whose target is not a member (a shim under `spikes/` or outside the repository, which could itself depend on `vilicus-storage`), any `git` dependency, and any dependency whose package name is a member name or `vilicus`/`vilicus-*` but which is not that member, read both from the declared dependencies (every kind and target-specific ones included) and from `resolve.nodes` by package id.
- *Every manifest under `crates/` and `testing/` must be a member.* The coordinator asked for `"testing/*"` in `members`; cargo 1.99.0 refuses a member glob that matches no directory (`failed to load manifest for workspace member /work/testing/*`), so it was not added. Story 2.6 adds it with the first crate there; until then this check covers an unreferenced crate.
- *Drift between the data file and its sources:* `SpineAgreementTest` parses the Mermaid flowchart under AD-3 and fails unless the nodes, the edges, the dev-only nodes (sources of dashed edges) and each label's crate name or pattern match `ci/crate_graph.toml`; `DecisionAgreementTest` fails unless the unsafe-allowed list is D140's. Most fixtures are derived from the data file. `HandWrittenEdgeTest` is the deliberate exception: an independent table of forbidden edges, so an encoding error in the data file that derived tests would reproduce still turns a test red. `plugins -> proto` is not in it, because plugins reach proto through the SDK and the graph allows it.
- *Workspace edges are wired now.* Each crate's manifest declares exactly its drawn AD-3 edges, so the check runs against a real graph rather than an empty one. The dependencies are unused until code lands.
- *Manifest fields are inherited* from `[workspace.package]` (`license`, `edition`, `rust-version`, `publish`) and checked on the values `cargo metadata` resolves, so the licence is stated once in the workspace and every member carries it.
- *SPDX scan scope:* the first 10 lines of every `*.rs`, `*.toml`, `*.py`, `*.yml`, `*.yaml` and `*.sh` file that `git ls-files --cached --others --exclude-standard` lists (so a new file is caught before its commit), case-insensitively; prose in Markdown is not a header. Without git, the script walks the tree, skipping `target/` and `.git/`. The script builds the marker from two halves so it does not match itself; `__pycache__/` is in `.gitignore` because compiled files fold the halves back.
- *Unsafe code (D140):* `[workspace.lints.rust]` forbids `unsafe_code` and denies `missing_docs`, so a crate root without `//!` documentation fails to build. The crates listed under `[unsafe_code] allowed` in `ci/crate_graph.toml` do not inherit the workspace lints: each repeats every key of `[workspace.lints]`, every table, at its workspace level, except that `unsafe_code` is `deny` (every block needs its own `#[allow(unsafe_code)]`) and clippy's `undocumented_unsafe_blocks` is `deny` (every block needs a `// SAFETY:` comment). The check fails when one of them inherits the workspace lints instead, or misses or weakens any of these keys (plain and `{ level = ... }` forms are both read), and when any inner attribute in their `src/**/*.rs` allows or expects `unsafe_code` (`#![allow(...)]`, `#![expect(...)]`, inside `cfg_attr` too), comments ignored. Every other crate must inherit the workspace lints; one that sets its own, `deny` or `allow` included, fails with a message naming the relaxation. Crates matching `vilicus-mod-*` or `vilicus-plugin-*` must carry `#![forbid(...)]` with `unsafe_code` in its lint list in every crate root, comments ignored; `vilicus-plugin-sdk` matches the pattern and carries it. A `.cargo/config` or `.cargo/config.toml` at the repository root or under `crates/` or `testing/` fails the check, since its `rustflags` could cap lints (`--cap-lints allow`); spikes keep their own.
- *Spikes* stay outside: `exclude = ["spikes"]`, and each spike already declares its own `[workspace]`.
- *CI:* ubuntu-24.04, `permissions: contents: read`, `actions/checkout` pinned by commit SHA (v7.0.1) with `persist-credentials: false`, toolchain installed by `rustup toolchain install`, which reads `rust-toolchain.toml`; no third-party action. In-progress runs are cancelled for pull requests only, so every push to `main` completes. The lint job exists now because clippy is what enforces the `// SAFETY:` comment of AC5; Story 2.2 makes the gates required.
- *Python rule deviation:* `.claude/rules/python.md` asks for `pyproject.toml`, `ruff` and `pytest`. This story allows no new dependency, so the script is standard library only and tested with `unittest`; it prints its findings because it is a CLI check whose output is the report.

**Files**
- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`
- `crates/<crate>/Cargo.toml` and `crates/<crate>/src/lib.rs` (`src/main.rs` for `vilicus`), one per crate of AC1
- `ci/check_workspace.py`, `ci/crate_graph.toml`, `ci/test_check_workspace.py`
- `.github/workflows/ci.yml`
- `.gitignore` (`__pycache__/`)

**Open points**
- *Unsafe code outside `vilicus-crypto`*, raised while building: the SQLite calls of D126 and D136 in `vilicus-storage`, the pidfd peer identity of D125 in `vilicus-core` and the socket-activated listener in `vilicus-gateway` need `unsafe` that no approved dependency wraps. Settled by D140, applied above.
- *Not checked by any tool:* D140's "kept in one module of FFI wrappers that expose safe functions" is left to review; the source scan reads attributes textually, so an attribute assembled by a macro would escape it (the compiler's `deny` still requires a local allow per block).
- *Toolchain point release.* The Docker image ships rustc 1.99.1 (2026-10-13); the owner keeps 1.99.0 as the spine pins it, so rustup installs 1.99.0 on every run.
- *`.claude/rules/vilicus-rust.md`* asks for the commands once the workspace lands. It should point at `.github/workflows/ci.yml` (jobs `workspace-policy`, `lint` and `build-and-test`) and `ci/check_workspace.py`, not list them; that edit was left to the owner.

## Result

All commands ran on 2026-10-18 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows), on a throwaway copy of the repository made inside the container, with `rust-toolchain.toml` active: `rustc 1.99.0 (b940084d7 2026-09-28)`, `rustfmt 1.10.0-stable`, `clippy 0.1.99`. Each mutation ran on a fresh copy, never on the working tree. The GitHub Actions workflow has not run yet; it passes `actionlint` 1.7.7 with no finding.

| Criterion | Result | Command and observed outcome |
|---|---|---|
| AC1 (AD-3, D1) | **Pass** | `cargo build --workspace --locked`, `cargo test --workspace --locked`, `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`: exit 0 each. `rustup show active-toolchain`: `1.99.0-x86_64-unknown-linux-gnu (overridden by '/src/rust-toolchain.toml')`. Mutation, `crates/vilicus-audit` deleted: `graph: required node aud (vilicus-audit) has no workspace crate`, exit 1. Mutation, the `//!` lines of `vilicus-proto` (inherits the workspace lints) or of `vilicus-storage` (repeats them) removed: `cargo build` fails with `error: missing documentation for the crate`, exit 101 each. |
| AC2 (D29) | **Pass** | `python3 ci/check_workspace.py`: `workspace checks passed: 12 crates`, exit 0. Mutation, a TOML file whose first line carries the marker in lower case: `crates/vilicus-types/header.toml carries an SPDX header`, exit 1; the same marker in a Markdown file is not reported. Mutation, `.git` removed and `git` off the `PATH`: the script walks the tree and passes, exit 0. Earlier mutations (first round): workspace licence `MIT`, one `declares license 'MIT', expected 'Apache-2.0'` line per crate; `rust-version` 1.98.0, one `rust-version` line per crate; exit 1. Unit tests: `ManifestTest` (each field out of policy; a manifest under `crates/` or `testing/` that is not a member; the marker in the header of each scanned suffix, in each case; the marker below the header or in prose passes; the listing without git). |
| AC3 (AD-3, AD-33) | **Pass** | Mutation, `vilicus-storage.workspace = true` added to `crates/vilicus-gateway/Cargo.toml` and the lockfile updated: `graph: forbidden edge vilicus-gateway -> vilicus-storage (normal dependency; storage is private to core)`, exit 1. Mutation, `spikes/shim` (not a member, depending on `vilicus-storage`) as a dev-dependency of `vilicus-gateway`: `source: vilicus-gateway -> shim (dev dependency) is a path dependency on /work/spikes/shim, which is not a workspace member`, exit 1. Mutation, `crypto-copy = { git = "file:///repo", package = "vilicus-crypto" }` in `vilicus-gateway`: `is a git dependency (git+file:///repo)` and `vilicus-gateway resolves vilicus-crypto to git+file:///repo#vilicus-crypto@0.0.0, not a workspace member`, exit 1. Mutation, `testing/stray/Cargo.toml` outside the members: `is not a workspace member, so no check covers it`, exit 1. Unit tests: `GraphTest`, `HandWrittenEdgeTest`, `SourceTest`, `SpineAgreementTest`, and `EndToEndTest`, which builds a temporary workspace with a shim outside it and a local git repository and runs the source check on real `cargo metadata` output: passes. |
| AC4 (AD-3) | **Pass** | First round: `testing/vilicus-mod-reference` as a normal dependency of `vilicus` gives `forbidden edge vilicus -> vilicus-mod-reference` and `dev-only crate vilicus-mod-reference is linked into shipped crate vilicus`; `vilicus` on `vilicus-crypto` gives `crypto is private to core`; exit 1 each. Mutation, `vilicus-mod-reference` as a dev-dependency of both `vilicus` and `vilicus-gateway`: one line, `graph: forbidden edge vilicus-gateway -> vilicus-mod-reference (dev dependency; testing links core, which gw does not reach)`, exit 1; the edge from `vilicus` passes. Unit tests: `PrivateAndShippedTest` and `HandWrittenEdgeTest` (dev-dependency on a test crate allowed from `vilicus-core`, `vilicus` and `vilicus-testbed` only). |
| AC5 (AD-3, D140) | **Pass** | Mutation, an `unsafe` block in `vilicus-proto`: `error: usage of an unsafe block`, exit 101. Mutation, an `unsafe` block without `// SAFETY:` in `vilicus-gateway`: `cargo clippy` fails with `unsafe block missing a safety comment`, exit 101; the documented block passes, exit 0. Mutation, `#![allow(unsafe_code)]` in `vilicus-storage/src/lib.rs` and `#![expect(unsafe_code)]` in `vilicus-core/src/ffi.rs`: one `allows unsafe code for a whole module` line each, exit 1. Mutation, `.cargo/config.toml` at the root and `.cargo/config` in `crates/vilicus-proto` with `--cap-lints allow`: one `could override the workspace lint levels` line each, exit 1. Mutation, `[workspace.lints.clippy] dbg_macro = "deny"` added: one line per D140 crate, `[lints.clippy] dbg_macro is None, expected 'deny'`, exit 1. Mutation, `#![forbid(unsafe_code, missing_docs)]` in `vilicus-plugin-sdk`: passes, exit 0. First round, still valid: `#![allow(unsafe_code)]` outside the list fails with E0453; a crate outside the list that stops inheriting or relaxes to `deny` fails; a D140 crate without the clippy lint fails; a commented block without its local allow fails `cargo build`. Unit tests: `UnsafeTest` and `DecisionAgreementTest`. No `vilicus-mod-*` crate exists yet, so the module half of the attribute check is covered by fixtures only. |
| Check tests | **Pass** | `python3 -m unittest discover -s ci -v`: `Ran 44 tests`, `OK`, `EndToEndTest` run, not skipped. On `python:3.10-slim`: `ci/check_workspace.py needs Python 3.11 or later (tomllib); this is 3.10.22`, exit 1. |
| Spikes standalone | **Pass** (first round) | `cargo locate-project --workspace` inside each directory under `spikes/` names that spike's own `Cargo.toml`. `cargo build --locked` in `spikes/canonical-cbor`, inside the repository tree (so with the root `rust-toolchain.toml` active, rustc 1.99.0): exit 0. The spikes' `run.sh` scripts mount only their own directory, so the root toolchain file does not reach them there. |
