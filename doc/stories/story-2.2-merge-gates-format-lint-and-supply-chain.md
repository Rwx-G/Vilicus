---
title: 'Merge gates: format, lint and supply chain'
epic: 2
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-33, D28, D29, NFR-6]
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

**Dependencies:**
- Story 2.1 (workspace and CI workflow exist)

**References:**
- `doc/architecture-spine.md` AD-33, Consistency Conventions (Dependencies)
- `doc/decisions.md` D28, D29
- `doc/prd.md` section 7 (Supply chain)
