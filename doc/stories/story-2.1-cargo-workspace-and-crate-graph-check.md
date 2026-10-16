---
title: 'Cargo workspace and crate graph check'
epic: 2
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-3, AD-33, D1, D29]
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

**AC5 (AD-3)**
**Given** a module or adapter crate (`vilicus-mod-*`, `vilicus-plugin-*`)
**When** it is compiled
**Then** it carries `#![forbid(unsafe_code)]`
**And** a CI lint fails on any `unsafe` block outside `vilicus-crypto`.

**Dependencies:**
- None.

**References:**
- `doc/architecture-spine.md` AD-3, AD-33, Structural Seed, Stack
- `doc/decisions.md` D1, D29
