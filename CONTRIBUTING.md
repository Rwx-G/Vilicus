# Contributing to Vilicus

Thank you for considering contributing to Vilicus. The project is in early development: the design is settled enough to build on, and the code follows the V0.1 stories. This document explains how to get started.

## Before You Start

Read the design documents in [`doc/`](doc/README.md), in their reading order, and use the terms of its glossary. A change that touches keys, policy, taint, the assistant or storage must respect the [threat model](doc/threat-model.md), the [AI safety](doc/ai-safety.md) invariants and the [decisions](doc/decisions.md); a change that alters a decision updates `doc/decisions.md` in the same commit. Open an issue first for anything beyond a small fix, so the design question is settled before the code.

## Getting Started

### Prerequisites

- Linux x86_64, or Docker on another platform. The server runs on Linux with systemd only
- Rust 1.99.0. `rust-toolchain.toml` pins it for local builds and CI both, and rustup installs it on first use; do not override it locally
- Python 3, for the checks under `ci/`
- The system OpenSSL development files (`libssl-dev`) and `pkg-config`, which the vendored SQLCipher builds against

On Windows or macOS, run everything inside the image CI uses, `rust:1.99-trixie` (the digest is pinned in `.github/workflows/ci.yml`).

### Building

```bash
git clone https://github.com/Rwx-G/Vilicus.git
cd Vilicus
cargo build --workspace --frozen --config ci/cargo-vendored.toml
```

Dependencies are built from `vendor/` only, offline: `--frozen --config ci/cargo-vendored.toml` is how CI builds and how you should too.

## Development Workflow

1. **Fork** the repository and create a branch: `feat/<name>` or `fix/<name>`
2. **Develop**: code, tests, and the documentation the change affects
3. **Validate**: run the gates CI runs (below)
4. **Submit** a pull request against `main`

### Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `chore`

**Scopes:** `design` and `planning` for the documents; the components `core`, `gateway`, `audit`, `egress`, `plugins`, `ai`, `mcp`; the shared crates `types` and `proto`; the cross-cutting concerns `keys`, `auth`, `pairing`, `policy`, `storage`; one scope per module (`familydocs` for family documentation); the clients `web`, `android`, `desktop`; and `ci`, `deps`, `release` for the repository plumbing.

One logical change per commit. Tests and the documentation that describes a change can ship in the same commit; unrelated cleanups go in their own.

### Code Quality

The gates are the jobs of `.github/workflows/ci.yml`, and their commands live there and nowhere else, so that a copy here cannot fall behind. Print them from the workflow and run each line:

```bash
grep -E '^\s+run: (python3 ci/|cargo )' .github/workflows/ci.yml
```

They cover the crate graph and `unsafe` rules, the supply-chain and vendor checks, the packaging checks that keep test code out of release artefacts, `cargo fmt`, `cargo clippy -D warnings`, the workspace tests, `cargo deny`, `cargo vet` and `cargo audit`.

- New behaviour has tests, and a test must be able to fail: removing or inverting the guard it covers makes it fail, and reviews check this
- Public items have doc comments (`///`)
- No new dependency without prior agreement in an issue: every package added to `Cargo.lock` is vendored, vetted and audited

### Documentation

Design documents are Markdown with Mermaid diagrams; images go in `doc/assets/`. Identifiers (D, T, A, P, I, E, R) are never renumbered or reused; a change to one updates every reference to it in the same commit.

## Architecture

The Cargo workspace follows the crate graph of the [architecture spine](doc/architecture-spine.md) (AD-3), which CI enforces.

| Directory | Purpose |
|-----------|---------|
| `crates/` | Product crates: the `vilicus` binary, the Core, storage, the module port, shared types and protocol, and the process crates |
| `testing/` | Test doubles, the reference module and the testbed; never packaged |
| `fuzz/` | Coverage-guided fuzzing of the wire protocol |
| `ci/` | The checks CI runs, with their own tests |
| `spikes/`, `e2e/` | V0.1 spikes and their replayable harness: evidence, not product code |
| `doc/` | Design documents, PRD, architecture spine, backlog and stories |

## Reporting Issues

Use [GitHub Issues](https://github.com/Rwx-G/Vilicus/issues) for bugs and design questions. Security vulnerabilities go through the private channel in [SECURITY.md](SECURITY.md), never a public issue.

## Code of Conduct

This project follows its [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
