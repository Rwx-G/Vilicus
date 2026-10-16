---
title: 'vilicus-testbed binary and testing tree'
epic: 2
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-109, AD-3, D102]
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

**AC2 (FR-109, AD-3)**
**Given** the workspace
**When** CI builds it
**Then** it produces both `vilicus` and `vilicus-testbed` from the same crates, `vilicus-testbed` additionally linking the reference module and the doubles.

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
- `doc/decisions.md` D102
