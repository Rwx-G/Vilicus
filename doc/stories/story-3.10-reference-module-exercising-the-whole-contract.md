---
title: 'Reference module exercising the whole contract'
epic: 3
story: 10
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-22, FR-109, D102, I8, I36, I6, AD-5]
---

# Story 3.10: Reference module exercising the whole contract

As a project maintainer,
I want a reference module that uses every part of the module contract and is linked only into `vilicus-testbed`,
So that the platform is proven end to end in V0.1 without shipping a user-facing module.

**Acceptance Criteria:**

**AC1 (FR-22, I8, I36)**
**Given** `vilicus-mod-reference`
**When** it is registered
**Then** it declares tables with the full envelope, structured and free-text fields with maximum lengths, a reviewed vocabulary, and record kinds with data types including a local-only type (`health` or `journal`)
**And** it passes registration under the checks of Stories 3.2 to 3.4.

**AC2 (FR-22)**
**Given** the reference module's tools
**When** the capability matrix check runs in the testbed
**Then** a tier 0 tool and a tier 1 tool are each backed by a row of a testbed-only matrix fixture under `testing/`, `doc/capability-matrix.md` gets no reference-module row, and one record kind is declared exempt from elevation.

**AC3 (FR-22)**
**Given** the reference module's test suite
**When** it runs
**Then** it exercises a typed write with journal, an event and its consumer, an outbox effect intent, an undo handler and two migrations applied in sequence, each asserted.

**AC4 (FR-109, D102)**
**Given** the build outputs
**When** the crate graph and packaging checks run
**Then** the reference module is linked into `vilicus-testbed` only and never into `vilicus` or any package.

**AC5 (I6, AD-5)**
**Given** a second test module in the testbed that reads reference-module data
**When** it reads that data
**Then** the call goes through the reference module's typed API registered with the Core, which checks the caller's partition scope
**And** any attempt to obtain a handle on the reference module's file is refused

**Dependencies:**
- Story 3.9 (complete module platform)
- Story 2.6 (testbed binary)

**References:**
- `doc/prd.md` FR-22, FR-109
- `doc/architecture-spine.md` AD-3, AD-9
- `doc/ai-safety.md` I8, I36
- `doc/decisions.md` D102
