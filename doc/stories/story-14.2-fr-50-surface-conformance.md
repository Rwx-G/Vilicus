---
title: 'FR-50 surface conformance'
epic: 14
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-50, D101, UX-DR1, AD-8]
---

# Story 14.2: FR-50 surface conformance

As the project maintainer,
I want a table-driven test that every V0.1 action is reachable on exactly its FR-50 surface,
So that no action leaks onto a surface where a compromised Gateway or the wrong actor could reach it.

**Acceptance Criteria:**

**AC1 (FR-50, UX-DR1)**
**Given** the FR-50 table encoded as test data (action, actor, surface, confirmation)
**When** the conformance test runs
**Then** each action succeeds on its listed surface, by its listed actor, with its listed confirmation
**And** it is refused on every other surface, by every other actor, and without the confirmation

**AC2 (D101, AD-8)**
**Given** the host-only actions (changing exposure, redeeming the admin recovery code, `vilicus member enroll-first`)
**When** the Gateway route table is inspected and every route is probed
**Then** no web route performs them, no web route starts a recovery, and no web route accepts the admin recovery code

**AC3 (FR-50)**
**Given** the Gateway route table and the CLI command list
**When** the test compares them with the FR-50 table
**Then** a route or command that performs an action not listed in the table fails the test

**AC4 (FR-50)**
**Given** the rows proposed by the decision tasks of this backlog (undo, single-adult cancel, recovery cancel, clock-jump acknowledgement)
**When** the owner has accepted a proposed row
**Then** that row is added to the test data in the same change that adds it to `doc/prd.md`
**And** a proposed row the owner has not accepted is absent from the test data and its action is unreachable

**Dependencies:**
- Story 14.1 (release-gate job that runs this test)

**References:**
- `doc/prd.md` FR-50
- `doc/architecture-spine.md` AD-8
- `doc/decisions.md` D101
- `doc/capability-matrix.md` section 1
