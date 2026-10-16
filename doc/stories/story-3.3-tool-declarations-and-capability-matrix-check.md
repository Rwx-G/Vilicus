---
title: 'Tool declarations and capability matrix check'
epic: 3
story: 3
status: draft
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
