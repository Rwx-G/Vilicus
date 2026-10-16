---
title: 'Partition isolation'
epic: 10
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-19, I5, AD-5]
---

# Story 10.4: Partition isolation

As an adult,
I want my web session and every AI session acting for me to read only my personal partition and the household partition,
So that the other adult's personal partition stays out of my reach and out of my assistant's reach.

**Acceptance Criteria:**

**AC1 (FR-19, I5)**
**Given** two members A and B, both unlocked
**When** a capability token issued for member A is used to read any record of member B's personal partition, through any registered tool
**Then** every such read fails and is audited

**AC2 (FR-19, I5)**
**Given** a marker value planted in a record of member B's personal partition
**When** the test calls every registered tool with tokens of member A
**Then** no tool result contains the marker

**AC3 (FR-19)**
**Given** member A's web session
**When** it requests data of member B's personal partition through any client API route
**Then** the Core refuses the request
**And** member A still reads their own personal partition and the household partition

**AC4 (AD-5)**
**Given** the module handles the Core opens for a call
**When** a token for member A is processed
**Then** the handles are bound to one module and to partitions in member A's scope only, and no handle to a file of member B's partition is opened

**Dependencies:**
- Story 10.3 (pipeline)
- Story 9.5 (a second adult)

**References:**
- `doc/prd.md` FR-19
- `doc/architecture-spine.md` AD-5
- `doc/architecture.md` section 9.4
- `doc/ai-safety.md` P3, I5
