---
title: 'Structured field validation and reviewed vocabularies'
epic: 3
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-58, DC-53, DC-59, D98, D104, I40]
---

# Story 3.4: Structured field validation and reviewed vocabularies

As a project maintainer,
I want the storage layer to validate every structured field against its declaration on every write,
So that a value outside its declared type is refused, never truncated or coerced, and structured data stays safe to treat as untainting.

**Acceptance Criteria:**

**AC1 (FR-58, DC-53, D98, I40)**
**Given** a write with a structured field whose value is outside its declared closed type (an unknown enumeration value, a number out of bounds, an invalid date, a malformed UUIDv7)
**When** the storage layer validates it
**Then** the whole write is refused with a typed error and nothing is stored.

**AC2 (FR-58, I40)**
**Given** a field value longer than its declared maximum length, structured or free text
**When** the write is validated
**Then** it is refused, never truncated.

**AC3 (DC-59, D104, I40)**
**Given** a reviewed-vocabulary field
**When** a write carries a label that is not among the confirmed labels of that vocabulary, or a label longer than 32 characters or outside the restricted alphabet
**Then** the write is refused
**And** a confirmed label of at most 32 characters from the restricted alphabet is accepted.

**AC4 (DC-53, I40)**
**Given** every module write path registered in the testbed
**When** the fuzz test drives each path with values outside their declarations
**Then** every such value is refused and the file is unchanged afterwards.

**AC5 (FR-58)**
**Given** the FR-50 action table, which lists no action to confirm a vocabulary label
**When** V0.1 is built
**Then** no surface confirms vocabulary labels, and tests seed confirmed labels through the `vilicus-testbed` binary only.

**Dependencies:**
- Story 3.2 (field declarations in the registry)

**References:**
- `doc/prd.md` FR-58, FR-50
- `doc/architecture-spine.md` AD-6
- `doc/ai-safety.md` I40
- `doc/decisions.md` D98, D104
