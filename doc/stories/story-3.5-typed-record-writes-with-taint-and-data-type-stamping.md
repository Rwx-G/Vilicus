---
title: 'Typed record writes with taint and data type stamping'
epic: 3
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-18, FR-20, AD-6, AD-7, D70, D99, D104, D103, I9, I21, I35, I43]
---

# Story 3.5: Typed record writes with taint and data type stamping

As a project maintainer,
I want modules to write only through a typed record API on which the Core stamps the envelope, taint and data types,
So that no module can choose its own provenance label and derived data never launders into `trusted`.

**Acceptance Criteria:**

**AC1 (FR-18, AD-6)**
**Given** the typed record API of `vilicus-module-api`
**When** a module inserts, updates by id with an expected `rev`, or deletes by id
**Then** the Core stamps `id`, `source`, `author`, `created_at`, `updated_at` and bumps `rev` in the write transaction
**And** an update whose expected `rev` differs from the stored one is refused.

**AC2 (AD-7, I9)**
**Given** a write by a non-member principal deriving a record
**When** it does not declare its input record ids
**Then** it is refused
**And** when it declares them, the stored taint is the maximum of the inputs' taints, any `member` or `external` input storing `external`.

**AC3 (D103, I43)**
**Given** a derived record
**When** it is written
**Then** its stored `data_types` is the union of its inputs' sets, computed by the Core
**And** a write declaring a smaller set is refused (storage property test over random input sets).

**AC4 (FR-20, D70, D99, I35)**
**Given** a write a member makes or explicitly approves
**When** it is stored
**Then** its structured fields are stored `trusted` with that member as `author` and provenance to its inputs
**And** free text drafted in a tainted session stays `external` even when edited, while text the member wrote in full in an empty field is stored `trusted`.

**AC5 (D104, I35)**
**Given** a member-written field that contains 8 or more consecutive words of the assistant's draft
**When** it is stored
**Then** it is stored `external`, by a verbatim word-sequence test and not an edit ratio.

**AC6 (AD-6, AD-7, I21)**
**Given** any write
**When** it is stored
**Then** stored taint is never `member`
**And** a write whose principal is `Plugin` is stored `external` whatever taint the plugin claims.

**Dependencies:**
- Story 3.4 (field validation runs in the same write transaction)

**References:**
- `doc/prd.md` FR-18, FR-20
- `doc/architecture-spine.md` AD-6, AD-7
- `doc/ai-safety.md` P5, I9, I21, I35, I43
- `doc/decisions.md` D70, D99, D103, D104
