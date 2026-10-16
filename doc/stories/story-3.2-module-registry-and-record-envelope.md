---
title: 'Module registry and record envelope'
epic: 3
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-18, FR-22, FR-58, FR-68, AD-6, AD-9, I8, I36, D98, D103, D104, I6, AD-5]
---

# Story 3.2: Module registry and record envelope

As a project maintainer,
I want modules registered at build time through `vilicus-module-api`, with the registry refusing any table or field that lacks its envelope and declarations,
So that every record the Core stores carries provenance, typed fields and its data types.

**Acceptance Criteria:**

**AC1 (FR-22, AD-9)**
**Given** a module crate implementing `vilicus-module-api`
**When** the binary is built
**Then** the registry lists its schema, migrations and record types at build time, with no runtime registration path.

**AC2 (FR-18, AD-6, I8)**
**Given** a module table
**When** the registry loads it
**Then** it is refused unless it carries `id`, `source`, `taint`, `data_types`, `author`, `created_at`, `updated_at` and `rev`
**And** a registry test with a table missing `source` or `taint` fails registration.

**AC3 (FR-58, D98, D104)**
**Given** a field of a module table
**When** the registry loads it
**Then** it is refused unless declared structured or free text with a maximum length
**And** a structured field is refused unless its value set is fixed at build time (compiled enumeration, bounded number, date, opaque UUIDv7) or it is declared a reviewed vocabulary.

**AC4 (FR-68, I36, D103)**
**Given** a record kind
**When** the registry loads it
**Then** it is refused unless it declares the data types its fields may hold, each from the closed set of `vilicus-types`
**And** a record kind declaring a type outside the set fails registration.

**AC5 (AD-9)**
**Given** the Rust table declaration and the schema the module's migrations produce
**When** the build-time test runs, and again when the Core opens a file
**Then** the declaration is compared with `PRAGMA table_xinfo` of the migrated schema
**And** any difference fails the test or refuses the file with a typed error.

**AC6 (I6, AD-5)**
**Given** two module crates
**When** the crate graph check runs
**Then** a module crate that depends on another module's storage or table types fails the build

**Dependencies:**
- Story 3.1 (storage layer)
- Story 2.4 (data type set, envelope types)

**References:**
- `doc/prd.md` FR-18, FR-22, FR-58, FR-68
- `doc/architecture-spine.md` AD-6, AD-9
- `doc/ai-safety.md` I8, I36
- `doc/decisions.md` D98, D103, D104
