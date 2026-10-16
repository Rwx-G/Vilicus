---
title: 'Shared vocabulary in vilicus-types'
epic: 2
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-68, AD-6, AD-8, AD-48, D103, D113, FR-27, FR-12]
---

# Story 2.4: Shared vocabulary in vilicus-types

As a project maintainer,
I want every closed vocabulary and confirmed V0.1 value defined once in `vilicus-types`,
So that the Core, modules, adapters and clients cannot disagree on identifiers, taint, principals, data types or limits.

**Acceptance Criteria:**

**AC1 (AD-6)**
**Given** the identifier and time conventions of the spine
**When** a record identifier or timestamp is created
**Then** identifiers are UUIDv7, stored as a 16-byte blob and rendered as lowercase hyphenated text at the edges, and times are UTC integer milliseconds in storage and RFC 3339 at the edges
**And** no code parses meaning out of an identifier.

**AC2 (AD-6, AD-8)**
**Given** the `Taint`, tier, `Principal` and `source` types
**When** they are serialized or matched
**Then** stored taint has only the values `trusted` and `external`, with `member` available only as a read-time view type that cannot be stored
**And** `Principal` is the closed enum `Member`, `Cli`, `AiTask`, `Plugin`, `Event`, `Rule`, `Display`, `Adapter`, `Playbook`, and `source` is the closed vocabulary of the spine conventions.

**AC3 (FR-68, D103)**
**Given** the data type set
**When** it is enumerated
**Then** it contains exactly `health`, `journal`, `budget`, `meals`, `meal_plan`, `stock`, `shopping_list`, `presence`, `home_state`, `alarm_state`, `calendar`, `child`, `mail_raw`, `household_other`, `personal_other`
**And** a test fails if a member is added or removed without updating the test, so the set is enumerated in this crate only.

**AC4 (AD-48)**
**Given** the I13 exception classes
**When** they are enumerated
**Then** the closed set is exactly `reversible_external_state`, `restorable_physical`, `own_account_delivery`.

**AC5 (D113, FR-27, FR-12)**
**Given** the confirmed V0.1 values
**When** code needs them
**Then** they are named constants: capability token lifetime 10 minutes, token budget 50 tool calls, unlock window maximum 24 hours and default 12 hours, undo journal retention 30 days
**And** only the backup schedule, the certificate alert lead time and the audit spool size are read from `vilicus.toml`, with every other security delay and cap compiled in.

**AC6 (AD-6)**
**Given** an error crossing a crate boundary
**When** it is returned to a client
**Then** it carries a stable error code, a message key and a retry class from `retryable`, `not_retryable`, `unknown_outcome`.

**Dependencies:**
- Story 2.1 (crate exists)

**References:**
- `doc/architecture-spine.md` AD-6, AD-8, AD-48, Consistency Conventions
- `doc/prd.md` FR-12, FR-27, FR-68, section 12
- `doc/decisions.md` D103, D113
