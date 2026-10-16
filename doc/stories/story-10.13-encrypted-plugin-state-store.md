---
title: 'Encrypted plugin state store'
epic: 10
story: 13
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-25, D95, D111, D102, AD-25]
---

# Story 10.13: Encrypted plugin state store

As a member,
I want each plugin's persistent state encrypted under a key owned by the household or by the member who owns the plugin,
So that a plugin's tokens and settings are protected at rest and a member-owned plugin cannot act while its owner is locked.

**Acceptance Criteria:**

**AC1 (FR-25, D95, AD-25)**
**Given** a household-owned plugin double
**When** it stores state
**Then** the state lives in an encrypted store in its own state directory, keyed from the instance key

**AC2 (FR-25, D95)**
**Given** a member-owned plugin double
**When** it stores state
**Then** the store is keyed from the owning member's partition key, and no delegation sub-key or other key opens it

**AC3 (D111)**
**Given** a member-owned plugin double
**When** its owner is locked, or their unlock window ends
**Then** the Core does not start it, or stops it, and it reads no state until the owner unlocks again

**AC4 (FR-25, D102)**
**Given** the V0.1 CLI and web client
**When** their command and route lists are checked
**Then** no plugin install command or route exists; first-party plugins ship inside the signed package

**Dependencies:**
- Story 10.3 (pipeline and plugin double)
- Story 9.3 (unlock window)

**References:**
- `doc/prd.md` FR-25
- `doc/architecture-spine.md` AD-25
- `doc/decisions.md` D95, D102, D111
