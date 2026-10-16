---
title: 'French and English catalogs'
epic: 7
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-110, UX-DR6, NFR-8]
---

# Story 7.4: French and English catalogs

As a member,
I want the web client in French or English following my setting,
So that every adult of the household can use the primary channel in their language.

**Acceptance Criteria:**

**AC1 (FR-110, UX-DR6)**
**Given** any user-facing string of the web client
**When** it is rendered
**Then** it comes from a message key with an entry in both the French and the English catalog

**AC2 (FR-110, NFR-8)**
**Given** a member with no language setting
**When** the client loads
**Then** it uses the browser's language when it is French or English, and English otherwise
**And** once the member sets a language, that setting wins on every device

**AC3 (UX-DR6)**
**Given** a message key present in one catalog and missing in the other
**When** CI runs the catalog check
**Then** the merge is blocked

**AC4 (FR-110)**
**Given** the CLI
**When** any command prints output
**Then** it is in English only

**Dependencies:**
- Story 7.3 (web client shell)

**References:**
- `doc/prd.md` FR-110
- `doc/architecture-spine.md` Consistency Conventions (Text and language)
- `doc/decisions.md` D113
