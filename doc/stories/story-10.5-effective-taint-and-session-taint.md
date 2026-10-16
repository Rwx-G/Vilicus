---
title: 'Effective taint and session taint'
epic: 10
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-20, FR-58, AD-7, D70, D37, D104, I21, I35]
---

# Story 10.5: Effective taint and session taint

As a member,
I want the Core to compute taint for each viewer and each AI session,
So that content from outside the household, or free text written by the other adult, cannot silently drive my assistant.

**Acceptance Criteria:**

**AC1 (FR-20, AD-7)**
**Given** records stored `trusted` or `external`, some authored by member A
**When** member B's session reads them
**Then** the Core computes effective taint per viewer at read time with the order `trusted` < `member` < `external`, A's `trusted` records reading as `member` for B
**And** `member` is never written to storage

**AC2 (FR-20, D70, I35)**
**Given** an AI session
**When** it consumes an `external` datum or a `member` free-text field
**Then** the session becomes tainted
**And** a session that reads only structured fields of `member` taint stays untainted

**AC3 (FR-58, D37)**
**Given** a field of `member` taint, structured or free text
**When** it reaches the planner role
**Then** it arrives as quoted data within its declared maximum length, with its taint

**AC4 (FR-58, D104)**
**Given** a free-text field of `external` taint
**When** a planner tool result would include it
**Then** it is withheld, since in V0.1 no reader output exists
**And** a member-approved assistant draft stored `external` reaches the planner as quoted data within its maximum length and taints the session

**AC5 (I21)**
**Given** a tainted session of each principal kind
**When** it calls a tier 1 tool
**Then** taint effects (elevation of tier 1, denial of H) apply to `AiTask` and `Plugin` principals only, and `Member`, `Cli` and `Event` calls are never gated by taint
**And** a write arriving from the plugin double is stored `external` whatever the plugin claims

**Dependencies:**
- Story 10.4 (partition isolation)
- Story 3.5 (stored taint on write)

**References:**
- `doc/prd.md` FR-20, FR-58
- `doc/architecture-spine.md` AD-6, AD-7
- `doc/architecture.md` sections 5.4, 9.3
- `doc/ai-safety.md` P2, P5, I21, I35
- `doc/decisions.md` D37, D70, D104
