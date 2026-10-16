---
title: 'Caps, detectors and daily digest'
epic: 10
story: 8
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-30, I11, D86, D113, FR-31]
---

# Story 10.8: Caps, detectors and daily digest

As a member,
I want caps that suspend a runaway task and a daily digest of every assistant write,
So that a wrong or injected task is bounded automatically and I can see afterwards what was done in my name.

**Acceptance Criteria:**

**AC1 (FR-30, I11, D113)**
**Given** a task whose token has a budget of 50 tool calls
**When** it attempts the 51st call
**Then** the task is suspended, an alert is raised and an audit entry is written

**AC2 (FR-30, I11)**
**Given** a task whose elevated requests are refused
**When** the third consecutive refusal happens
**Then** the task is suspended, an alert is raised and an audit entry is written

**AC3 (FR-30, D86)**
**Given** a task that keeps hitting pipeline denials
**When** it reaches 5 denials (PRD assumption)
**Then** the repeated-denial detector suspends that task or AI session only
**And** it never triggers the kill switch and never ends an unlock window

**AC4 (FR-30)**
**Given** assistant writes journaled during the last day
**When** the member opens the digest in the member web
**Then** the digest, rendered from `_journal`, lists every assistant write of the day
**And** the count of unread digests is shown to the member

**AC5 (FR-31, FR-30)**
**Given** a full audit spool
**When** an AI task calls a tool
**Then** the AI sessions are suspended until the audit writer returns, and the suspension is audited once it is back

**AC6 (FR-30)**
**Given** a member web session or a CLI command
**When** it makes more than 50 writes in a row
**Then** no cap applies, because caps bind token principals only

**Dependencies:**
- Story 10.7 (undo, journal reads for the digest)

**References:**
- `doc/prd.md` FR-30
- `doc/architecture.md` section 9.5
- `doc/capability-matrix.md` section 11
- `doc/ai-safety.md` P8, I11
- `doc/decisions.md` D86, D113
