---
title: 'Ordered pipeline enforcement'
epic: 10
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-26, FR-25, AD-8, AD-27, AD-28, I18]
---

# Story 10.3: Ordered pipeline enforcement

As a member,
I want every tool call from a plugin or an AI process to pass the same ordered checks in the Core,
So that a wrong or hostile call is stopped before it touches my data.

**Acceptance Criteria:**

**AC1 (FR-26, AD-8)**
**Given** a tool call from a token principal
**When** the Core processes it
**Then** it validates schema, capability token, deterministic rules and taint, in that order, and stops at the first failure
**And** every data write from any principal goes through this pipeline, never through a side door

**AC2 (FR-26)**
**Given** a call carrying an unknown field or a value of the wrong type
**When** it reaches schema validation
**Then** it is rejected, never repaired, and the rejection is audited

**AC3 (FR-26, FR-25)**
**Given** the plugin double and the AI double, each holding a token
**When** each calls one tool allowed by its manifest and token, then a tool outside it
**Then** the allowed call succeeds and the other is refused
**And** a call outside the token's module, partition, action set or budget is rejected and audited

**AC4 (AD-28)**
**Given** a write call carrying a `call_id`
**When** the same principal sends the same `call_id` again
**Then** the Core returns the first outcome and the write is applied once

**AC5 (AD-27)**
**Given** a consumer that writes in reaction to an in-partition event
**When** the write runs
**Then** it enters the pipeline as principal `Event`, carrying the emitting call's id, its author and the most restrictive taint of its inputs, and reaches at most tier 1

**AC6 (I18)**
**Given** the registry and the pipeline
**When** the static check runs
**Then** no H action is reachable as a tool through the pipeline

**Dependencies:**
- Story 10.2 (capability tokens)
- Story 3.8 (events and outbox)

**References:**
- `doc/prd.md` FR-25, FR-26
- `doc/architecture-spine.md` AD-8, AD-27, AD-28
- `doc/architecture.md` section 9.2
- `doc/ai-safety.md` P8, I18
