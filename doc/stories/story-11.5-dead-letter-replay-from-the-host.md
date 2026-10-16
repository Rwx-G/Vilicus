---
title: 'Dead-letter replay from the host'
epic: 11
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-24, FR-3, AD-29]
---

# Story 11.5: Dead-letter replay from the host

As an operator,
I want to replay one dead-lettered event with `vilicus events replay`,
So that an event that failed delivery can be delivered once the fault is fixed.

**Acceptance Criteria:**

**AC1 (FR-24, AD-29)**
**Given** a reference-module event moved to `_dead_letter` after 5 failed deliveries, and a consumer that now succeeds
**When** root runs `vilicus events replay <dead-letter id>`
**Then** the event is delivered once to that consumer and its effect is recorded in `_consumed`
**And** the dead-letter row is marked replayed

**AC2 (AD-29)**
**Given** later events of the same source file were delivered while the event was dead-lettered
**When** the replay runs
**Then** the consumer accepts the out-of-order event without error and produces one effect

**AC3 (FR-24)**
**Given** an unknown or already replayed dead-letter id, or a partition that is locked
**When** root runs the command
**Then** it reports the reason and changes nothing; a locked partition's event stays queued until unlock

**AC4 (FR-3)**
**Given** any replay attempt
**When** the command finishes
**Then** an audit entry records the dead-letter id and the outcome, without the event payload

**Dependencies:**
- Story 11.1 (status lists dead letters)
- Story 3.8 (events, outbox and dead letters)

**References:**
- `doc/prd.md` FR-24, FR-3
- `doc/architecture-spine.md` AD-26, AD-29
