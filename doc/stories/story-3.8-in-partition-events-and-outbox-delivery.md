---
title: 'In-partition events and outbox delivery'
epic: 3
story: 8
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-24, AD-10, AD-27, AD-29, D20, D107, DC-62]
---

# Story 3.8: In-partition events and outbox delivery

As a project maintainer,
I want modules to exchange typed, versioned events through the Core with stamped emitters and outbox delivery,
So that cross-module consistency never needs a cross-file transaction and a failing consumer never blocks a partition.

**Acceptance Criteria:**

**AC1 (FR-24, AD-29)**
**Given** a module declaring a topic `<module>.<entity>.<past_verb>`
**When** it emits an event
**Then** the Core stamps the real emitter and a payload version, a claim of another emitter is rejected, and per-topic ACLs decide which consumers receive it
**And** consumers accept every earlier payload version.

**AC2 (AD-10, D20)**
**Given** a change and its outbox row
**When** the module commits
**Then** both are in one transaction in one file
**And** after a simulated crash the undelivered rows are delivered once the partition unlocks.

**AC3 (FR-24, AD-29)**
**Given** events in a source file's outbox
**When** the Core delivers them
**Then** delivery happens only after the file's migrations, at least once, in commit order per source file and consumer
**And** a consumer processing the same event twice produces one effect through `_consumed`.

**AC4 (FR-24, AD-29)**
**Given** a consumer that fails the same event 5 times
**When** the fifth delivery fails
**Then** the event moves to `_dead_letter`, a typed instance admin alert is returned and later events proceed
**And** the consumer tolerates the gap in order.

**AC5 (AD-10)**
**Given** an outbox row requesting a cross-module link
**When** the Core delivers it
**Then** the Core registers the link in the link table of the partition that owns the data, never in the module's transaction, and no link crosses partitions.

**AC6 (AD-27, D107, DC-62)**
**Given** a consumer that writes in reaction to an event
**When** it writes
**Then** the write carries principal `Event`, the emitting call's id, its author and the most restrictive taint of its inputs, and is at most tier 1
**And** in V0.1 no event is delivered outside its source partition (test with two partitions).

**Dependencies:**
- Story 3.6 (outbox and `_consumed` tables)

**References:**
- `doc/prd.md` FR-24
- `doc/architecture-spine.md` AD-10, AD-27, AD-29
- `doc/decisions.md` D20, D107
