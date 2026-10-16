---
title: 'Core metadata, durable deadlines and alert queue'
epic: 5
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-30, AD-32, AD-22, D113]
---

# Story 5.2: Core metadata, durable deadlines and alert queue

As an adult,
I want security delays that survive reboots and clock tricks, and alerts that the Core keeps until they are delivered,
So that a veto window or a recovery wait cannot be shortened by restarting the host or moving its clock.

**Acceptance Criteria:**

**AC1 (AD-22, D113)**
**Given** the instance key delivered as the Core unit's systemd credential
**When** the Core starts
**Then** it opens `core.db` under a key derived from the instance key
**And** the household time zone and the Core's runtime policy are stored there

**AC2 (AD-30)**
**Given** a delay longer than a web session (veto, recovery wait, request expiry, unlock window)
**When** the Core creates it
**Then** it is stored in `core.db` as a UTC wall-clock deadline together with the uptime accumulated toward it, and re-armed at every start
**And** a security delay completes only when both the wall clock and the accumulated uptime agree it has elapsed (test: restart the Core mid-delay, then advance only the wall clock)

**AC3 (AD-30)**
**Given** short expiries (tokens, nonces, pairing codes)
**When** they are checked
**Then** they use the monotonic clock, not the wall clock

**AC4 (AD-30)**
**Given** a running Core
**When** the wall clock jumps against the monotonic clock beyond the detection threshold, or wall clock and uptime disagree widely on a security delay
**Then** completion of every pending delay is suspended and stays suspended until a human acknowledges
**And** the suspension is recorded and raises an alert in the queue of AC5

**AC5 (AD-32)**
**Given** a Core component that needs to alert the instance admin or adults
**When** it raises an alert (kind, audience, Core-resolved parameters)
**Then** the alert is persisted in a Core alert queue in `core.db`, survives a restart, and keeps its delivery state per recipient
**And** alert kinds and audiences are closed types, so no free text from a module or a model can enter an alert

**Dependencies:**
- Story 5.1 (Core process)
- Story 4.3 (instance-key-derived keys)

**References:**
- `doc/architecture-spine.md` AD-22, AD-30, AD-32
- `doc/architecture.md` sections 5.2 and 17 (host clock wrong or jumps)
- `doc/decisions.md` D113
