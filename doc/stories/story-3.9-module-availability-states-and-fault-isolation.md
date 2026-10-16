---
title: 'Module availability states and fault isolation'
epic: 3
story: 9
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-54, AD-9, FR-11, FR-23]
---

# Story 3.9: Module availability states and fault isolation

As a project maintainer,
I want the Core to track one availability state per module file and to contain every module fault,
So that callers and the event bus never guess whether a file can serve, and a panicking module never takes the Core down.

**Acceptance Criteria:**

**AC1 (AD-54)**
**Given** a module file
**When** any caller asks for it
**Then** the Core reports one of `locked`, `opening`, `re-keying`, `migrating`, `ready`, `failed migration`, `faulted`, `deactivated`, `newer than code`
**And** every non-ready state answers typed API calls with `module_unavailable` and the retry class of the AD-54 table (`retryable` for the first four, `not_retryable` for the rest).

**AC2 (AD-54, FR-23)**
**Given** a consumer whose file is not ready
**When** an event is due to it
**Then** the event stays in the source outbox and does not count as a failed delivery.

**AC3 (AD-54, FR-11)**
**Given** a partition becoming available
**When** its keys are derived
**Then** the Core reports it usable at once and moves each file through re-key, migration and outbox delivery in the background, in that order.

**AC4 (AD-9)**
**Given** a handler, undo handler or event consumer
**When** it panics on the file's writer thread
**Then** the Core catches it with `catch_unwind`, rolls back the transaction, marks the module `faulted` for that partition and returns a typed instance admin alert
**And** release builds use `panic = "unwind"`, and the panic never unwinds into the Core.

**AC5 (AD-9)**
**Given** a handler call that exceeds its time budget
**When** the budget expires
**Then** the module is marked `faulted` for that partition and receives no further calls there.

**AC6 (AD-9)**
**Given** a module faulted in one partition
**When** other modules and partitions are called
**Then** they keep serving normally (test with a deliberately panicking handler).

**Dependencies:**
- Story 3.8 (event delivery the states gate)

**References:**
- `doc/architecture-spine.md` AD-9, AD-54
- `doc/architecture.md` section 17
- `doc/prd.md` FR-11, FR-23
