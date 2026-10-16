---
title: 'Audit spool and emergency set'
epic: 6
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-31, AD-17, D59, D113]
---

# Story 6.3: Audit spool and emergency set

As a member,
I want ordinary work and emergency actions to keep running while the audit writer is down, without losing a single entry,
So that an audit outage neither blocks the household nor opens a gap in the chain.

**Acceptance Criteria:**

**AC1 (AD-17, FR-31)**
**Given** the audit writer is unreachable
**When** the Core must append an entry
**Then** it seals the entry with a MAC under a key derived from the instance key into a bounded spool owned by the Core
**And** when the writer returns, the Core replays the spooled entries in order before any new entry (test: stop the writer mid-run, restart it, verify the chain)

**AC2 (FR-31, D113)**
**Given** the spool
**When** its size is configured
**Then** it holds 10 000 entries by default (PRD assumption) and the size is read from `vilicus.toml` as one of the three operator-tunable values

**AC3 (FR-31)**
**Given** the audit writer is down
**When** an H action is requested
**Then** it is refused with a retryable error, because no administrative action runs without an acknowledged audit entry

**AC4 (FR-31, D59)**
**Given** the spool is full
**When** a write is requested
**Then** it is refused with a retryable error until the writer returns, except the emergency set of `doc/architecture.md` section 17 (unlock, lock, device removal, recovery cancel, kill switch), which proceeds and is spooled
**And** a test fills the spool and checks each emergency action still succeeds while an ordinary tier 1 write is refused

**AC5 (AD-17)**
**Given** a spooled entry altered on disk
**When** the Core replays it
**Then** the MAC check fails, the entry is not appended as valid, and an instance admin alert is raised in the Core alert queue

**Dependencies:**
- Story 6.2 (append path)

**References:**
- `doc/prd.md` FR-31
- `doc/architecture-spine.md` AD-17
- `doc/architecture.md` section 17 (audit writer unavailable)
- `doc/decisions.md` D59, D113
- `doc/key-management.md` section 2 (instance key)
