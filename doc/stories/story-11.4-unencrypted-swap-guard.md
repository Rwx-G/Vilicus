---
title: 'Unencrypted swap guard'
epic: 11
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [NFR-5, FR-3]
---

# Story 11.4: Unencrypted swap guard

As an operator,
I want the Core to refuse to start on a host with unencrypted swap unless I acknowledge the risk,
So that unlocked keys are not written to disk in clear without a deliberate decision.

**Acceptance Criteria:**

**AC1 (NFR-5)**
**Given** a Debian 13 VM with an unencrypted swap device active and no acknowledgement recorded
**When** the Core starts
**Then** it refuses to start and logs the reason to the journal

**AC2 (NFR-5)**
**Given** a host with encrypted swap, or no swap
**When** the Core starts
**Then** it starts normally without any acknowledgement

**AC3 (NFR-5, FR-3)**
**Given** the host of AC1
**When** root runs `vilicus host acknowledge-swap`
**Then** the acknowledgement is recorded, the Core starts, and an audit entry records the command

**AC4 (NFR-5)**
**Given** an acknowledged unencrypted swap
**When** the instance admin goes through the bootstrap wizard, or root runs `vilicus status`
**Then** both show that unencrypted swap was acknowledged

**Dependencies:**
- Story 11.1 (status output)
- Story 8.4 (bootstrap wizard admin steps)

**References:**
- `doc/prd.md` section 7 (host hygiene), FR-3
- `doc/architecture.md` section 4 (memory hygiene)
