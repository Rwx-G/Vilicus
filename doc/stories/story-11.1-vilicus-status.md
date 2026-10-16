---
title: 'vilicus status'
epic: 11
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-3, FR-4, AD-17, AD-55]
---

# Story 11.1: vilicus status

As an operator,
I want `vilicus status` to report the health of the instance without unlocking anything,
So that I can see at the host whether services, members, migrations, the audit chain and notifications are in order.

**Acceptance Criteria:**

**AC1 (FR-3, AD-55)**
**Given** an installed instance with the Core, Gateway, audit writer and egress proxy running
**When** root runs `vilicus status`
**Then** the command reports the health of each service through the admin socket
**And** it needs no member passphrase and unlocks nothing

**AC2 (FR-3)**
**Given** two members, one unlocked and one locked
**When** root runs `vilicus status`
**Then** each member is listed as locked or unlocked, with suspension shown where it applies
**And** no record content, partition data or key material appears in the output

**AC3 (FR-3, AD-17)**
**Given** a module file with a failed migration and another with a pending one, and an audit chain whose last verification found a broken entry
**When** root runs `vilicus status`
**Then** the pending and failed migrations are listed per file
**And** the audit chain state from `vilicus audit verify` is shown

**AC4 (FR-3)**
**Given** a member whose out-of-browser destination failed the last delivery, and an egress proxy that failed three consecutive health checks
**When** root runs `vilicus status`
**Then** the notification delivery failure is reported for that member without the alert content
**And** the egress proxy is reported as unhealthy

**AC5 (FR-4)**
**Given** a fresh install where bootstrap has not completed
**When** root runs `vilicus status`
**Then** the current bootstrap token and the temporary certificate fingerprint are shown
**And** once bootstrap completes neither is shown again

**AC6 (FR-3)**
**Given** any invocation of `vilicus status`, successful or not
**When** it finishes
**Then** an audit entry records the command and its outcome

**Dependencies:**
- Story 6.4 (audit chain state)
- Story 8.1 (notification delivery failures)
- Story 3.7 (migration states per file)

**References:**
- `doc/prd.md` FR-3, FR-4
- `doc/architecture-spine.md` AD-17, AD-55
- `doc/architecture.md` section 17 (egress proxy health)
