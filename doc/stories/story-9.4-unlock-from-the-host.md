---
title: 'Unlock from the host'
epic: 9
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-57, FR-3, D77]
---

# Story 9.4: Unlock from the host

As a member with host access,
I want to unlock my partition with `vilicus unlock` on the host,
So that my passphrase never transits through the Gateway.

**Acceptance Criteria:**

**AC1 (FR-57, D77)**
**Given** a locked member
**When** root runs `vilicus unlock <member>` and the member types their own passphrase at the prompt
**Then** the partition unlocks and an unlock window is set with the same maximum, default and deadline rules as FR-12

**AC2 (FR-3, D77)**
**Given** the command targets a member
**When** the passphrase of another adult is typed
**Then** the unlock is refused; only the target member's own passphrase unlocks, read only from the interactive prompt

**AC3 (FR-57, FR-3)**
**Given** any run of `vilicus unlock`, successful or failed
**When** it completes
**Then** an audit entry is written, without the passphrase or any key material
**And** the member sees the window in the member web with its remaining time

**Dependencies:**
- Story 9.3 (unlock window)

**References:**
- `doc/prd.md` FR-3, FR-57
- `doc/key-management.md` section 4
- `doc/decisions.md` D77
