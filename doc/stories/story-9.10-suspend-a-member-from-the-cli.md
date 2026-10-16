---
title: 'Suspend a member from the CLI'
epic: 9
story: 10
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-107, D77, D101, FR-3]
---

# Story 9.10: Suspend a member from the CLI

As an adult,
I want to suspend another member, or my own account, at once from the host,
So that a compromised account or a departing adult loses every access immediately, without a key rotation.

**Acceptance Criteria:**

**AC1 (FR-107, FR-3, D101)**
**Given** root at the host
**When** `vilicus member suspend <member>` runs
**Then** it succeeds only with the passphrase of an adult other than the suspended member, or with the member's own passphrase for their own account, read from the prompt
**And** a failure is audited

**AC2 (FR-107, D77)**
**Given** a successful suspension
**When** it takes effect
**Then** at once the member's web sessions, paired devices and unlock window are revoked, the member's keys are dropped from memory, and login is blocked
**And** keys, wrappers and data are kept and the household key is not rotated

**AC3 (FR-107)**
**Given** a suspended member
**When** they try to log in, pair a browser, re-enroll or unlock from the host
**Then** each attempt is refused and audited

**AC4 (FR-107)**
**Given** a suspension
**When** it takes effect
**Then** every adult, the suspended member included, is notified in the primary channel and on the out-of-browser notification channel

**Dependencies:**
- Story 9.3 (unlock window to revoke)
- Story 9.7 (paired devices to revoke)

**References:**
- `doc/prd.md` FR-3, FR-107
- `doc/key-management.md` section 5
- `doc/architecture.md` section 6
- `doc/decisions.md` D77, D101
