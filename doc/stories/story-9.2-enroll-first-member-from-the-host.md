---
title: 'Enroll the first member from the host'
epic: 9
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-7, FR-3, D101, UJ-1]
---

# Story 9.2: Enroll the first member from the host

As an operator,
I want `vilicus member enroll-first` to print an enrollment token while no member exists,
So that an interrupted wizard never leaves the instance without a way to enroll its first member.

**Acceptance Criteria:**

**AC1 (FR-7, FR-3, D101)**
**Given** the instance admin exists and no member exists
**When** root runs `vilicus member enroll-first` and types the admin recovery code at the prompt
**Then** the CLI prints an enrollment token of 128 random bits, single use, valid 15 minutes
**And** the code is read only from the interactive prompt, never from an argument, an environment variable or a file

**AC2 (FR-7, UJ-1)**
**Given** a token printed by `vilicus member enroll-first`
**When** the person opens the member enrollment page on the instance name with it
**Then** the enrollment follows Story 9.1 in full (one passkey, strength-checked passphrase, recovery secret re-typed, test notification confirmed by the check of Story 8.1 AC4 (D135), Core-generated keys, household key created)
**And** the token cannot be redeemed a second time or after 15 minutes

**AC3 (FR-7, D101)**
**Given** at least one member exists
**When** root runs `vilicus member enroll-first`
**Then** the command is refused before any prompt result is used, and no token is printed

**AC4 (FR-3, D101)**
**Given** a wrong admin recovery code
**When** root runs the command
**Then** it fails, attempts are rate limited, and every attempt, failed or not, produces an audit entry
**And** the command grants no access to member or household data

**Dependencies:**
- Story 9.1 (first member enrollment flow)

**References:**
- `doc/prd.md` FR-3, FR-7, FR-50, UJ-1 edge case
- `doc/key-management.md` section 3
- `doc/decisions.md` D101, D135
- `doc/capability-matrix.md` section 1
