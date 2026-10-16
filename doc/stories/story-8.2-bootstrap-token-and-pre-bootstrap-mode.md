---
title: 'Bootstrap token and pre-bootstrap mode'
epic: 8
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-4, FR-3, AD-52, D32, D76]
---

# Story 8.2: Bootstrap token and pre-bootstrap mode

As an operator,
I want the first start to print a one-time bootstrap token and the temporary certificate fingerprint,
So that only someone with host access can start the wizard, over a connection I can check.

**Acceptance Criteria:**

**AC1 (FR-4, D32)**
**Given** a first start with no instance admin
**When** the Core starts
**Then** it creates a token of 128 random bits, single use, valid 15 minutes, with redemption rate limited
**And** writes the token and the temporary certificate fingerprint to the Core unit's journal and shows them in `vilicus status` while bootstrap is pending

**AC2 (FR-4, FR-3)**
**Given** bootstrap is pending
**When** root runs `vilicus bootstrap token`
**Then** a new token is issued and the previous one is invalidated
**And** the command is audited

**AC3 (FR-4, AD-52)**
**Given** bootstrap is pending
**When** a browser on a private address opens the wizard
**Then** the wizard answers only on loopback and private addresses, over the temporary self-signed certificate, and asks for the token

**AC4 (FR-4, D76)**
**Given** the temporary self-signed certificate
**When** the wizard routes are enumerated
**Then** no WebAuthn ceremony is offered on them

**AC5 (FR-4)**
**Given** an expired, already used or wrong token
**When** it is submitted
**Then** it is refused, the attempt is rate limited and audited

**Dependencies:**
- Story 7.1 (Gateway pre-bootstrap mode and temporary certificate)
- Story 6.2 (audit append path)

**References:**
- `doc/prd.md` FR-3, FR-4
- `doc/architecture-spine.md` AD-52
- `doc/architecture.md` section 7.1
- `doc/decisions.md` D32, D76
