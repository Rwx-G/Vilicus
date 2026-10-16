---
title: 'Instance name and certificate setup'
epic: 8
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-65, FR-4, D51, D76, E24, D113]
---

# Story 8.3: Instance name and certificate setup

As an operator holding the bootstrap token,
I want to set the instance name and a certificate trusted by the household's devices before any passkey exists,
So that every passkey is bound to the name members will keep using.

**Acceptance Criteria:**

**AC1 (FR-65, FR-4, D76)**
**Given** a redeemed bootstrap token
**When** the operator enters the instance name and chooses the certificate source
**Then** the choice is a certificate and key file delivered as a Gateway credential, or a reverse proxy that terminates TLS for the name

**AC2 (FR-65, D51)**
**Given** a configured name and certificate
**When** the wizard checks it from the wizard's browser
**Then** the certificate must validate there before any passkey enrollment page, for the instance admin or a member, is served
**And** a certificate that does not validate keeps the wizard on this step

**AC3 (FR-4, D76)**
**Given** the certificate validates
**When** the step completes
**Then** the wizard moves to the instance name and continues there

**AC4 (FR-65, D113)**
**Given** the certificate file option
**When** the certificate is within the alert lead time of its expiry (14 days, PRD assumption, operator-tunable in `vilicus.toml`)
**Then** an out-of-browser alert goes to the instance admin and every member

**AC5 (FR-65, E24)**
**Given** the reverse-proxy option
**When** it is chosen
**Then** the wizard states that the operator monitors certificate expiry and that the hybrid key exchange ends at the proxy
**And** the naming options it describes are those that passed E24

**Dependencies:**
- Story 8.2 (bootstrap token)
- Story 8.1 (notification stage for expiry alerts)

**References:**
- `doc/prd.md` FR-4, FR-65
- `doc/architecture-spine.md` AD-52, AD-22
- `doc/architecture.md` sections 7.1, 15
- `doc/decisions.md` D27, D51, D76, D113
- `doc/research-notes.md` E24
