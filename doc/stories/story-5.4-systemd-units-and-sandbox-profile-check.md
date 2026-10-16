---
title: 'Systemd units and sandbox profile check'
epic: 5
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-2, AD-24, AD-16, D115, D18]
---

# Story 5.4: Systemd units and sandbox profile check

As an operator,
I want every Vilicus unit to run under the fixed sandbox profile, checked in CI,
So that a compromised process is confined by systemd and no unit drifts from the profile unnoticed.

**Acceptance Criteria:**

**AC1 (AD-24, D18)**
**Given** the unit files shipped in `packaging/`
**When** they are installed
**Then** the Core, Gateway (socket activated), audit writer and egress proxy run as static units, each under its own static system user
**And** the templates `vilicus-ai@.service` and `vilicus-plugin@.service` run with `DynamicUser=yes`

**AC2 (FR-2, D115, AD-16)**
**Given** every sandboxed unit
**When** its profile is read
**Then** it sets `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX` (the egress proxy alone gets the families it needs), `IPAddressDeny=any`, `ProtectProc=invisible`, `MemoryMax`, `TasksMax` and `LimitCORE=0`
**And** no unit carries an `IPAddressAllow=` entry for loopback

**AC3 (AD-24)**
**Given** the polkit rule shipped with the package
**When** the Core asks systemd over D-Bus to start or stop a unit
**Then** it succeeds only for instances of the `vilicus-ai@` and `vilicus-plugin@` templates and is refused for any other unit (test in the Debian 13 VM)

**AC4 (FR-2)**
**Given** a change to any unit file
**When** CI runs the profile check
**Then** the merge is blocked on any deviation from the profile of `doc/architecture.md` section 4
**And** the check also fails when `systemd-analyze security` scores any unit above 2.0 (PRD assumption)

**Dependencies:**
- Story 5.3 (sockets and peer identity)
- Story 2.3 (Debian 13 VM harness)

**References:**
- `doc/prd.md` FR-2
- `doc/architecture.md` section 4
- `doc/architecture-spine.md` AD-16, AD-24
- `doc/decisions.md` D18, D115
