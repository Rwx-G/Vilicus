---
title: 'Systemd units and sandbox profile check'
epic: 5
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-2, AD-24, AD-16, D115, D18, D125, D128, D131]
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

**AC5 (D125, FR-2)**
**Given** the `vilicus-plugin@.service` and `vilicus-ai@.service` templates
**When** their profile is read with `systemctl show`
**Then** they carry the default template profile, whose reference is the fixed profile block of `spikes/sandbox-profile/units/vilicus-plugin@.service` (with `DynamicUser=yes` and one `LoadCredential=`) until the shipped template replaces it, plus `NoExecPaths=/` and `ExecPaths=/usr`, and every line of it is asserted against `systemctl show`, the `IPAddressDeny=` prefixes compared as a set because systemd 257 prints them in an order that varies per boot
**And** the plugin double still loads its libraries under `NoExecPaths=/` and `ExecPaths=/usr`, and a probe unit under each template fails to reach the system bus, the journal stream socket, an abstract socket of the host and another unit's socket, and to create a user namespace, each next to an unsandboxed control unit for which the same probe succeeds (`spikes/sandbox-profile/checks.sh` is the template); the profile of `doc/architecture.md` section 4 alone leaves those four open
**And** units that cannot take the default profile (the egress proxy, device adapters with a network or shared-namespace grant, the D115 forwarder, the WireGuard peer manager, runtimes that generate code at run time) get their own profile, tested on its own.

**AC6 (D125)**
**Given** every Vilicus unit, the Core included
**When** its system call filter is read
**Then** it explicitly denies `io_uring_setup`, `io_uring_enter` and `io_uring_register`, because `@system-service` includes them through `@aio` on systemd 257, and a test checks the loaded filter denies them, `mount` and `setuid` and allows `pidfd_open`
**And** no Vilicus unit sets `Delegate=`, the Core does not set `PrivateUsers=yes` (its uid checks need the real uids), and the templates set `KillMode=control-group`.

**AC7 (D131, D128)**
**Given** the Core unit
**When** it is installed
**Then** it runs under its own static user, sets `LimitMEMLOCK` to the key pool size with a margin and `LimitCORE=0`, and holds no `CAP_IPC_LOCK`
**And** its `MemoryMax=` covers the Argon2id limit times m (at most 1 GiB, Story 4.4 AC6) plus the Core's baseline.

**Dependencies:**
- Story 5.3 (sockets and peer identity)
- Story 2.3 (Debian 13 VM harness)
- Story 1.6 (the E10 template profile and `checks.sh`)
- Story 4.2 (key pool size)

**References:**
- `doc/prd.md` FR-2
- `doc/architecture.md` section 4
- `doc/architecture-spine.md` AD-16, AD-24
- `doc/decisions.md` D18, D115, D125, D128, D131
- `doc/stories/story-1.6-e10-sandbox-profile-and-peer-identity.md` (settled tasks 3 and 4; `systemd-analyze security` measured 0.4 for the Core and 0.2 for the plugin)
