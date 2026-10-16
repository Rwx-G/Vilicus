---
title: 'Debian package install, remove and purge'
epic: 5
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-1, FR-54, AD-22, AD-25, D96]
---

# Story 5.7: Debian package install, remove and purge

As an operator,
I want to install, remove and purge Vilicus with the system package manager, without containers,
So that a clean Debian 13 host runs the Core and its services under unprivileged accounts in one command.

**Acceptance Criteria:**

**AC1 (FR-1, AD-22)**
**Given** a clean Debian 13 amd64 VM
**When** the operator runs `apt install ./vilicus_<version>.deb`
**Then** the Core, Gateway, audit writer and egress proxy run as separate systemd services under unprivileged static users
**And** the package created those users, the units, the polkit rule, `/etc/vilicus/vilicus.toml`, `/var/lib/vilicus` owned by the Core's user with `audit.db` in a subdirectory owned by the audit writer's user, and `/run/vilicus`

**AC2 (AD-25, D96)**
**Given** the first installation
**When** the install-time secrets are created
**Then** the instance key and the audit key are generated as systemd credentials, sealed to PCR 7 when the host has a TPM and stored as file credentials otherwise
**And** each key is readable only by its own unit

**AC3 (FR-1)**
**Given** an installed system with data
**When** the operator removes the package
**Then** the services stop and the data directory stays in place
**And** purging is a separate explicit step that the documentation names

**AC4 (FR-54)**
**Given** the package maintainer scripts
**When** they run as root
**Then** they do the minimum and touch no member data file beyond the ownership of the data directory (test compares file hashes before and after)
**And** the package enables no automatic upgrade

**AC5 (FR-1)**
**Given** the package build in CI
**When** its contents are listed
**Then** `vilicus-testbed`, the reference module and every test double are absent, and the package targets amd64 (arm64 later, PRD assumption)

**Dependencies:**
- Story 5.4 (units)
- Story 5.5 (egress proxy)
- Story 5.6 (CLI framework)

**References:**
- `doc/prd.md` FR-1, FR-54, FR-109
- `doc/architecture-spine.md` AD-22, AD-25, AD-34
- `doc/key-management.md` section 2 (instance key, audit key)
- `doc/decisions.md` D96
