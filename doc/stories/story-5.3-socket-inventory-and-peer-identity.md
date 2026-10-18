---
title: 'Socket inventory and peer identity'
epic: 5
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-24, AD-55, FR-2, E10, D125]
---

# Story 5.3: Socket inventory and peer identity

As an operator,
I want every Unix socket created by its owning unit and every Core peer identified by its systemd unit,
So that no process can talk to the Core as another one, and only root reaches the administration socket.

**Acceptance Criteria:**

**AC1 (AD-55)**
**Given** the socket inventory of AD-55
**When** the units start
**Then** each socket exists under `/run/vilicus` at its inventory path, created by its owning unit or passed by systemd, never by a client
**And** the Core listens on one socket per peer instance, reachable only by that unit

**AC2 (AD-24, FR-2, E10, D125)**
**Given** a connection accepted on a Core peer socket
**When** the Core identifies the peer
**Then** it takes the peer's pidfd (`SO_PEERPIDFD`) and pid at accept, checks that the pid is listed in `cgroup.procs` of the cgroup systemd reports for the unit the socket belongs to (its `ControlGroup` property over D-Bus, read once the unit is active and pinned for the life of the Core, never derived from the unit name), and only then checks that the pidfd's process has not exited; it never reads `/proc/<pid>`, which its own `ProtectProc=invisible` hides, and never compares the last component of a cgroup path alone
**And** a peer whose unit does not match is refused and the refusal is recorded; tests, with `spikes/sandbox-profile/checks.sh` as the template, refuse a process of another unit, a process of another unit running under the same uid, a process in a cgroup whose last component is the expected unit name, a process outside any unit, and a pid reused by the expected unit after the connecting process exited (`reason=peer-exited`), and accept the expected unit

**AC3 (AD-24, AD-55)**
**Given** the administration socket `core/admin/admin.sock`
**When** a client connects
**Then** it is accepted only when `SO_PEERCRED` reports uid 0, and the socket sits in a directory readable by root only
**And** `SO_PEERCRED` is not used alone on any other socket

**AC4 (E10, AD-24, D125)**
**Given** E10 passed on a Debian 13 VM (kernel 6.12, systemd 257, AppArmor active) without its fallback (D125), so the uid-only fallback is not built
**When** `SO_PEERPIDFD` fails on an accepted connection, whatever the errno (Debian 13's 6.12 refuses a late pidfd for a reaped peer with `EINVAL`)
**Then** the connection is refused, with no fallback to the pid or the uid alone
**And** the Core refuses to start on a kernel older than 6.5, which lacks `SO_PEERPIDFD`

**AC5 (AD-55)**
**Given** a frame received on any Core socket
**When** the Core reads it
**Then** the framing and `Hello` handshake of `vilicus-proto` are applied, and a frame above the socket kind's maximum is refused before decoding

**AC6 (D125, AD-24)**
**Given** a verified peer connection
**When** the verified process exits while the connection is still open, held by a forked child or by a process that received the descriptor with `SCM_RIGHTS`
**Then** the Core, which watches the pidfd for the life of the connection, closes the connection and revokes what is bound to it, the capability tokens included (Story 10.2)
**And** a test reproduces Story 1.6's case: a peer of a unit with `KillMode=process` forks a child that keeps the connection and exits, and the child sees the close.

**AC7 (D125, AD-55)**
**Given** the Core's peer sockets
**When** the Core creates them
**Then** `core/peer/` is owned by the Core with mode 0700, and each peer's socket sits in its own directory `core/peer/<unit>/core.sock`, which only that unit bind-mounts (`BindPaths=` of the directory, never of the socket file, which would keep the old inode after the Core recreates it)
**And** the Core's runtime directory is kept across restarts (`RuntimeDirectoryPreserve=yes`), so a restart of the Core alone serves the same plugin process again on the recreated socket (test as `restart_core_alone_same_plugin_served_again`).

**AC8 (E10, D125)**
**Given** an unprivileged user manager with a delegated cgroup subtree
**When** it creates a cgroup named like a system unit and a process in it connects to that unit's socket
**Then** the connection is refused, tested in the Debian 13 VM harness (gate E10-3: not exercised by the spike, on Docker Desktop or in the VM).

**Dependencies:**
- Story 5.1 (Core process)
- Story 1.6 (E10 result; D125)
- Story 2.3 (Debian 13 VM harness)
- Story 2.5 (framing in `vilicus-proto`)

**References:**
- `doc/architecture-spine.md` AD-12, AD-24, AD-55
- `doc/architecture.md` section 4
- `doc/decisions.md` D18, D125
- `doc/prd.md` FR-2
- `doc/research-notes.md` E10
- `spikes/sandbox-profile/` (`src/core.rs`, `src/peer.rs`, `src/unit.rs`, `checks.sh`, `tests/peer.rs`)
- `doc/qa/gates/1.6-e10-sandbox-profile-and-peer-identity.yml` (E10-2, E10-3)
