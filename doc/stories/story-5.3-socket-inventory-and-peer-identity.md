---
title: 'Socket inventory and peer identity'
epic: 5
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-24, AD-55, FR-2, E10]
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

**AC2 (AD-24, FR-2, E10)**
**Given** a connection accepted on a Core peer socket
**When** the Core identifies the peer
**Then** it reads the systemd unit name from the cgroup of the peer's pidfd (`SO_PEERPIDFD`) and compares it with the unit the socket belongs to
**And** a peer whose unit does not match is refused and the refusal is recorded (test: a process of another unit connects and is refused)

**AC3 (AD-24, AD-55)**
**Given** the administration socket `core/admin/admin.sock`
**When** a client connects
**Then** it is accepted only when `SO_PEERCRED` reports uid 0, and the socket sits in a directory readable by root only
**And** `SO_PEERCRED` is not used alone on any other socket

**AC4 (E10, AD-24)**
**Given** the E10 result recorded in `doc/research-notes.md`
**When** E10 took its fallback
**Then** each first-party unit runs under its own static user and the Core checks the uid with `SO_PEERCRED`, and the weaker check is recorded in `doc/architecture.md` section 20 as the E10 fallback

**AC5 (AD-55)**
**Given** a frame received on any Core socket
**When** the Core reads it
**Then** the framing and `Hello` handshake of `vilicus-proto` are applied, and a frame above the socket kind's maximum is refused before decoding

**Dependencies:**
- Story 5.1 (Core process)
- Story 1.6 (E10 result)
- Story 2.5 (framing in `vilicus-proto`)

**References:**
- `doc/architecture-spine.md` AD-12, AD-24, AD-55
- `doc/architecture.md` section 4
- `doc/prd.md` FR-2
- `doc/research-notes.md` E10
