---
title: 'E10: sandbox profile and peer identity'
epic: 1
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E10, FR-2, AD-24, AD-55, D18]
---

# Story 1.6: E10: sandbox profile and peer identity

As the owner,
I want the fixed systemd profile and the Core's peer identification tested on Debian 13,
So that every socket check and unit profile of Epic 5 rests on behaviour observed on the target system.

**Acceptance Criteria:**

**AC1 (E10, FR-2, D18)**
**Given** a reference plugin under `spikes/e10-sandbox/` running in a unit with `DynamicUser=yes`, `LoadCredential=`, `SystemCallFilter=@system-service` and `IPAddressDeny=any` on Debian 13
**When** it serves one request over its Unix socket and reads its one credential
**Then** it works, and its attempts to open a direct network socket fail

**AC2 (E10, AD-24, AD-55)**
**Given** a prototype listener owned by a Core-like unit
**When** a peer connects and the listener reads the systemd unit name from the cgroup of the peer's pidfd (`SO_PEERPIDFD`)
**Then** the expected unit is recognized, and a connection from another unit, including one running under the same uid, is rejected

**AC3 (E10, AD-24)**
**Given** the unit name cannot be read from the cgroup on Debian 13
**When** the result is recorded
**Then** the fallback is recorded in `doc/decisions.md`: each first-party unit runs under its own static user and the Core checks the uid with `SO_PEERCRED`, recorded as weaker against a compromised unit of the same user

**Spike plan:**
- Question: does the fixed systemd profile work for a plugin that needs a socket, one credential and the egress proxy, and can the Core identify peers by unit (E10)?
- Method: reference plugin and listener on a Debian 13 VM; negative socket tests; same-uid impersonation test.
- Pass criterion: the plugin works, direct sockets fail, peer identity verified by unit name.
- Timebox: 4 working days.
- Fallback on failure: relax individual options with a documented list; if `SO_PEERPIDFD` and the cgroup unit cannot be read, each first-party unit runs under its own static user and the Core checks the uid with `SO_PEERCRED`, recorded as weaker.
- Result record: E10 status in `doc/research-notes.md` with a link to the test run; any relaxed option or fallback recorded in `doc/decisions.md`.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E10), section 1.1 (systemd IP filter)
- `doc/architecture-spine.md` AD-24, AD-55, AD-16
- `doc/architecture.md` section 4
- `doc/decisions.md` D18
- `doc/prd.md` FR-2, section 9
