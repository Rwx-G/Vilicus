---
title: 'Egress proxy with per-caller allowlists'
epic: 5
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-55, AD-16, AD-55, E14, I4, D105]
---

# Story 5.5: Egress proxy with per-caller allowlists

As an operator,
I want all outbound traffic to go through one proxy that allows only listed hostnames per caller and refuses internal addresses,
So that no Vilicus process can reach the household network or an unlisted host on its own.

**Acceptance Criteria:**

**AC1 (AD-16, AD-55)**
**Given** the egress proxy unit
**When** it runs
**Then** it keeps no TCP listener and accepts callers only on one Unix data socket per caller (`egress/data/<caller>.sock`), identified by `SO_PEERPIDFD`, and takes allowlists from the Core only over `egress/control.sock`
**And** it accepts `CONNECT host:port` only, for a hostname on that caller's exact-hostname allowlist

**AC2 (AD-16, FR-55)**
**Given** an allowed hostname
**When** the proxy connects
**Then** it resolves the name itself, checks each resolved address at connect time and connects to that exact address
**And** it refuses loopback, RFC 1918, link-local and unique local addresses, 100.64.0.0/10, IPv4-mapped and NAT64 forms of all of these, multicast and unspecified addresses, and the host's own and the household's public addresses
**And** a test name that rebinds between two lookups to an internal address is refused

**AC3 (D105, I4)**
**Given** a named private destination entry (host and port) set by the Core
**When** a caller requests it
**Then** the proxy allows it to the Core and backup callers only and refuses it to any other caller

**AC4 (I4, FR-55, E14)**
**Given** a sandboxed unit in the Debian 13 VM
**When** it opens a direct outbound connection
**Then** the connection fails, while the same request through its proxy socket to an allowlisted host succeeds
**And** the E14 fallback (per-caller IP ranges as a second filter) is applied if E14 took it

**AC5 (AD-16)**
**Given** the Core
**When** it starts on a host that cannot enforce the IP filter (negative connection test fails)
**Then** it refuses to start with a clear error
**And** while running it checks the proxy's health every 30 seconds (assumption of `doc/architecture.md` section 17) and, after three failures, raises an alert in the Core alert queue

**Dependencies:**
- Story 5.4 (units and profile)
- Story 1.12 (E14 result)

**References:**
- `doc/prd.md` FR-55, FR-56
- `doc/architecture-spine.md` AD-16, AD-55
- `doc/architecture.md` sections 4 and 17
- `doc/ai-safety.md` I4
- `doc/decisions.md` D105
- `doc/research-notes.md` E14
