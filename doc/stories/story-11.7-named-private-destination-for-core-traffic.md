---
title: 'Named private destination for Core traffic'
epic: 11
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-56, FR-50, D105, AD-16, I4, D133]
---

# Story 11.7: Named private destination for Core traffic

As an instance admin,
I want to name a private host and port that Core-originated traffic may reach,
So that a push server, backup target or audit sink on the household's network works while everything else stays blocked from internal addresses.

**Acceptance Criteria:**

**AC1 (FR-56, D105, FR-50, D133)**
**Given** the instance admin web
**When** the instance admin names the host `push.home.arpa`, the port 8443 and the private range `10.0.0.0/24` its addresses must fall in, and approves with a step-up bound to that action
**Then** the destination is stored with its host, port and range, and pushed to the egress proxy's control socket
**And** every adult receives an out-of-browser alert and an audit entry is written
**And** the host is a DNS name, since the proxy refuses an IP literal as a CONNECT target (Story 5.5 AC7), and a range outside RFC 1918 or unique local space is refused when it is named (D133)

**AC2 (AD-16, D105)**
**Given** a named private destination
**When** the Core or the backup caller opens a `CONNECT` to it
**Then** the egress proxy allows it

**AC3 (I4, AD-16)**
**Given** the same destination
**When** an AI process double or a plugin double requests a `CONNECT` to it
**Then** the egress proxy refuses it and the refusal is audited

**AC4 (AD-16)**
**Given** a private address that was not named
**When** the Core requests a connection to it
**Then** the egress proxy refuses it

**AC5 (D133, AD-16)**
**Given** a named destination whose name resolves, at connect time, to an address outside its recorded range, or to a mix of in-range and other addresses
**When** the Core requests a connection to it
**Then** the egress proxy refuses it, so a rebinding name cannot redirect the Core's exception to another private host (Story 1.12, finding 7); a destination whose address moves outside its range must be named again

**Dependencies:**
- Story 5.5 (egress proxy)
- Story 8.1 (out-of-browser notification stage)
- Story 7.6 (action-bound step-up)

**References:**
- `doc/prd.md` FR-56, FR-50
- `doc/architecture-spine.md` AD-16
- `doc/ai-safety.md` I4
- `doc/decisions.md` D105, D133
