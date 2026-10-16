---
title: 'E14: egress proxy domain filtering'
epic: 1
story: 12
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E14, FR-55, AD-16, I4]
---

# Story 1.12: E14: egress proxy domain filtering

As the owner,
I want CONNECT-based exact-hostname filtering tested against real client traffic,
So that the egress proxy of Epic 5 is the network control it claims to be.

**Acceptance Criteria:**

**AC1 (E14, FR-55, AD-16)**
**Given** a prototype proxy under `spikes/e14-egress/` accepting `CONNECT host:port` over a Unix socket with an exact-hostname allowlist, resolving names itself and connecting to the checked address
**When** a reference client makes HTTP/1.1 and HTTP/2 requests to an allowlisted host, attempts QUIC, and follows a redirect to a host not on the allowlist
**Then** allowlisted traffic works, QUIC cannot leave without the proxy, and the redirect target is refused

**AC2 (E14, AD-16, I4)**
**Given** a test resolver that answers a public address for a name on the first lookup and an internal address on the second
**When** the client connects to that name through the proxy
**Then** the proxy refuses the internal address at connect time

**AC3 (E14, I4)**
**Given** the client tries a direct outbound connection without the proxy under `IPAddressDeny=any`
**When** the attempt runs
**Then** it fails
**And** if any bypass of the allowlist is found, the fallback (per-plugin IP ranges as a second filter) is recorded in `doc/decisions.md`

**Spike plan:**
- Question: does CONNECT-based domain filtering hold for real traffic (HTTP/2, QUIC, redirects) (E14)?
- Method: reference client and prototype proxy; a rebinding resolver; direct-socket negative test.
- Pass criterion: no bypass of the allowlist; no breakage of normal flows.
- Timebox: 3 working days.
- Fallback on failure: per-plugin IP ranges as a second filter.
- Result record: E14 status in `doc/research-notes.md`; the test set kept for Story 5.5.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E14)
- `doc/architecture-spine.md` AD-16, AD-55
- `doc/architecture.md` section 4
- `doc/prd.md` FR-55, section 9
- `doc/ai-safety.md` section 3 (I4)
