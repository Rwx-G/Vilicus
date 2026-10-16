---
title: 'E3: hybrid key exchange negotiation'
epic: 1
story: 16
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E3, D27, NFR-7]
---

# Story 1.16: E3: hybrid key exchange negotiation

As the owner,
I want the negotiated TLS group recorded for each client against the rustls server,
So that the README transport wording says exactly which clients get the hybrid key exchange (X25519MLKEM768), within the D27 wording.

**Acceptance Criteria:**

**AC1 (E3, D27)**
**Given** a rustls 0.23.45 server with the aws-lc-rs provider preferring X25519MLKEM768, under `spikes/e3-tls/`
**When** current Chrome, Firefox, Safari, Android System WebView, OkHttp and Cronet complete a real handshake
**Then** the negotiated group is recorded per client and version

**AC2 (E3, NFR-7)**
**Given** the recorded table
**When** the README transport wording is checked
**Then** it claims the hybrid exchange only for the clients that negotiated it, keeps the classical fallback for the others, and makes no claim beyond D27

**AC3 (E3)**
**Given** the result
**When** it is recorded
**Then** it informs the README wording only and blocks no other V0.1 work

**Spike plan:**
- Question: does every client negotiate the hybrid key exchange (E3)?
- Method: real handshakes against the rustls server from each listed client.
- Pass criterion: the negotiated group per client is recorded; the result informs the README wording of the transport claim.
- Timebox: 2 working days.
- Fallback on failure: document which clients lose the hybrid exchange; keep the classical fallback.
- Result record: E3 table in `doc/research-notes.md`; README wording checked against it.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E3), section 1.1 (TLS hybrid)
- `doc/decisions.md` D27
- `doc/architecture.md` section 15
- `doc/prd.md` section 9
