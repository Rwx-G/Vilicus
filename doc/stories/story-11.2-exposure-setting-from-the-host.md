---
title: 'Exposure setting from the host'
epic: 11
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-6, FR-3, D101, FR-56, D137, DC-78]
---

# Story 11.2: Exposure setting from the host

As an operator,
I want to set the Gateway's listening addresses only at the host CLI,
So that a compromised Gateway or web session can never expose the instance to the internet.

**Acceptance Criteria:**

**AC1 (FR-6, D101)**
**Given** a running instance
**When** root runs `vilicus instance listen <addresses>` with private addresses only (loopback, RFC 1918, fc00::/7, link-local)
**Then** the Gateway's socket unit is rewritten with those addresses and the Gateway is restarted on them

**AC2 (FR-6)**
**Given** a list containing a non-private address such as `198.51.100.7`
**When** root runs `vilicus instance listen` without `--acknowledge-public-exposure`
**Then** the command is refused and the socket unit is unchanged
**And** with `--acknowledge-public-exposure` the change is applied

**AC3 (FR-6, D101)**
**Given** the client API route table
**When** a test enumerates every web route of the member and instance admin surfaces
**Then** no route changes the listening addresses or exposure

**AC4 (FR-6, FR-56, FR-3)**
**Given** any accepted or refused exposure change
**When** the command finishes
**Then** an audit entry records it with its outcome
**And** for an applied change every adult receives an "exposure changed" alert on the out-of-browser notification channel

**AC5 (D137, FR-6, DC-78)**
**Given** an overlay network whose addresses are in 100.64.0.0/10, which is never private by default (Story 7.1 AC7)
**When** root names one overlay interface with `vilicus instance listen`
**Then** that interface's address in 100.64.0.0/10 becomes private for FR-6 and FR-4, the Gateway's socket for it is bound to that interface (`BindToDevice=`), and a peer on that address is accepted only on that socket; without the named interface, listening on such an address still needs `--acknowledge-public-exposure` (AC2)
**And** at most one overlay interface is named, and naming it is audited and alerted to every adult like any exposure change (AC4).

**Dependencies:**
- Story 11.1 (status reports the active listening addresses)

**References:**
- `doc/prd.md` FR-6, FR-50, FR-56
- `doc/decisions.md` D101, D137
- `doc/architecture.md` section 15
