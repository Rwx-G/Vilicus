---
title: 'Server-sent change stream'
epic: 7
story: 8
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-56, AD-19, FR-50, UX-DR7]
---

# Story 7.8: Server-sent change stream

As a member,
I want my screens to refresh when something changes,
So that I see pending requests and alerts without reloading, while no data travels outside signed requests.

**Acceptance Criteria:**

**AC1 (AD-56, FR-50)**
**Given** a paired browser with a web session
**When** the client opens the change stream with a signed request
**Then** the Gateway serves one server-sent event stream for that session

**AC2 (AD-56, UX-DR7)**
**Given** a change in data the member may read
**When** it is announced on the stream
**Then** the notice carries only ids and versions
**And** the client re-reads the data through signed requests

**AC3 (AD-56, UX-DR7)**
**Given** the stream is unavailable
**When** the client detects it
**Then** it polls every 30 seconds until the stream comes back

**AC4 (AD-19, AD-56)**
**Given** the production CSP
**When** `connect-src` is inspected
**Then** the change stream is its only entry besides the client API

**Dependencies:**
- Story 7.7 (signed requests)

**References:**
- `doc/architecture-spine.md` AD-56, AD-19
- `doc/prd.md` FR-50
- `doc/architecture.md` section 6
