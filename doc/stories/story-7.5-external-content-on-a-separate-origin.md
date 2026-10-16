---
title: 'External content on a separate origin'
epic: 7
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-17, FR-52, AD-19, E26, UX-DR3]
---

# Story 7.5: External content on a separate origin

As a member,
I want content that came from outside the household rendered away from the client's origin,
So that hostile markup in an external record can neither run script nor reach my session.

**Acceptance Criteria:**

**AC1 (FR-17, AD-19, UX-DR3)**
**Given** E26 passed and a reference-module record with `external` free text in the testbed
**When** the member opens it
**Then** it renders in a script-less sandboxed iframe served from the same instance name on a separate port
**And** that origin's CSP forbids every subresource and every form

**AC2 (AD-19)**
**Given** the separate origin is same-site with the client, so the session cookie can accompany its requests
**When** a test issues every GET endpoint from that origin
**Then** no GET endpoint has a side effect

**AC3 (AD-19)**
**Given** a link inside external content
**When** it is displayed
**Then** its full destination is shown

**AC4 (E26, UX-DR3)**
**Given** E26 took its fallback
**When** external content is displayed
**Then** it is shown as sanitized plain text, never as HTML, and no separate-origin listener is opened

**Dependencies:**
- Story 7.3 (web client shell and CSP)
- Story 1.14 (E26 result)
- Story 3.10 (reference module providing an external record)

**References:**
- `doc/prd.md` FR-17, FR-52
- `doc/architecture-spine.md` AD-19
- `doc/research-notes.md` E26
- `doc/architecture.md` section 6
