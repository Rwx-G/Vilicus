---
title: 'Web client shell under strict CSP'
epic: 7
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-52, FR-17, AD-19, UX-DR2, NFR-9]
---

# Story 7.3: Web client shell under strict CSP

As a member,
I want the web client to run under a strict content security policy with Trusted Types,
So that injected markup or script cannot run in the primary channel.

**Acceptance Criteria:**

**AC1 (AD-19, FR-52)**
**Given** the web client built with Lit and Vite
**When** the binary is built
**Then** the client is embedded and served by the Gateway as static files, with no server-side rendering

**AC2 (FR-17, AD-19, UX-DR2)**
**Given** any page of the web client
**When** it is served
**Then** the CSP is `default-src 'none'`, `script-src 'self'` with a nonce generated per response, `frame-ancestors 'none'`, `base-uri 'none'`, Trusted Types enforced with the `lit-html` policy only, and `connect-src` limited to the client's own API and change stream
**And** `img-src`, `style-src` and `connect-src` allow no remote origin

**AC3 (AD-19, UX-DR2)**
**Given** the front-end source
**When** lint runs in CI
**Then** any use of `unsafeHTML`, `unsafeSVG` or another HTML-from-string path fails the merge

**AC4 (AD-19, NFR-9)**
**Given** the production CSP header
**When** the CI browser test loads every page on the current and previous releases of Chrome and Firefox, desktop and Android (emulated)
**Then** any CSP or Trusted Types violation report fails the build

**AC5 (FR-17)**
**Given** the web client running in a browser
**When** its storage is inspected after login
**Then** no secret is held in `localStorage`

**Dependencies:**
- Story 7.2 (generated client API types)

**References:**
- `doc/prd.md` FR-17, FR-52, FR-50 (supported browsers)
- `doc/architecture-spine.md` AD-19
- `doc/architecture.md` section 6
- `doc/decisions.md` D26, D107
