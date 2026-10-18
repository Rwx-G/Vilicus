---
title: 'Web client shell under strict CSP'
epic: 7
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-52, FR-17, AD-19, UX-DR2, NFR-9, E22, D122, D139]
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

**AC6 (AD-19, E22, D122)**
**Given** the CI browser test of AC4
**When** it checks the policy of a page
**Then** the probes (`eval`, WebAssembly compilation, `innerHTML` from a string, a Trusted Types policy under a name other than `lit-html`) run from the page's own module at load, never through `page.evaluate` or another DevTools-protocol call, because Chrome lets code evaluated through the DevTools protocol run `eval` despite the CSP (Story 1.3, finding 2)
**And** a test-only control page that allows what the others forbid shows the same probes reporting `allowed`, so a blocked result is not an artefact of the probe
**And** Lit's module is loaded before any other script, because `trusted-types lit-html` lets the first script that creates a `lit-html` policy own it (Story 1.3, finding 3).

**AC7 (D139, AD-19)**
**Given** the client's CSP of AC2
**When** `frame-src` is read
**Then** it lists only the external-content origin, the instance name on port 8443 (Story 7.5), which also keeps the iframe from navigating anywhere else (Story 1.14, finding 3)
**And** CSP violation reports are treated as monitoring only, never as the evidence that a load was blocked, since browsers miss reports for some blocked loads (Story 1.14, finding 5); the browser test asserts the block itself.

**Dependencies:**
- Story 7.2 (generated client API types)

**References:**
- `doc/prd.md` FR-17, FR-52, FR-50 (supported browsers)
- `doc/architecture-spine.md` AD-19
- `doc/architecture.md` section 6
- `doc/decisions.md` D26, D107, D122, D139
- `spikes/browser-device-key/web/` (pages, `static/common.js` probes, `control.html`)
