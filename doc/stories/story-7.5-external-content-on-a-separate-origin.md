---
title: 'External content on a separate origin'
epic: 7
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-17, FR-52, AD-19, E26, UX-DR3, D139, DC-77]
---

# Story 7.5: External content on a separate origin

As a member,
I want content that came from outside the household rendered away from the client's origin,
So that hostile markup in an external record can neither run script nor reach my session.

**Acceptance Criteria:**

**AC1 (FR-17, AD-19, UX-DR3, D139)**
**Given** E26 passed on desktop with the sanitizer (D139) and a reference-module record with `external` free text in the testbed
**When** the member opens it
**Then** it renders in an iframe with an empty `sandbox` attribute served from the same instance name on port 8443, a named constant
**And** that origin's CSP forbids every subresource and every form: `default-src 'none'` with every fetch directive, `form-action` and `base-uri` set to `'none'`, `frame-ancestors https://<instance name>` and the `sandbox` directive, with `X-DNS-Prefetch-Control: off` and no `report-uri`

**AC2 (AD-19)**
**Given** the separate origin is same-site with the client, so the session cookie can accompany its requests
**When** a test issues every GET endpoint from that origin
**Then** no GET endpoint has a side effect

**AC3 (AD-19, D139)**
**Given** a link inside external content
**When** it is displayed
**Then** its full destination is shown by the client outside the iframe, and no link is clickable in place: the sanitizer strips `href` and `xlink:href`, and the client's `frame-src` (Story 7.3 AC7) blocks every navigation of the iframe

**AC4 (E26, UX-DR3, D139)**
**Given** D139 kept the port-based origin, so the E26 fallback (sanitized plain text, no separate-origin listener) is not taken, while E26 is not passed until Android runs
**When** the manual Android procedure of Story 1.14 (Implementation Notes, "Not run here") runs on Chrome and Firefox for Android (gate E26-1)
**Then** its result is recorded in the E26 entry of `doc/research-notes.md`
**And** if it fails there, the fallback is recorded as a decision before V0.1 ships and external content is then shown as sanitized plain text, never as HTML, with no separate-origin listener opened.

**AC5 (D139, DC-77)**
**Given** external HTML (head and body together, as a mail body arrives)
**When** the Gateway serves it
**Then** it first sanitizes it with `ammonia` pinned exactly (4.2.4 when E26 ran, MIT OR Apache-2.0, reviewed under D28 like any dependency) with the allowlist of D139: inert presentational elements only (text structure, lists, tables, inline emphasis, `a`), the attributes `lang`, `dir`, `colspan`, `rowspan` and `scope` only, no URL scheme, so no `href`, `xlink:href`, `src`, `srcset`, `poster`, `background`, `style` or event-handler attribute; `script`, `style`, `template` and `noscript` dropped with their content; `link`, `meta`, `base`, forms, frames, `object`, `embed`, media, images and SVG dropped; comments stripped
**And** it places the sanitized fragment in its own document shell; a unit test runs every fixture and vector of `spikes/separate-origin/src/fixtures.rs` through the sanitizer and finds no URL, resource element, style or handler in the output.

**AC6 (D139, E26)**
**Given** the browser tests of the content origin
**When** they run in production mode (sanitizer, CSP, sandbox) and in the unsanitized control (CSP and sandbox only)
**Then** in production no script, form, popup, navigation, subresource, preconnect or DNS prefetch reaches any server, each hostile URL naming its run and vector (`<run>-<vector>.attacker.example`) so DNS queries, handshakes and requests are attributed
**And** the unsanitized control is kept: Firefox 157 and 158 resolve the host of a `<link rel=preconnect>` despite the CSP and `X-DNS-Prefetch-Control: off`, which shows the sanitizer, not CSP, closes it (gate E26-2); the harness fails when a listed known finding passes, is not run, or when any other check fails.

**AC7 (D139, AD-19)**
**Given** the iframe and the session cookie
**When** requests reach the Gateway
**Then** the iframe's own document request, started by the client page, carries the `SameSite=Strict` cookie as same-site, while every request the sandboxed content starts itself (frame navigation, credentialed fetch, no-cors POST, form POST) is cross-site and carries no cookie
**And** no response of the content origin carries `Set-Cookie` or relays an upstream response header, checked over every mode and fixture, since cookies ignore ports.

**AC8 (D139, FR-65)**
**Given** a deployment behind a reverse proxy
**When** the content origin is reached
**Then** the externally visible ports are exactly 443 and 8443 on every access path, the proxy terminates TLS on both and forwards the Host header with its port (nginx `proxy_set_header Host $http_host`, not `$host`), and the Gateway's plain listeners bind to loopback or accept only the configured proxy
**And** the tests of AC6 pass directly, behind Caddy and behind nginx, with the client's headers and the content CSP unchanged.

**Dependencies:**
- Story 7.3 (web client shell and CSP)
- Story 7.1 (Gateway listeners and reverse-proxy mode)
- Story 1.14 (E26 result; D139)
- Story 3.10 (reference module providing an external record)

**References:**
- `doc/prd.md` FR-17, FR-52, FR-65, DC-77
- `doc/architecture-spine.md` AD-19, Stack (ammonia)
- `doc/decisions.md` D26, D139
- `doc/research-notes.md` E26
- `doc/architecture.md` section 6
- `spikes/separate-origin/` (`src/sanitize.rs`, `src/fixtures.rs`, `harness/`, `known-findings.txt`)
- `doc/qa/gates/1.14-e26-separate-origin-by-port-for-external-content.yml` (E26-1, E26-2)
