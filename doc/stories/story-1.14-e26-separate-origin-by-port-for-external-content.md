---
title: 'E26: separate origin by port for external content'
epic: 1
story: 14
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E26, AD-19, FR-17, FR-52, NFR-9]
---

# Story 1.14: E26: separate origin by port for external content

As the owner,
I want the port-based separate origin for sandboxed external content tested with each naming option and with reverse proxies,
So that external content is rendered in isolation, or shown only as sanitized plain text.

**Acceptance Criteria:**

**AC1 (E26, AD-19, FR-17, NFR-9)**
**Given** a prototype under `spikes/e26-origin/` serving the client on the instance name and external content from the same name on a separate port, in a script-less sandboxed iframe
**When** it runs with each FR-65 naming option (placeholder names) on current and previous Chrome and Firefox, desktop and Android (Safari best effort)
**Then** the iframe renders, cannot run script, and cannot reach the client's origin

**AC2 (E26, AD-19, FR-52)**
**Given** the content origin's CSP forbids every subresource and every form
**When** a hostile test page tries images, styles, fonts, frames, forms and links that auto-load
**Then** every attempt is blocked and reported

**AC3 (E26, AD-19)**
**Given** the same setup behind a reverse proxy terminating TLS for both ports
**When** the tests of AC1 and AC2 run again
**Then** results are recorded per proxy configuration
**And** if a port-based origin is not workable, the fallback (sanitized plain text, never HTML) is recorded in `doc/decisions.md`

**Spike plan:**
- Question: does a separate origin by port work for sandboxed external content with each naming option and with reverse proxies (E26)?
- Method: prototype client and content origin; browser and naming option matrix; hostile page; reverse proxy runs.
- Pass criterion: isolation and CSP blocking hold on every supported browser with every naming option kept in the documentation.
- Timebox: 3 working days.
- Fallback on failure: external content shown as sanitized plain text, never as HTML.
- Result record: E26 status in `doc/research-notes.md`; a decision record if the fallback is taken.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3.1 (E26)
- `doc/architecture-spine.md` AD-19
- `doc/architecture.md` section 6 (content security policy)
- `doc/prd.md` FR-17, FR-52, FR-65, section 9

## Implementation Notes

**What was built** (`spikes/separate-origin/`, a standalone crate: its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`, `#![forbid(unsafe_code)]`). One binary plays every server of an internal Docker network:

- `gateway`: the Gateway stand-in. For each instance name it serves the client origin on 443 and the external-content origin on 8443 (same name, separate port), over TLS itself (rustls, certificate by SNI) for the `direct` names, and over plain HTTP on 8080 and 8081 for the names behind a reverse proxy. A listener serves only its own role and only the names bound to its transport (`421` otherwise). The plain listeners trust the Host header; a product Gateway binds them to loopback or accepts only the configured proxy (comment in `src/main.rs`).
  - Client origin: a page whose CSP is `default-src 'none'`, `script-src 'self' 'nonce-<per response>'`, `frame-src https://<name>:8443`, `frame-ancestors 'none'`, `base-uri 'none'`, `require-trusted-types-for 'script'`, `trusted-types lit-html`, with `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, COOP and CORP. Its nonce script checks Trusted Types, logs in, records any `postMessage` without acting on it, and creates the iframe with `sandbox=""`. A script without the nonce is part of the page and must not run.
  - Session cookie: `__Host-vilicus_session=<random>; Path=/; Secure; HttpOnly; SameSite=Strict` (host-only by the `__Host-` prefix).
  - API: `GET /api/state` and `GET /api/probe/*` are read-only; `GET /api/action` answers 405; `POST /api/action` changes state only with a valid session and an `x-vilicus-signature` header (the stand-in for the AD-21 signature). The routes are one table (`APP_ROUTES`); a GET or HEAD route reaches only a handler that receives a read-only snapshot. The unit test iterates the table for GET and HEAD, asserts that no such request reaches a POST route, and compares the session set itself before and after.
  - Content origin, production configuration: the hostile markup (head and body together, as a mail body arrives) goes through the allowlist sanitizer (`src/sanitize.rs`, `ammonia` 4.2.4) and is placed in the Gateway's own document shell, served with `default-src 'none'` and every fetch directive, `form-action` and `base-uri` set to `'none'`, `frame-ancestors https://<name>`, the `sandbox` directive, `report-uri /csp-report` (test instrument, see update 3), plus `X-DNS-Prefetch-Control: off`. No content response carries `Set-Cookie` (unit test over every mode and fixture, browser check per name).
  - Sanitizer rules: kept elements are inert presentational ones only (text structure, lists, tables, inline emphasis, `a` without any attribute); kept attributes are `lang`, `dir` and table `colspan`, `rowspan`, `scope`; `script`, `style`, `template`, `noscript` and `title` are dropped with their content; everything else (`link`, `meta`, `base`, forms, frames, `object`, `embed`, media, images, SVG) is dropped; no URL scheme is allowed, so no `href`, `src`, `srcset`, `poster`, `background`, `xlink:href`, `style` or event-handler attribute survives; comments are stripped. Unit test: every fixture and every vector comes out without a URL, a resource element, a style or a handler.
- `sink`: the attacker's site, every name under `attacker.example`; logs every TLS handshake (SNI) and request. `dns`: the network's own DNS server; logs every query. `pki`: one CA per naming option, one leaf per instance name, never regenerated under running servers.
- `network/instances.txt` is the single layout read by the PKI, the DNS server, the Gateway and the harnesses. Each server has a test-only control listener (`/log`, `/state`, `/catalogue`); the harnesses derive the vector list, the fixtures, the cookie name and the expected content CSP from `/catalogue`.

**Naming options (placeholders, FR-65).** Free dynamic DNS subdomain with a DNS-01 certificate: `house-<deployment>.dyndns.example` (certificate from a "public CA stand-in"). Private-network name: `vilicus-<deployment>.home.arpa`. Local certificate authority: `vilicus-<deployment>.internal`. Each name exists for three deployments: `direct`, `caddy` (Caddy 2.11.7) and `nginx` (nginx 1.31.7), both proxies terminating TLS on 443 and 8443 and forwarding each port to the Gateway's matching plain listener. The browsers trust the three CAs through NSS; no certificate check is skipped.

**Browsers.** Two official Playwright images pinned by digest, labelled by their position: `v1.64.1-noble` ("current": Chromium 156.0.8078.4, Firefox 157.0) and `v1.63.0-noble` ("previous": Chromium 153.0.8010.12, Firefox 155.0), all headless, driven by `harness/harness.mjs` through every mode. Mozilla's own builds, Firefox 158.0 (the release on 2026-10-16) and 157.0.1, pinned by SHA-256 as in `spikes/naming-options` and driven over WebDriver by geckodriver 0.37.1 (`harness/branded.mjs`), rerun the passive fixtures in production and in the unsanitized control on all nine names.

**Harness.** Each visit loads the client page with a fixture, a mode and a fresh run id; every hostile URL names the run and the vector (`<run>-<vector>.attacker.example`), so the logs attribute each request, handshake and query to one attempt. Modes:

- `prod`: the production configuration (sanitizer, CSP, sandbox), on all nine names.
- `unsanitized`: the same CSP and sandbox without the sanitizer, on all nine names: the control that shows what the sanitizer adds.
- Controls on the first direct name: `open` (no CSP, permissive sandbox, client `frame-src https:`) proves each detector fires; `sandbox-only` (production sandbox, no CSP, no sanitizer) is the per-browser baseline of what is attempted at all; `scripts` (sandbox `allow-scripts` only) runs the isolation probes; `csp-only` (CSP without the sandbox directive) and `inline-style` (CSP with `style-src 'unsafe-inline'`) are ablations; `sandbox_layer` replays the navigation fixtures unsanitized with the client's `frame-src` relaxed; `only-<vector>` fixtures serve one vector alone; `passive-nolink` is the passive fixture with every `<link>` element removed (a fixture change, not the sanitizer).
- A check on a visit whose content did not render fails (`rendered.*`). A vector the browser never attempts even without CSP passes as "vacuous" and says so. A cookie jar that cannot be read fails the checks that need it (`cookie_jar_read`).
- CSP reports are recorded as INFO only (`reported.*`, and one `csp_report` line per report of the run, whatever origin received it): a browser may block a speculative load without reporting it.
- Requests the content starts toward the client API are checked: cookieless and `cross-site` in every sandboxed mode, `same-site` with the cookie in the `csp-only` ablation.
- Firefox 155 under Playwright 1.63 sometimes never reaches DOMContentLoaded on the client page (30 s); the harness then restarts that browser on the same profile and retries the visit once more with a new run id (at most twice), and prints each retry. In the recorded run, 13 Firefox 155 loads were retried once and all succeeded; no other browser needed a retry.

**`run.sh`** runs fmt, clippy (`-D warnings`), the release build and the tests (fails on an ignored test or a count other than 43) in `rust:1-trixie` pinned by digest; brings up the compose project `vilicus-e26`; checks the API's side-effect rules from the network (`api.*`); runs the six harnesses in parallel and fails a harness whose PASS plus FAIL count differs from its expected count (1110 Playwright, 558 branded). A FAIL whose check is listed in `known-findings.txt` prints `KNOWN-FAIL <check> <finding>`; a listed check that passes, a listed check not run, and any other FAIL fail the run. It ends with `RESULT PASS` or `RESULT FAIL`, exits non-zero on failure, and removes the compose project and its volumes. `shellcheck` is clean.

**Dependencies** (spike crate only). `tokio` 1.53.2, `hyper` 1.12.0, `rustls` 0.23.45 (aws-lc-rs), `tokio-rustls` 0.26.6 at the spine's pins; `hyper-util` 0.1.21 and `http-body-util` 0.1.5 (MIT); `rcgen` 0.14.10 (test PKI only); `ammonia` =4.2.4 (MIT OR Apache-2.0, html5ever parser), approved by the owner on 2026-10-17 for this spike. Images: `rust:1-trixie`, Playwright 1.64.1 and 1.63.0, Firefox 158.0 and 157.0.1 with geckodriver 0.37.1, `caddy:2-alpine`, `nginx:1-alpine`, all pinned by digest or SHA-256.

**Decision tasks.** The story names none explicitly. Choices the spike had to make, settled with the recommended answer:

- Content port: 8443, a named constant; the externally visible ports are exactly 443 and 8443 on every access path, because the client's `frame-src` and the content's `frame-ancestors` are derived from them. What it gives up: a host where 8443 is taken must free it or front Vilicus with a proxy that exposes 8443.
- Sanitize, then sandbox: the sanitizer closes what CSP cannot (finding 2); CSP and the sandbox stay the enforcement layers. What it gives up: rich mail formatting, images and in-place links.
- Content `style-src 'none'`, and `style` attributes stripped: allowing inline style does not reopen CSS exfiltration (`inline-style` ablation), so this is a fidelity choice. What it gives up: unstyled mail bodies.
- Links: the sanitizer strips `href` and `xlink:href`, and the client's `frame-src` limited to the content origin blocks every navigation of the iframe; the client lists the content's links outside the iframe with their full destination. What it gives up: no in-place link of any kind.
- `report-uri` is dropped from the production content CSP: reports are incomplete (finding 5) and an unauthenticated endpoint receiving them needs rate limiting and truncation. What it gives up: violation telemetry from content documents.
- The reverse proxy must forward the Host header with its port (nginx: `$http_host`, not `$host`).

**Deviations.**

- Location: the story names `spikes/e26-origin/`; the spike lives in `spikes/separate-origin/`, as the epic's spike instructions asked.
- The Playwright browsers are Playwright's builds (Chrome for Testing and Playwright's patched Firefox) with Playwright's launch flags; their labels "current" and "previous" name the two Playwright releases, not consumer releases. Mozilla's Firefox 158.0 and 157.0.1 reran the passive fixtures; branded Chrome and Chrome 155/154 were not run in this spike.
- The "public CA stand-in" must be installed in the test browsers, whereas a real DNS-01 certificate is trusted by default.

**Findings.**

1. **The port-based origin with the sanitizer holds on every tested browser, naming option and proxy.** In production no script, inline handler, `javascript:` link, form, popup, top navigation, meta refresh, `<base>`, `postMessage`, subresource (images, `srcset`, `<picture>`, `input type=image`, posters, media, `<object>`, `<embed>`, frames, `data:` frames, stylesheets, `@import`, style `url()`, CSS attribute-selector exfiltration, `@font-face`, font preload, prefetch, modulepreload, external script), preconnect, DNS prefetch, probe of the client API or state change reached any server, on Chromium 156 and 153, Playwright Firefox 157 and 155, and Mozilla's Firefox 158.0 and 157.0.1. Results are identical across naming options and deployments: both origins share the host, so the certificate and the same-site relation do not depend on the naming option.
2. **Without the sanitizer, Firefox preconnects despite CSP.** In the unsanitized control `<link rel="preconnect" href="https://<attacker>">` made Firefox resolve the attacker's name (2 DNS queries per visit, no TCP or TLS connection) on all nine names, in Playwright Firefox 157 and in Mozilla's Firefox 158.0 and 157.0.1; Firefox 155 and both Chromium versions did not preconnect. CSP does not govern preconnect and `X-DNS-Prefetch-Control: off` did not stop it. The sender of a mail would learn through its own DNS server that it was opened. The link-free fixture (`passive-nolink`, unsanitized) made no DNS query, TLS handshake or request at all in any browser, and the sanitized production configuration closed it everywhere: the sanitizer, not CSP, is what closes it. These 27 checks are the known findings of `known-findings.txt`.
3. **The client's `frame-src` is a layer of its own.** It governs every navigation of the iframe: with `frame-src https://<name>:8443`, no link, form, meta refresh or `<base>`-relative link in unsanitized content navigated the frame. With `frame-src` relaxed (`sandbox_layer`), a click navigated the frame to the attacker's page, which stayed sandboxed (its script did not run) but loaded its own images. Meta refresh was blocked by the sandbox alone in all four browsers. Only scripted left clicks were exercised; the sanitizer removes `href` so no click path remains.
4. **The session cookie and same-site.** The iframe's own document request, started by the client page, carried the `SameSite=Strict` cookie with `Sec-Fetch-Site: same-site` on every browser and name, as AD-19 says. Every request the sandboxed content started itself (frame navigation to the API, credentialed fetch, no-cors POST, form POST) was `cross-site` and carried no cookie, because a sandbox without `allow-same-origin` gives the content an opaque origin. Without the sandbox (`csp-only`) the same content-started navigation was `same-site` and carried the cookie. Cookies ignore ports, so the content origin could also set the session cookie: no content response emits `Set-Cookie`.
5. **CSP reports are monitoring only.** The earlier "not reported" failures were refuted as a requirement: served alone, an external `<script src>` and a `<link rel=preload as=font>` were fetched in the sandbox without CSP (Chromium and Firefox: DNS query and request at the sink) and were blocked with CSP; Chromium sent no report for the script to either origin, Firefox none for the font preload, while Chromium did report the font preload. The block is complete; the report is not. Inline script in a script-less sandbox is refused by the sandbox before CSP. With the sanitizer most vectors never reach the browser, so production reports are few.
6. **Isolation with scripts running (`scripts` mode).** Reading the parent DOM, the parent's or its own storage, `document.cookie` and `top.location` threw `SecurityError`; `window.open` returned no window; top navigation was refused; a credentialed fetch could not be read and carried no cookie; a no-cors POST reached the API without a cookie and changed nothing; `postMessage` reached the client with origin `null`, and the client ignored it.
7. **Behind Caddy and nginx** both origins worked with the client's headers and the content CSP unchanged (exact comparison), the content requests arrived on the plain listener from the proxy's address, and the Host header kept its port. nginx needs `proxy_set_header Host $http_host`. Caddy keeps the Host header by default and adds HTTP/3 on both ports.
8. A `javascript:` link inside the framed document did not run in any browser even in the `open` control; the same fixture runs at top level (`control.detector_fires.click-javascript_top_level`). `<meta http-equiv="set-cookie">` was not attempted by any browser even without defences, so its check is vacuous and proves nothing.
9. The `csp-only` ablation now keeps `X-DNS-Prefetch-Control: off` and differs from production by the `sandbox` directive only (unit test compares every other header); the earlier attribution of a DNS prefetch leak to "CSP alone" came from the missing header, not from the missing sandbox.

**Not run here.**

- Android (Chrome and Firefox, current and previous): not run. Procedure: run the compose project on a LAN host with an override that publishes the Gateway's 443 and 8443, Caddy's or nginx's 443 and 8443, the DNS server's UDP 53 and the control port 9000 of the Gateway, the sink and the DNS server; set the phone's Wi-Fi DNS to the host and turn Private DNS off; install `ca-public.crt`, `ca-private-network.crt` and `ca-household.crt` from the PKI volume as user CAs (Firefox for Android also needs its "use third-party CA certificates" setting); open `https://<name>/?mode=prod&fixture=<fixture>&run=<id>` and the same with `mode=unsanitized` for `passive` and each single fixture, then read `http://<host>:9000/log?contains=<id>` on the Gateway, the sink and the DNS server and apply the judgements of `harness/harness.mjs` (no sink request, handshake or DNS query for any `<id>-<vector>` name; no `/api/probe/` request; the iframe document request with the cookie and `same-site`). Chrome for Android can also be driven by Playwright over ADB.
- Safari (best effort): not run, no macOS or iOS host.
- Branded Chrome (155 and 154): not run in this spike; the Chromium results come from Playwright's Chrome for Testing builds.

## Result

Command, from the repository root on any host with Docker (Git Bash on Windows works): `bash spikes/separate-origin/run.sh`. It takes about 30 minutes after the first image build.

Run on 2026-10-17: exit code 0, `RESULT PASS`, 5590 `PASS` lines, 0 `FAIL` lines and 27 `KNOWN-FAIL` lines. The cargo gates passed (`fmt`, `clippy`, `build_release`, `test_count`: 43 passed, 0 ignored), so did `network_ready`, the six `api.*` checks and the six `check_count` lines. The 27 `KNOWN-FAIL` lines are all `<option>.<deployment>.unsanitized.ac2.blocked.preconnect` (finding 2), nine each for Playwright Firefox 157, Mozilla Firefox 158.0 and Mozilla Firefox 157.0.1; no production check failed.

| Criterion (production: sanitizer, CSP, sandbox) | Chromium 156 | Firefox 157 (Playwright) | Chromium 153 | Firefox 155 (Playwright) |
|---|---|---|---|---|
| AC1: iframe renders, cannot run script, cannot reach the client origin (9 names) | **Pass** (306 of 306) | **Pass** (306 of 306) | **Pass** (306 of 306) | **Pass** (306 of 306) |
| AC1: isolation with scripts running (`isolation.*`) | Pass | Pass | Pass | Pass |
| AC2: every attempt is blocked (9 names) | **Pass** (360 of 360) | **Pass** (360 of 360) | **Pass** (360 of 360) | **Pass** (360 of 360) |
| AC2: CSP reports | Monitoring only, recorded as INFO (finding 5) | same | same | same |
| AC3: same results per proxy configuration (`direct`, `caddy`, `nginx`) | **Pass** | **Pass** | **Pass** | **Pass** |
| Unsanitized control (CSP and sandbox only) | Pass | Preconnect DNS lookup on all 9 names (KNOWN-FAIL, finding 2) | Pass | Pass |
| Android Chrome and Firefox | Not run here | Not run here | Not run here | Not run here |
| Safari (best effort) | Not run here | | | |

Mozilla's Firefox 158.0 and 157.0.1 (passive fixtures): production passes on all nine names (no attacker DNS query, handshake, request or API probe, no script beacon); the unsanitized control shows the preconnect lookup on all nine names (KNOWN-FAIL), and the link-free fixture makes no contact.

Evidence, per criterion:

- AC1: `<option>.<deployment>.ac1.*`: `tls_trusted`, `app_csp_strict`, `app_nonce_script_ran`, `app_unnonced_script_blocked`, `app_trusted_types_enforced`, `session_cookie_attributes`, `session_cookie_hidden_from_script`, `content_csp_header`, `content_sets_no_cookie`, `iframe_renders`, `content_request_same_site_with_cookie`, `content_started_requests_cookieless_cross_site`, `no_script_ran`, `blocked.*`, `click-link.stays_sandboxed`, `click-app-get.*`, `no_postmessage`, `no_state_change`, `rendered.*`. Controls: `control.detector_fires.*`, `isolation.*`, `csp_layer.click-app-get.content_started_request_same_site_with_cookie`, `sandbox_layer.*`.
- AC2: `<option>.<deployment>.ac2.blocked.<vector>` for every vector of `src/fixtures.rs` (`PASSIVE`), `ac2.blocked.meta-refresh`, `click-ping`, `click-base`, `form-get`, `ac2.nolink.*`, `ac2.cookie_jar_read`; the unsanitized control as `<option>.<deployment>.unsanitized.ac2.*`; single-vector evidence as `single.<mode>.<vector>.*`. "Every attempt is blocked; CSP reports are monitoring only": reports are printed as INFO `csp_report` lines.
- AC3: `<option>.caddy.ac3.served_via_caddy` and `<option>.nginx.ac3.served_via_nginx`, with the same AC1 and AC2 lines per deployment; no result differs between deployments. The port-based origin is workable, so the fallback (sanitized plain text) is not taken.

## Proposed design document updates

Not applied: this spike does not edit shared design documents. Where a decision is needed it is written as "new decision record"; the number is assigned when it is added.

1. `doc/research-notes.md` section 3.1, E26 row: status "Partly passed", and after the table add: "E26 ran on 2026-10-17 (Story 1.14, `spikes/separate-origin/run.sh`) with Chromium 156 and 153 and Firefox 157 and 155 (Playwright builds) and Mozilla's Firefox 158.0 and 157.0.1, the three FR-65 naming options under placeholder names, directly and behind Caddy and nginx. With external HTML sanitized (`ammonia` 4.2.4) and rendered in an empty sandbox under the content CSP, no script, form, popup, navigation, subresource, preconnect or DNS prefetch reached any server, and requests started by the content were cross-site and carried no session cookie. Without the sanitizer, Firefox 157 and 158 resolve the host of a `<link rel=preconnect>` despite CSP. CSP reports are incomplete and are monitoring only. The fallback is not taken [new decision record]. Android and Safari are pending (Story 1.14, Not run here)."
2. `doc/decisions.md`: add a new decision record and its row in the table. Text: "Context: E26 (Story 1.14) showed that the sandboxed separate origin by port isolates external content on the supported desktop browsers with every naming option and behind reverse proxies, but that Firefox 157 and 158 resolve the host of a `<link rel=preconnect>` in that content despite a CSP that forbids every fetch, which tells the sender that the content was opened; that the client's `frame-src` keeps the iframe from navigating anywhere; and that CSP reports miss some blocked attempts. Decision: keep the port-based origin (E26 fallback not taken). Before serving external HTML, the Gateway sanitizes it with `ammonia` (exact version pinned, 4.2.4 when E26 ran; MIT OR Apache-2.0; approved by the owner on 2026-10-17 and reviewed under D28 like any dependency) with an allowlist: inert presentational elements only (text structure, lists, tables, inline emphasis, `a`), the attributes `lang`, `dir`, `colspan`, `rowspan` and `scope` only, no URL scheme, so no `href` on `a`, no `xlink:href`, `src`, `srcset`, `poster`, `background`, `style` or event-handler attribute; `script`, `style`, `template` and `noscript` dropped with their content; `link`, `meta`, `base`, forms, frames, `object`, `embed`, media, images and SVG dropped; comments stripped. The sanitized fragment is placed in the Gateway's own document shell; the sandbox and the content CSP remain the enforcement layers. The client's `frame-src` lists the content origin only, and the client shows the links of external content outside the iframe with their full destination. The content origin is the instance name on port 8443; the externally visible ports are exactly 443 and 8443 on every access path. The content origin never emits `Set-Cookie` and never relays an upstream response header. The production content CSP carries no `report-uri`; if one is added later, its endpoint is rate limited and truncates reports. Consequences: mail bodies render without images, styles or in-place links; a reverse proxy must expose 8443 and forward the Host header with its port; the Gateway's plain listeners behind a proxy bind to loopback or accept only the configured proxy."
3. `doc/architecture-spine.md` AD-19 rule:
   - Replace "External content is rendered in a script-less sandboxed iframe from a separate origin (same instance name, separate port)." with "External content is sanitized with an allowlist (inert presentational elements only, no URL-bearing, style or handler attribute, no `href` on links), then rendered in an iframe with an empty `sandbox` attribute from a separate origin (same instance name, port 8443) whose responses also carry the CSP `sandbox` directive and `X-DNS-Prefetch-Control: off`, never carry `Set-Cookie` and never relay upstream headers [new decision record]."
   - Replace "That origin is same-site with the client, so the session cookie can accompany its requests: its CSP forbids every subresource and every form, and no GET endpoint of the API has a side effect." with "That origin is same-site with the client, so the session cookie accompanies the iframe's own document request; requests the sandboxed content starts have an opaque origin, are cross-site and carry no `SameSite=Strict` cookie (E26). Its CSP forbids every subresource and every form and carries no `report-uri`, and no GET endpoint of the API has a side effect. The client's `frame-src` lists the content origin only, which also keeps the iframe from navigating elsewhere; links of external content are shown by the client outside the iframe with their full destination. The externally visible ports are exactly 443 and 8443 on every access path."
   - Replace "`[ASSUMPTION]` The port-based origin with each FR-65 naming option and with reverse proxies is tested by E26." with "`[ASSUMPTION]` E26 partly passed: the port-based origin with the sanitizer passed with each FR-65 naming option, directly and behind Caddy and nginx, on desktop Chrome and Firefox; it stays open until run on Android. A reverse proxy terminates TLS on 443 and 8443 and forwards the Host header with its port."
4. `doc/architecture.md` section 6, the content security policy item: replace "External content (mail bodies, imported pages, recipes) is rendered inside a sandboxed iframe served from a separate origin, without scripts." with "External content (mail bodies, imported pages, recipes) is sanitized with an allowlist, then rendered inside an iframe with an empty `sandbox` attribute served from a separate origin (the instance name on port 8443) whose CSP forbids every subresource, script and form; the client's `frame-src` lists that origin only, and the links of the content are shown outside the frame."
5. `doc/prd.md` FR-65, the reverse proxy consequence: append "The reverse proxy terminates TLS for the instance name on ports 443 and 8443, which are the only externally visible ports, and forwards the Host header with its port (spine AD-19)."
6. `doc/prd.md` FR-17: after "external content in a sandboxed separate origin", add "(sanitized first; links shown outside the frame) [new decision record]".
