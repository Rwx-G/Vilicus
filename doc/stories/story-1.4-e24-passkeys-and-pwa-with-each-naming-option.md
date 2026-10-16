---
title: 'E24: passkeys and PWA with each naming option'
epic: 1
story: 4
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E24, FR-65, FR-4, D51, D76, D107, NFR-9]
---

# Story 1.4: E24: passkeys and PWA with each naming option

As the owner,
I want passkeys and PWA installation tested on every supported browser with each documented naming option,
So that the documentation only offers naming and certificate options that work, and the bootstrap order is confirmed.

**Acceptance Criteria:**

**AC1 (E24, FR-65, D51, NFR-9)**
**Given** three test instances under placeholder names: a free dynamic DNS subdomain with a DNS-01 certificate, a private-network name with its certificate, and a local certificate authority installed on each device
**When** passkey registration, passkey login and PWA installation run on current and previous Chrome and Firefox, desktop and Android (Safari best effort)
**Then** a result is recorded for every browser and naming option pair, with no real hostname, address or device model in the record

**AC2 (E24, FR-4, D76)**
**Given** a page served over a temporary self-signed certificate on a private address
**When** a WebAuthn registration ceremony is attempted from each supported browser
**Then** the record states whether the browser refuses it or binds the credential to a host that becomes unusable once the instance name exists
**And** either outcome confirms that the D76 order (no WebAuthn before the instance name) is required, and the order does not depend on it

**AC3 (E24, FR-65)**
**Given** a naming option fails on a supported browser
**When** the result is recorded
**Then** that option is marked for removal from the documentation in `doc/research-notes.md`, and the bootstrap order of D76 is unchanged

**Spike plan:**
- Question: which naming options support passkeys and PWA installation on each supported browser, and is WebAuthn over the temporary self-signed certificate refused or unusable (E24)?
- Method: three test instances under placeholder names, a browser matrix, a self-signed ceremony attempt.
- Pass criterion: a complete matrix; every naming option kept in the documentation works on every supported browser.
- Timebox: 5 working days.
- Fallback on failure: a naming option that fails is removed from the documentation; the bootstrap order of D76 does not change.
- Result record: matrix in `doc/research-notes.md` (E24 status moved per its section 5); a decision record for each option removed.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3.1 (E24)
- `doc/prd.md` FR-4, FR-65, section 9
- `doc/decisions.md` D51, D76, D107
- `doc/architecture-spine.md` AD-52, AD-19
- `doc/architecture.md` section 15

## Implementation Notes

**What was built.** A standalone crate, `spikes/naming-options/` (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`), and a Docker Compose test bed driven by `run.sh`:

- `src/`: one HTTPS test instance per process. `rp.rs` builds the relying party from `E24_ORIGIN`, with the origin's host as RP ID, as Vilicus does with the instance name (D51); `server.rs` serves a page, a web app manifest, a pass-through service worker, two PNG icons (`png.rs`, a minimal encoder so no image crate is needed) and the passkey registration and login routes of webauthn-rs, over rustls (ring provider, HTTP/1.1). Test users are keyed by name (the driver uses one per browser, and one more for two passkeys of one user), and the request bodies use `deny_unknown_fields`. When webauthn-rs refuses the origin as a relying party (an IP address), the page is still served and the ceremony routes answer 503 with the library's reason.
- `site/app.js`: the browser half. `register` and `login` run the server ceremonies; `probeCreate` runs a creation ceremony with client-side options and the default RP ID (used where the server cannot be a relying party, and over the self-signed certificate), checks the `rpIdHash` of the authenticator data against the page's host, and can abort a ceremony still waiting after a delay; `probeGet` asserts given credential IDs, with an optional explicit RP ID; `probeAllowLists` asserts with allow lists of one and two credentials, timed; `pwa` reports the secure context, the manifest fetch and the service worker activation.
- `compose/compose.yaml`: three internal networks (no internet). `wan` (198.51.100.0/24) stands in for the internet, with `public-dns` answering for the dynamic DNS zone with the host's private address. `lan` (10.88.0.0/24) is the household network: `router` is the home router's resolver (dnsmasq, rebinding protection with an exception for the dynamic DNS zone), which knows nothing of the overlay, and `lan-client` is a device on the LAN only. `overlay` (100.64.88.0/24, the shared address space mesh VPNs use) carries the private-network instance and `overlay-dns`, the overlay client's resolver on a joined device, which answers for the overlay zone and forwards every other name to the router; the browsers are a joined device and use it. `router-strict`, on every network, has rebinding protection and no exception. Test instances: `household.dyn.example`, `household.tailnet.example`, `vilicus.home.arpa`, `vilicus.local`, `https://10.88.0.24` (valid local CA certificate on an IP address), the self-signed instance (`https://10.88.0.25`, `host01.home.arpa`, and `localhost` through a port forward inside the browser container), and `same.home.arpa`, served with a self-signed certificate on port 8443 and with its real certificate on port 443 (the RP ID ignores the port, so this is the case where the temporary certificate names the instance name).
- `compose/certs.sh`: two test authorities, a "stand-in public CA" and a "local CA", plus the self-signed certificates. Leaves are P-256, 90 days, with `serverAuth`.
- `compose/browsers.Dockerfile`: the official Playwright image `v1.64.1-noble` pinned by digest, plus the vendors' own builds, each pinned by SHA-256: Chrome for Testing 155.0.8059.84 (Chrome stable on 2026-10-16) and 154.0.8037.97 (previous stable), Firefox 158.0 (current release) and 157.0.1 (previous release; Mozilla's `SHA256SUMS` list the same hashes), and geckodriver 0.37.1. Playwright's own builds were not used: its Chromium is 156, ahead of stable, and its Firefox carries Playwright's patches.
- `compose/driver.mjs`: runs every option in one browser and prints `PLAN <n>`, one `PASS` or `FAIL` line per declared check, `INFO` evidence lines and `ROW` lines for the matrix. Chrome is driven by Playwright over CDP with a persistent profile (an off-the-record context reports `in-incognito`), the CDP virtual authenticator and `Page.getInstallabilityErrors`; Firefox by geckodriver over WebDriver with the WebDriver virtual authenticator, which answered only with `security.webauth.webauthn_enable_softtoken` set. Both test roots are added to each browser's own NSS database. Certificate warnings are passed the way a person does: Chrome's interstitial "Advanced" then "Proceed"; Firefox's warning page "Advanced" then "Accept the Risk and Continue" (in the shadow root of `<net-error-card>` in Firefox 157 and 158). Each self-signed target starts with a fresh virtual authenticator: Chrome's stopped creating credentials partway through a run (cause not established), which the positive control caught.
- `run.sh`: cargo gates in `rust:1.99-trixie` pinned by digest (build, `fmt --check`, `clippy -D warnings`, tests, and a count check: every `#[test]` and `#[tokio::test]` must pass, none ignored), then the test bed, the DNS and reachability checks, the four browsers, the server-side evidence, the matrix, `RESULT PASS` or `RESULT FAIL`. It removes its compose project on exit and exits non-zero on any `FAIL`, on a driver that does not print exactly its planned number of checks, or on a driver error.
- Tests: 10 Rust tests (3 in `png.rs`, 2 in `rp.rs`, 5 in `server.rs`). Two passkeys for one user are tested end to end through the server (webauthn-rs builds the allow list) by the driver, not by a Rust unit test, because a `Passkey` can only come from a real registration.

**Dependencies (exact versions from `Cargo.lock`).** webauthn-rs 0.5.5 (webauthn-rs-core 0.5.5, openssl 0.10.81), axum 0.8.9, hyper 1.12.0, hyper-util, tokio, tokio-rustls 0.26.6 (rustls 0.23.46, ring provider), serde, serde_json; dev: tower 0.5 (already in axum's tree). Test tooling outside the crate: Playwright 1.64.1, geckodriver 0.37.1, dnsmasq 2.91 and openssl from Debian 13.

**Deviations and limits.**

- Desktop Linux builds only. Android (Chrome and Firefox), Windows and macOS desktops, and Safari were not run: see "Not run here" under Result.
- Virtual authenticators, not real ones. A virtual authenticator changes what Chrome allows (finding 2), so each refusal or acceptance below says which authenticator it came from, and Chrome's behaviour without one is a separate check.
- One trust path for every row. The "stand-in public CA" and the local CA are both user-added roots in the browser's NSS database. A real public root differs: it is built in, and Chrome requires Certificate Transparency for it while it does not for a locally added root (Chrome's documented policy, not tested here). So the dynamic DNS and private-network rows test the name, the resolution path and the RP ID, not public trust or CT; and the run cannot show that the household's name appears in public CT logs, which any public certificate does.
- `.local` is resolved by unicast DNS here, never by mDNS: the `.local` row says nothing about mDNS resolution on each device.
- Installation is measured on Chrome only (`Page.getInstallabilityErrors`). On Firefox for Linux desktop it is not measured; its page signals (secure context, manifest, active service worker) are recorded.
- Beyond the three options of FR-65, the run adds rows that the documentation must not offer, to show why: `.local` (mDNS dependent), an IP address with a valid certificate, and four self-signed targets.

**Open decision tasks settled.** The story names none explicitly; the spike settles the ones its result forces, with the recommended answer:

1. **Naming options kept in the documentation: all three of FR-65**, each with the conditions found here (tasks 4 and 5). Each passed passkey registration, login and Chrome installability on every browser run. None is marked for removal (AC3 not triggered). What it gives up: Android, real authenticators and a real public CA are still to run.
2. **The RP ID is the full instance name (a recommendation, not tested against a parent domain).** Under a dynamic DNS provider's zone the parent is usually a public suffix, and an overlay network's zone belongs to its provider. No probe set `rp.id` to a parent domain.
3. **An IP address is never offered as the instance name, even with a valid certificate.** Every browser refused WebAuthn on an IP origin, webauthn-rs refuses an IP address as RP ID, while Chrome still reported the page installable.
4. **Dynamic DNS and rebinding protection.** When the dynamic DNS record holds the host's private address, a resolver with rebinding protection drops the answer (dnsmasq `--stop-dns-rebind`); the household needs an exception for that name, or a public record with NAT loopback (not reproduced). The same dnsmasq protection let an overlay answer in 100.64.0.0/10 through: that range is not in its rebinding list, so the private-network option is not affected by it (other router resolvers may differ; not tested). This joins E28's "resolvers that block private answers".
5. **Private-network name: every device joins the overlay.** A LAN-only device neither resolves the overlay name (the home router does not know it) nor reaches the instance. Each household device then runs the overlay client; on Android that client takes the single VPN slot, which D60's WireGuard tunnel also needs, so a phone cannot hold both at once (reasoned from D60, not tested).
6. **The temporary certificate carries IP SANs only (proposal).** A credential made over the temporary certificate is unusable on the instance name only when the temporary name differs from it: with the virtual authenticator, Chrome's credential made on `same.home.arpa:8443` (self-signed) worked on `same.home.arpa` (real certificate). Chrome without a virtual authenticator refuses both, but on the same host it then also refuses the real certificate for the rest of the browser session (finding 5). A temporary certificate with only IP SANs leaves no name for a ceremony: every browser refuses WebAuthn on an IP origin.
7. **D76 order unchanged.** AC2 below confirms it is required; nothing makes it depend on a browser's choice.
8. **Two passkeys for one user: an open item.** Firefox's virtual authenticator refused every assertion whose allow list named two credentials (own and own, matching first, matching second, and the server's login for a user with two passkeys), while Chrome's accepted all of them. Attributed to the test token, not established for a real authenticator. Recommended: an open item that blocks the E24 gate of V0.1 until Firefox is tested with a real authenticator and a user with two passkeys.

## Result

Command, from the repository root on the Windows development host with Docker Desktop: `bash spikes/naming-options/run.sh`. Run of 2026-10-17 (after review): exit code 0, 199 `PASS` and 0 `FAIL` lines, `RESULT PASS`. Cargo stage: rustc 1.99.1, `build`, `fmt`, `clippy`, the 10 tests one line each, `test_count` (10 passed, 0 ignored, 10 expected). DNS and reachability stage: 13 checks. Browser stage: 48 checks in each Chrome and 36 in each Firefox (Chrome adds `installable` and the two checks without a virtual authenticator), each followed by its `check_count` line. Earlier runs printed `FAIL` lines and exited 1 (an off-the-record Chrome context reported `in-incognito`; Firefox logins failed while the server listed every browser's passkeys in one allow list; the positive control failed until each target got a fresh authenticator, finding 6), which shows the failure path works. The run of 2026-10-16 before review (141 `PASS`) had no positive control and no same-name or `localhost` target; its AC2 claims are superseded by this one.

**Matrix** (`passkey`: server registration and login with webauthn-rs, virtual authenticator; `install`: Chrome's `Page.getInstallabilityErrors` empty; `not measured`: Firefox on Linux desktop; `virtual`: outcome with the virtual authenticator; `no authenticator`: Chrome from a tab, in a second profile, with no virtual authenticator):

| Option | Chrome 155 | Chrome 154 | Firefox 158 | Firefox 157 |
|---|---|---|---|---|
| Dynamic DNS name, stand-in public CA (`dyndns`) | passkey ok, install ok | passkey ok, install ok | passkey ok, install not measured | passkey ok, install not measured |
| Private-network name, stand-in public CA, overlay device (`private-network`) | passkey ok, install ok | passkey ok, install ok | passkey ok, install not measured | passkey ok, install not measured |
| `home.arpa` name, local CA (`local-ca`) | passkey ok, install ok; allow lists of two ok | passkey ok, install ok; allow lists of two ok | passkey ok, install not measured; allow lists of two `NotAllowedError` | passkey ok, install not measured; allow lists of two `NotAllowedError` |
| `.local` name, local CA (`local-ca-dot-local`) | ok (unicast DNS, not mDNS) | ok (unicast DNS, not mDNS) | ok (unicast DNS, not mDNS) | ok (unicast DNS, not mDNS) |
| Private IP address, local CA (`local-ca-ip`) | refused, `SecurityError` | refused, `SecurityError` | refused, `SecurityError` | refused, `SecurityError` |
| Self-signed, private IP address (`selfsigned-ip`) | virtual refused `SecurityError`; no authenticator refused `SecurityError` | same | virtual refused `SecurityError` | same |
| Self-signed, LAN name differing from the instance name (`selfsigned-name`) | virtual: created, bound to the temporary host, unusable on the instance name; no authenticator: refused (TLS certificate errors) | same | virtual refused `SecurityError` | same |
| Self-signed, same name as the instance (`selfsigned-same-name`) | virtual: created and usable on the instance name; no authenticator: refused (TLS certificate errors), on the real certificate too | same | virtual refused `SecurityError` | same |
| Self-signed, `localhost` (`selfsigned-localhost`) | virtual: created, bound to `localhost`, unusable on the instance name; no authenticator: accepted (waited for an authenticator) | same | virtual: created, bound to `localhost`, unusable on the instance name | same |

**AC1: PASS for the desktop Linux half; Android and Safari not run.** Each named option passed `tls`, `secure_context`, `pwa_signals`, `register` (`rp_id` equals the option's host) and `login` (the same credential), and on Chrome `installable`, on Chrome 155 and 154 and Firefox 158 and 157. The record holds only placeholder names and documentation or private addresses, and no device model.

**AC2: PASS. Every browser refuses, or binds the credential to a host that becomes unusable, under the condition of settled task 6.** Each self-signed target has: `cert_rejected` (the first load is refused), `positive_control_on_instance` (the same browser and a fresh authenticator create a credential on the instance name, so a later refusal is not a broken authenticator), `virtual_authenticator_outcome` (an outcome counts as a refusal only with `SecurityError`; "unusable" requires the credential to fail on the instance name and still work back on its own host), and on Chrome `no_authenticator_outcome` and `no_authenticator_on_instance` (a refusal must carry the expected message within 1 s; "accepted" must wait at least 2.5 s, which is also the control that such a tab can tell a refusal from a timeout).

- Private address: every browser refused before any authenticator was involved (Chrome `This is an invalid domain.`, Firefox `The operation is insecure.`), with or without a virtual authenticator.
- LAN name differing from the instance name: Firefox refused (`SecurityError`). Chrome without a virtual authenticator refused within 10 ms with `WebAuthn is not supported on sites with TLS certificate errors.`, while the same kind of tab on the instance name waited; with the virtual authenticator Chrome created a credential bound to `host01.home.arpa`, not found on the instance name, refused there with an explicit `rpId` (`SecurityError`), and still usable back on `host01.home.arpa`.
- Same name: Firefox refused. Chrome without a virtual authenticator refused, and kept refusing on the real certificate of the same host in that profile (finding 5). With the virtual authenticator the credential was usable on the instance name: "unusable" holds only because the temporary name differs from the instance name (settled task 6).
- `localhost` (a port forward to the wizard): both browsers ran the ceremony over the self-signed certificate (Chrome without a virtual authenticator accepted and waited; Firefox with its virtual authenticator created the credential). The credential is bound to `localhost` and unusable on the instance name. `localhost` can never be an instance name, so the D76 order still holds, but "browsers refuse WebAuthn over the self-signed certificate" is false on `localhost`.
- Either outcome confirms that D76's order is required, and the order does not depend on which one a browser takes.

**AC3: not triggered.** No documented option failed on a browser run here; none is marked for removal in `doc/research-notes.md`, and no decision record of removal is needed. D76 is unchanged. The open item of settled task 8 is not a failure of an option, but it holds the E24 gate.

**DNS and reachability checks (all PASS).** `router` resolves the dynamic DNS name to its private address through its exception; `router-strict` returns no address and logs `possible DNS-rebind attack detected: household.dyn.example`; the overlay resolver answers the overlay name and forwards LAN names; the home router does not know the overlay name; a LAN-only client neither resolves the overlay name nor reaches the overlay instance; `router-strict` passes the 100.64.0.0/10 answer; the `home.arpa`, `.local`, temporary and same names resolve on the LAN.

**Other findings.**

- Finding 1: after passing the warning, Chrome reports a secure context but refuses the service worker and reports `not-from-secure-origin`; Firefox registered it. Nothing is installed before the instance name exists.
- Finding 2: the CDP virtual authenticator lets Chrome run a ceremony on a page with a certificate error that Chrome otherwise refuses. The CI run of UJ-1 with a virtual authenticator (spine AD-33) cannot show this refusal.
- Finding 3: Firefox's WebDriver virtual authenticator refused every allow list of two credentials (settled task 8), immediately rather than after a timeout (the timings are in the run's `allow_list_of_two` line).
- Finding 4: Chrome reported the IP-address origin installable while refusing WebAuthn on it.
- Finding 5: after a person passes Chrome's warning for a host, Chrome refuses WebAuthn on that host even once it serves a valid certificate, for the rest of the browser session (seen in a fresh profile without a virtual authenticator). If the temporary certificate named the instance name, the instance admin's passkey enrollment could fail in the browser that ran the wizard.
- Finding 6: Chrome's CDP virtual authenticator stopped creating credentials partway through a run (every creation returned `NotAllowedError`) until it was replaced; cause not established.

**Not run here, with the manual procedure.** Real devices are a release check (the manual run of spine AD-33). For each of the three options, on one Android phone (Chrome current and previous, Firefox current and previous), one Windows desktop and one other desktop available (Chrome, Firefox; Safari best effort):

1. Dynamic DNS with a public certificate: register a free dynamic DNS subdomain, issue a DNS-01 certificate from a public ACME CA with an external client, point the record at the host's private address; on the household router, check whether the name resolves inside the LAN (rebinding protection) and add an exception if not. Check that the name appears in a public CT log search.
2. Private-network name: join the host and the device to the overlay network, enable its name and certificate feature, open the name from the device over the overlay. On Android, note that the overlay client and the WireGuard tunnel of D60 cannot be active together.
3. Local CA: create the CA, issue a certificate for a `home.arpa` name, install the CA on each device (Android: Settings, Security, install a CA certificate; Firefox for Android may trust user CAs only after enabling "Use third party CA certificates"; desktop Firefox may need the CA in its own store; all unverified here).
4. Resolver settings on each device: repeat the option with Android Private DNS set to a strict-mode provider, and with the browser's DNS over HTTPS on; record whether the name still resolves (a public resolver neither knows `home.arpa` names nor the overlay zone, and may drop private answers).
5. On each pair: open the instance, register a passkey with the device's own authenticator, log out, log in; install the web app (Android: "Install app"; Windows: Chrome's install icon, and Firefox's own install where offered), then launch the installed app from the home screen or start menu and check that it opens standalone, on the instance name, and logs in; register a second passkey for the same user on another authenticator and log in with an allow list naming both (settled task 8).
6. AC2 on each browser: open the wizard address with the self-signed certificate, by IP address and by `localhost` through a port forward, pass the warning, run a creation ceremony; record whether it is refused.

Record per pair: pass or fail, browser version and OS version, without the device model or any real name or address.

## Proposed design document updates

- `doc/research-notes.md`, section 3.1, E24 row, Status: from "To test" to "Partly verified (desktop Linux, virtual authenticators, test roots; story 1.4, `spikes/naming-options/run.sh`, 2026-10-16); Android, Safari, real authenticators, a real public CA and two passkeys per user on Firefox to test". Section 5 asks for a link to the result: this story's Result.
- `doc/research-notes.md`, section 3.1, a note after the table: "E24 desktop result (story 1.4), with virtual authenticators and user-added test roots: the three FR-65 options passed passkey registration and login on Chrome 155 and 154 and Firefox 158 and 157, and installability on Chrome (not measured on Firefox for Linux). Over the temporary self-signed certificate, every browser refused WebAuthn on a private IP address; on a LAN name, Firefox refused, and Chrome without a virtual authenticator refused with `WebAuthn is not supported on sites with TLS certificate errors`; on `localhost`, both browsers ran the ceremony, binding the credential to `localhost`."
- `doc/research-notes.md`, section 4, a new open question: "Whether the private-network naming option fits FR-4 and FR-6: its addresses are usually in 100.64.0.0/10, which is not in FR-6's list of private interfaces, so the bootstrap wizard refuses a peer on the overlay (FR-4) and listening on the overlay address needs `--acknowledge-public-exposure` on every such install (FR-6); adding the range to the list would also cover carrier-grade NAT space (E24)." **open**.
- `doc/research-notes.md`, section 4, a new open question: "Whether Firefox with a real authenticator accepts an allow list of two credentials; its WebDriver virtual authenticator refused every such list (E24). Blocks the E24 gate of V0.1." **open**.
- `doc/prd.md`, FR-65, consequence on the no-cost options, append: "The instance name is a DNS name, never an IP address: browsers refuse WebAuthn on an IP origin even with a valid certificate (E24). A certificate from a public CA, which the dynamic DNS and private-network options use, is published in Certificate Transparency logs, so the instance name becomes public. With a dynamic DNS record holding the host's private address, the documentation warns that router DNS rebinding protection may drop the answer and says how to add an exception. With a private-network name, every household device joins the overlay network, and on Android the overlay client and the WireGuard tunnel of D60 compete for the single VPN slot."
- `doc/prd.md`, FR-4, the consequence on the temporary self-signed certificate, append: "The temporary certificate names only the host's IP addresses, loopback included, never a host name, so no browser keeps a certificate exception for the instance name and browsers refuse WebAuthn on the addresses it names (E24). Reached as `localhost`, browsers do run WebAuthn over it; the wizard serves no ceremony route before the instance name exists, which D76 already requires."
- `doc/architecture.md`, section 15, "Instance name and certificate", after "which of them support passkeys and installation on each browser is tested by E24": "On desktop Chrome and Firefox, with virtual authenticators and test roots, all three passed (E24, story 1.4); installation was measured on Chrome only."
- `doc/architecture-spine.md`, AD-52, replace "(E24 confirms)" with "(E24, desktop: browsers refuse WebAuthn on an IP origin, which is all the temporary certificate names; on `localhost` they do not, and a credential made there is bound to `localhost`)". This wording rests on the checks `no_authenticator_outcome` and `virtual_authenticator_outcome`, which exist in the spike.
- `doc/architecture-spine.md`, AD-33, after the sentence on UJ-1 to UJ-3 with a virtual authenticator: "A negative test of the bootstrap order runs the ceremony from a browser profile without a virtual authenticator, because Chrome's CDP virtual authenticator bypasses Chrome's refusal on certificate errors (E24)."
- No new decision record is needed: no option is removed and D76 is unchanged. If a real-device run fails an option, its removal is a new decision record amending D51; the temporary certificate's IP-only SANs, if adopted, are a new decision record amending D76.
