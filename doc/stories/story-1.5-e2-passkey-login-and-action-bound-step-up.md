---
title: 'E2 login half: passkey login and action-bound step-up'
epic: 1
story: 5
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E2, D71, D107, D117, FR-10, NFR-9]
---

# Story 1.5: E2 login half: passkey login and action-bound step-up

As the owner,
I want passkey login and a step-up whose challenge derives from an action hash proven with `webauthn-rs` on every supported browser,
So that the authentication epic starts on a library that can carry the one-action binding of D71.

**Acceptance Criteria:**

**AC1 (E2, FR-10, NFR-9)**
**Given** a minimal server on `webauthn-rs` 0.5.5 and a page under `spikes/e2-login/`
**When** passkey registration and login run on current and previous Chrome and Firefox, desktop and Android (Safari best effort)
**Then** every supported browser completes registration and login

**AC2 (E2, D71, FR-10)**
**Given** a pending action whose canonical hash the server computes before the prompt
**When** the server derives the WebAuthn challenge from that hash and the browser completes the assertion
**Then** the server verifies the assertion against that action, and refuses the same assertion presented for a different action hash

**AC3 (E2, D107, D117)**
**Given** AC1 or AC2 fails on a supported browser
**When** the result is recorded
**Then** the failing browser and the library behaviour are recorded in `doc/research-notes.md`, and that browser leaves the supported list before Epic 7 authentication work starts
**And** if every supported browser fails, TOTP (D33) temporarily becomes the primary second factor, and the fallback taken is recorded in `doc/decisions.md`

**Spike plan:**
- Question: does `webauthn-rs` 0.5.5 support passkey login and a step-up whose challenge derives from an action hash on every supported browser (E2, login half)?
- Method: minimal server and page; browser matrix; challenge derivation and cross-action refusal test.
- Pass criterion: passkey login and a step-up whose challenge derives from an action hash (D71) succeed on every supported browser (D107).
- Timebox: 3 working days.
- Fallback on failure (D117): a browser that fails leaves the supported list; if every supported browser fails, TOTP (D33) temporarily becomes the primary second factor, until a supported browser passes.
- Result record: E2 login half status in `doc/research-notes.md` per its section 5, with a link to the test result.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E2) and section 1.1 (WebAuthn library)
- `doc/prd.md` FR-10, section 9 (E2 login half)
- `doc/decisions.md` D33, D71, D107, D117
- `doc/architecture-spine.md` AD-8, AD-13, Stack

## Implementation Notes

Spike code: `spikes/passkey-stepup/`, a standalone crate (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`). AC1 names `spikes/e2-login/`; the spike lives under `spikes/passkey-stepup/` instead, by the instruction that launched this story. Nothing else depends on the path.

What it holds:

- `src/rp.rs`: an in-memory relying party on `webauthn-rs` 0.5.5 (`Webauthn` with the passkey flows, so user verification is required). Passkey registration, login by user name, and a step-up.
  - Login closes the pre-login session and issues a new session identifier.
  - A step-up creates the pending request first and stores its canonical bytes. It then derives the WebAuthn challenge from the request hash and a public handle of the session (AD-8 rule 3). An approval returns the stored canonical bytes, which are what an executor runs; the caller never supplies the action at approval time.
  - Finishing a step-up checks, in this order: a logged-in session; a request of this session (another session's request reads as `unknown_request`, like a request that does not exist); the hash the client presents (`action_mismatch`); single use (`already_used`); expiry (`expired`); the challenge recomputed for the presenting session against the one in the stored state (`challenge_mismatch`); the assertion (`webauthn-rs`: a challenge other than the request's is `challenge_mismatch`, any other refusal `assertion_rejected`); and the signature counter (`counter_regressed`).
  - The counter check is the spike's own. `webauthn-rs` compares the counter with a snapshot taken when the authentication state was created, so two step-ups started together would each accept the same counter value. The relying party keeps the last counter seen per credential across every ceremony and refuses a counter that does not exceed it (both zero means no counter).
  - Store invariant: every check and state change of one call runs under one lock, so "not yet used" is checked and set atomically. A refused attempt does not consume the request; an approved one does.
  - Expiry: the browser gets the prompt timeout; the server expires every ceremony (registration, login, step-up) at the prompt timeout plus `EXPIRY_SLACK` (2 s), so an assertion completed at the end of the prompt can still arrive.
  - Login with an unknown user name answers 200 with the same shape as a known one: one decoy credential identifier, stable per name (SHA-256 of a label, a per-process key and the name), and a login that can only fail. Registration still answers `user_exists` for a taken name: the spike's registration is open, while the product's enrollment is token-gated (key management section 3).
- `src/action.rs`: the pending request and its hash. The request is a map of a layout version, a 128-bit request identifier from the server's CSPRNG, the member's 16-byte identifier and the action fields, encoded by story 1.9's AD-13 profile (`canonical-cbor` as a path dependency: `profile::insert_unique`, `profile::encode`, `profile::decode`, `profile::hash`; that spike is not modified). `decode_request` reads stored bytes back and refuses anything that is not exactly that layout.
- `src/stepup.rs`: the session handle `SHA-256("vilicus/v1/session-handle" || session_id)`, so the bearer secret of the cookie never enters a challenge; the derivation `challenge = SHA-256("vilicus/v1/step-up" || session_handle (32 bytes) || request_hash (32 bytes))`, fixed-length fields after a fixed label; and `bind_challenge` (decision 1).
- `src/http.rs`, `src/main.rs`, `src/pki.rs`: axum 0.8.9 over rustls (TLS 1.3 only, aws-lc-rs provider) through a small `axum::serve::Listener` that completes the TLS handshake (5 s timeout) before handing the stream to axum; a throwaway rcgen test CA. The session identifier travels in a `__Host-vilicus_sid` cookie (`Secure; HttpOnly; SameSite=Strict`, `Path=/`, no `Domain`); a request that carries it twice is refused with `duplicate_session_cookie`. A refusal gives the client its reason code only; the detail is logged on the server. The page has a strict CSP.
- `static/`: the page and its script, no framework. The script converts the `webauthn-rs` JSON options to WebAuthn calls and back by hand, and exposes the calls the driver uses; its three buttons run the same calls for the manual procedure.
- `tests/ceremonies.rs` (17 tests): the relying party driven by a minimal software authenticator written in the test (ES256, `none` attestation, aws-lc-rs signatures). Registration and login with session rotation; the signed challenge equals the derivation; the approved bytes decode to the started action and hash to the request hash; and each refusal with its exact error: assertion for another request (`MismatchedChallenge`), request with another hash, replay, the same assertion sent twice at once from two threads behind a barrier (exactly one approval, one `AlreadyUsed`), a counter value already seen answered to a second pending request (`CounterRegressed`), an assertion without the UV flag (`UserNotVerified`), expiry of a step-up, of a registration and of a login, an unknown user's login options, another session's request (`UnknownRequest`), the same action asked in another session (`MismatchedChallenge`), a login assertion presented as a step-up (`MismatchedChallenge`), another origin (`InvalidRPOrigin`), and a step-up from an anonymous session.
- Unit tests (15): the request encoding and its decoder, including a refused extra key; the handle and the derivation; `bind_challenge` (below); the cookie parsing, including a duplicated cookie; and, in `rp.rs`, a pending request whose stored session is altered to the presenting one, which passes the session check and is then refused by the recomputed challenge alone (`ChallengeMismatch`).
- `browser/`: the Playwright driver (`driver.mjs`), its image (`Dockerfile`: an official Playwright image, `libnss3-tools`, `npm ci` from a lockfile) and one `package.json` plus `package-lock.json` per Playwright version (`current`: `playwright@1.64.1`, `previous`: `playwright@1.63.0`, each equal to its image tag).
- `compose.yaml` and `run.sh`: the server answers on the compose network as `rp.vilicus.test`, which is the origin's host (`https://rp.vilicus.test:8443`) and the RP ID. `run.sh` runs `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, the release build and `cargo test --locked` in the Debian 13 Rust container, fails if any test is ignored or if the passed count differs from the harness's own listing, starts the server, reads the server's expiry from its `SERVER` line, runs the four browser drivers, prints one `PASS` or `FAIL` line per check and the server's outcome counts, and removes its compose project and volumes on exit. Only the cargo target volume `vilicus-passkey-stepup-target` is kept, for incremental builds, as the other spikes do.

How the browsers run:

- The test CA is added to each browser's NSS trust store with `certutil` (Chromium: `~/.pki/nssdb`; Firefox: a fresh profile directory opened with `launchPersistentContext`). No certificate error is ignored: the page is a real secure context over a certificate the browser validates.
- Chromium: CDP `WebAuthn.addVirtualAuthenticator` (CTAP2, internal transport, resident keys, user verification, automatic presence).
- Firefox: Playwright drives Firefox through its own Juggler protocol, which has no WebAuthn command; WebDriver BiDi was not tried, since Marionette already carries the WebDriver WebAuthn commands. The driver starts Firefox with `-marionette` and sends `WebAuthn:AddVirtualAuthenticator` over Marionette, next to Playwright. The pref `security.webauth.webauthn_enable_softtoken` is also needed: without it, registration failed with `NotAllowedError` on Firefox 155 and 157 in the first run.
- That the browser used this authenticator is shown, not assumed: after registration the driver lists the authenticator's credentials (CDP `WebAuthn.getCredentials`, Marionette `WebAuthn:GetCredentials`) and checks that it holds exactly the credential the page registered, and that its signature count advances after login and after a step-up.
- Browser-side negative checks: a `navigator.credentials.get` with `rpId: "attacker.example"` must be refused with `SecurityError`; and with the authenticator switched to "user not verified" (CDP `WebAuthn.setUserVerified`, Marionette `WebAuthn:SetUserVerified`) a step-up must be refused.
- A virtual authenticator is not a real one. It proves the browser's WebAuthn client and the server, not a platform authenticator, a password manager acting as a passkey provider, a security key or the user verification of a real device.

Dependencies and why:

| Component | Version (Cargo.lock or lockfile) | Why |
|---|---|---|
| webauthn-rs | =0.5.5 (webauthn-rs-core 0.5.5), feature `danger-allow-state-serialisation` | The design's WebAuthn library at the spine's pin; the feature is the only way 0.5.5 offers to set the challenge (decision 1 below) |
| canonical-cbor (path) and dcbor | story 1.9's crate, dcbor =0.25.2 | The AD-13 encoding and hash of the request, reused rather than reimplemented |
| axum / hyper | =0.8.9 / 1.12.0 | The spine's pins; axum without default features (`tokio`, `http1`, `json`) is the smallest HTTP layer that extracts JSON |
| tokio | 1.53.3 | Runtime; the spine lists 1.53.2, and `1.53` resolved to the later patch release |
| rustls / tokio-rustls | =0.23.45 / =0.26.6 | The spine's pins; TLS 1.3 with the aws-lc-rs provider |
| aws-lc-rs | 1.18.2, as pulled by rustls | CSPRNG and SHA-256 of the handle, the derivation and the decoy, ES256 signatures in the test authenticator; already in the tree |
| rcgen | =0.14.10, aws-lc-rs backend | Test CA and server certificate only |
| serde / serde_json | 1.0.229 / =1.0.154 | Required by the `webauthn-rs` JSON types; already in its tree |
| openssl | 0.10.81 (system libssl, Debian 13) | Pulled by `webauthn-rs-core`, as the spine's stack table already states |
| playwright (npm) | 1.64.1 and 1.63.0, exact, with lockfiles | Browser driver; each version matches its official image |

Images, pinned by digest in `compose.yaml` (tags as pulled on 2026-10-16): `rust:1-trixie`, `mcr.microsoft.com/playwright:v1.64.1-noble` (Chromium 156.0.8078.4, Firefox 157.0) and `mcr.microsoft.com/playwright:v1.63.0-noble` (Chromium 153.0.8010.12, Firefox 155.0). The `libnss3-tools` package in the driver images comes from Ubuntu 24.04 and is not pinned. The Rust checks run in the container, not on the Windows host: `webauthn-rs-core` links the system OpenSSL, which the host does not provide.

Open decision tasks settled (recommended answers, recorded here):

1. **Setting the challenge in `webauthn-rs` 0.5.5.** The library draws every challenge from its own CSPRNG (`generate_challenge` in `webauthn-rs-core/src/core.rs`); `ChallengeAuthenticateBuilder` has no challenge field and `AuthenticationState` has crate-private fields. Recommended: keep `webauthn-rs` and set the derived challenge through the serialized state, behind one function (`stepup::bind_challenge`). It fails closed: it refuses unless the original state round-trips through its serialization unchanged (so no field would be dropped silently), refuses a state without a string at `/ast/challenge`, and refuses unless the rewritten state round-trips unchanged. Its tests check those refusals on hand-made states and, on a real 0.5.5 state, that the bound state differs from the original at `/ast/challenge` only and that the options carry the same challenge. The state never leaves the server, so the client-held-state danger the feature's name warns about does not apply. Propose upstream a caller-supplied challenge on `ChallengeAuthenticateBuilder` and drop the workaround when it lands. This gives up a plain public API: the Core depends on a serialization detail of the library, guarded by tests. A random challenge mapped to the request on the server only was rejected: it binds the request by server state, not by what the authenticator signs, which is weaker than D71 states.
2. **What the challenge binds.** Recommended: a non-secret session handle (SHA-256 of a label and the session identifier) and the request hash, the request carrying a server-random identifier. The session identifier itself is the cookie's bearer secret and never enters the challenge, so the challenge, a log line or an audit record holding it discloses nothing that opens the session. Cross-session refusal does not rest on the explicit session check alone: the server recomputes the challenge for the presenting session and compares it with the stored one (unit test above). It gives up a challenge that depends on the action alone: two identical actions never share a challenge, so an audit check must recompute from the stored request and the session handle, not from the action fields only.
3. **Expiry.** The browser's prompt timeout is one constant; every ceremony expires on the server at that timeout plus `EXPIRY_SLACK` (2 s in the spike). The spike runs with a 4 s prompt and a 6 s server expiry to keep the expiry check short; the product values are named constants, not chosen here.
4. **Browser versions.** "Current and previous" are the two latest Playwright releases (1.64.1 and 1.63.0) and their bundled Chromium and Firefox builds. They stand in for current and previous Chrome and Firefox desktop but are not the vendors' release channels: the Chromium builds are Chrome for Testing builds that may precede the stable release, the pair 156 and 153 skips the milestones between them, and the Firefox builds are Playwright's patched builds. Recommended: accept them as the automated desktop rows, and run Android and any release-channel check by the manual procedure below.
5. **Devices not run here.** Chrome and Firefox on Android, Safari, real platform authenticators, password-manager passkey providers and security keys are "Not run here": they need a phone, a Mac or a hardware key. Recorded with the manual procedure below, not inferred from the desktop runs.

Limits kept, with the reason:

- Login is by user name, so a known user's options still list that user's credential identifiers and transports; the decoy makes an unknown name answer with the same status and shape (one identifier, no transports), which differs from a known user with several credentials or with transports. A usernameless (discoverable) login removes this, but `webauthn-rs`'s passkey registration in 0.5.5 does not require a resident key (`require_resident_key(false)` in `start_passkey_registration`), so it is a product decision, not taken here.
- On all four browsers the virtual authenticator set to "user not verified" makes the browser refuse the step-up itself (`NotAllowedError`); no unverified assertion reached the server. The server's own refusal (`UserNotVerified`) is shown by the ceremony test only.
- Firefox's virtual authenticator reports its signature count advancing by 2 per assertion in this run (2 after login, 4 after a step-up); Chromium's by 1. Both advance, which is all the check requires.

Manual procedure for the devices not run here (Chrome and Firefox on Android, current and previous; Safari on iOS and macOS, best effort; a real platform authenticator on the desktop browsers):

1. Run `bash spikes/passkey-stepup/run.sh` once, so the release binary exists in the `vilicus-passkey-stepup-target` volume.
2. On the dev host, with a scratch directory outside the repository: `docker run --rm -p 8443:8443 -v vilicus-passkey-stepup-target:/target:ro -v <scratch directory>:/pki rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a /target/release/passkey-stepup serve 0.0.0.0:8443 /pki rp.vilicus.test 120000`. The server writes `ca.pem` into the scratch directory and prints its `SERVER` line, then one line per ceremony. Open TCP 8443 for the LAN only.
3. Make `rp.vilicus.test` resolve to the host's LAN address (for example `192.0.2.10`) on the test device, through the household router's local DNS or a hosts entry. WebAuthn refuses an IP address as RP ID, so the name is required.
4. Install `ca.pem` as a user CA on the device (Android: Settings, Security, Encryption and credentials, Install a certificate, CA certificate; Firefox for Android also needs its setting to use third-party CA certificates; iOS: install the profile, then enable full trust in About, Certificate Trust Settings). Check that the page opens with no certificate warning: a warning means the page is not a secure context for WebAuthn.
5. Open `https://rp.vilicus.test:8443/`, enter a user name unique per browser and version, then press "Register a passkey", "Log in" and "Approve a sample action", using the device's own authenticator (screen lock, biometrics, or the password manager offered). Each step shows the server's answer; the last one must show HTTP 200 with `approved`. The server log shows `REGISTER outcome=accepted`, `LOGIN outcome=accepted` and `STEP_UP ... outcome=accepted`.
6. Record per device: browser and version, OS version, authenticator used, and the three outcomes. The refusals of AC2 are decided by the server from the assertion bytes and do not depend on the browser once an assertion verifies; they are checked by the automated runs, not repeated by hand.
7. Stop the server, then delete the scratch directory and remove the user CA from the device.

## Result

Run on 2026-10-16 on the Windows dev host with Docker Desktop, after the review fixes: `bash spikes/passkey-stepup/run.sh` printed 112 `PASS` lines, no `FAIL`, and `RESULT PASS` (exit 0), then left no container or compose volume behind. The crate checks inside it: `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, release build, `cargo test --locked` (32 passed, 0 ignored, 32 listed), all clean. Server line: `prompt_timeout_ms=4000 expiry_ms=6000`. Server counts of the run: 4 registrations, 8 logins and 8 step-ups accepted; step-ups refused 8 times `challenge_mismatch`, and 4 times each `action_mismatch`, `already_used`, `expired` and `unknown_request`.

Per-browser checks (`<label>.<check>` lines of `run.sh`; virtual authenticators throughout):

| Check | Chromium 156.0.8078.4 (current) | Firefox 157.0 (current) | Chromium 153.0.8010.12 (previous) | Firefox 155.0 (previous) |
|---|---|---|---|---|
| `secure_context`: page over HTTPS with a validated certificate | PASS | PASS | PASS | PASS |
| `foreign_rp_id_refused`: `rpId: "attacker.example"` refused by the browser (`SecurityError`) | PASS | PASS | PASS | PASS |
| `register`: passkey registration | PASS | PASS | PASS | PASS |
| `authenticator_holds_credential`: the virtual authenticator holds exactly the registered credential | PASS | PASS | PASS | PASS |
| `login`: passkey login, session issued | PASS | PASS | PASS | PASS |
| `step_up_challenge_derived`: the browser signed SHA-256 of label, session handle and request hash, and the request hash is SHA-256 of the canonical bytes | PASS | PASS | PASS | PASS |
| `step_up_approved` | PASS | PASS | PASS | PASS |
| `sign_count_advances`: the authenticator's count rises after login and after the step-up | PASS | PASS | PASS | PASS |
| `approved_request_matches`: the approval returns the canonical bytes of the started request | PASS | PASS | PASS | PASS |
| `other_request_refused`: assertion for A presented for B (HTTP 403 `challenge_mismatch`) | PASS | PASS | PASS | PASS |
| `other_hash_refused`: request A presented with B's hash (HTTP 403 `action_mismatch`) | PASS | PASS | PASS | PASS |
| `other_request_own_assertion_approved`: B still approves with its own assertion | PASS | PASS | PASS | PASS |
| `replay_refused` (HTTP 409 `already_used`) | PASS | PASS | PASS | PASS |
| `expired_refused`: assertion presented after the server expiry (HTTP 410 `expired`) | PASS | PASS | PASS | PASS |
| `user_verification_required`: authenticator set to "user not verified", step-up refused (by the browser in every run) | PASS | PASS | PASS | PASS |
| `other_session_refused`: request of the previous session, presented after a new login (HTTP 404 `unknown_request`) | PASS | PASS | PASS | PASS |
| `other_session_same_action_refused`: same action asked in the new session, old assertion (HTTP 403 `challenge_mismatch`) | PASS | PASS | PASS | PASS |

Not run here, by the manual procedure above: Chrome and Firefox on Android (current and previous), Safari on iOS and macOS (best effort), and real platform authenticators, password-manager passkey providers and security keys on any browser.

**AC1: partly met.** Passkey registration and login complete on current and previous Chromium and Firefox desktop (Playwright's builds, standing in for Chrome and Firefox; decision 4), with `webauthn-rs` 0.5.5 over TLS on a real host name, and the driver shows the browser used the virtual authenticator it installed. Evidence: the `secure_context`, `register`, `authenticator_holds_credential` and `login` rows. Android, which D107 lists as supported, and Safari are "Not run here", and every run used a virtual authenticator, not a real one; the manual procedure above covers the rest. The page is under `spikes/passkey-stepup/` instead of `spikes/e2-login/`. Command: `bash spikes/passkey-stepup/run.sh`.

**AC2: met for what is shown, on the four desktop browsers run with virtual authenticators.** Shown: the server computes the canonical request hash before the prompt and derives the challenge from it and the session handle; each browser signed exactly that challenge (`step_up_challenge_derived`, recomputed independently by the driver from the session cookie and the request hash); the approval returns the stored request; the same assertion presented for a different request is refused (`other_request_refused`), as is the request presented with another hash, a replay, an expired request, the assertion reused in another session, and a step-up without user verification. `tests/ceremonies.rs` and the unit tests check the same refusals with the exact errors, plus a concurrent double submission, a repeated counter and a moved request. Not shown: any real authenticator, platform or roaming; Android and Safari; a password-manager passkey provider; the server's refusal of an unverified assertion coming from a browser (browsers refused first); a compromised Gateway or page showing a different action than the one hashed (D71 states this limit; nothing here addresses it); the product's expiry values. `webauthn-rs` 0.5.5 binds the challenge only through the state-serialization workaround of decision 1. Command: as AC1.

**AC3: not triggered.** No browser that was run failed AC1 or AC2, so no browser leaves the supported list and the TOTP fallback of D117 is not taken; nothing is recorded in `doc/decisions.md` as a fallback. The library behaviour that needs recording, the missing challenge API and the per-state counter snapshot, is in the proposed updates below. If the manual run fails on an Android browser, that browser leaves the list under D117 and the failure is recorded as this AC states.

## Proposed design document updates

Not applied: this spike does not edit shared design documents.

1. `doc/research-notes.md`, section 3, E2 row, Pass criterion column: after "succeed on every supported browser (D107)", add: "**Login half run** (story 1.5, `spikes/passkey-stepup/`, 2026-10-16): with `webauthn-rs` 0.5.5 and virtual authenticators, passkey registration, login and the action-bound step-up pass on Chromium 156 and 153 and Firefox 157 and 155 (Playwright builds); an assertion presented for another request, a replay, an expired request, an assertion reused in another session and a step-up without user verification are refused. Chrome and Firefox on Android, Safari and real authenticators are still to run, by the manual procedure in story 1.5."
2. `doc/research-notes.md`, section 1.1, two new rows after "WebAuthn library": topic "WebAuthn challenge", claim "`webauthn-rs` 0.5.5 has no API for a caller-chosen authentication challenge; it can be set only by rewriting the state serialized under the `danger-allow-state-serialisation` feature"; and topic "WebAuthn counter", claim "`webauthn-rs` 0.5.5 checks the signature counter against the value copied into each authentication state when it starts, so two states started together accept the same counter; the relying party must track the last counter itself"; each with status "Verified (story 1.5, `spikes/passkey-stepup/`)", used in "E2; D71; spine AD-8".
3. `doc/research-notes.md`, status line: in "Apart from the AD-36 construction (D119), nothing here has been proven by a prototype.", also name the E2 login half as run on desktop Chromium and Firefox; at the end of the update paragraph, add "Story 1.5 then ran the E2 login half on desktop Chromium and Firefox with virtual authenticators; Android, Safari and real authenticators remain." If another spike has changed this sentence first, merge both.
4. `doc/decisions.md`, new decision record "Step-up challenge derivation and its setting in `webauthn-rs`", amending D71: "Context: D71 binds every step-up assertion to the hash of one pending action, but `webauthn-rs` 0.5.5 chooses every challenge itself and has no API to set one. Decision: the step-up challenge is SHA-256 of `vilicus/v1/step-up`, a session handle and the request hash (AD-13). The session handle is SHA-256 of `vilicus/v1/session-handle` and the session identifier, so the bearer secret never enters a challenge, a log or an audit record. The request carries a 128-bit identifier from the Core's CSPRNG, and the Core stores its canonical bytes and executes only those after approval. At approval the Core recomputes the challenge for the presenting session and compares it with the stored one; a request of another session reads as unknown. The pending request is single use, checked and set atomically, and the Core refuses a signature counter that does not exceed the last one it saw for the credential. The browser's prompt timeout is a named constant, and every ceremony (registration, login, step-up) expires on the Core at that timeout plus a named slack. The Core sets the challenge in `webauthn-rs` through the state serialized under `danger-allow-state-serialisation`, in one function that refuses unless the state round-trips unchanged and differs from the original at the challenge only; the state never leaves the Core. A caller-supplied challenge is proposed upstream, and the workaround is removed when it lands. Consequences: an assertion verifies for one request in one session only; two identical actions never share a challenge; an audit check recomputes from the stored request and the session handle; a `webauthn-rs` upgrade is gated by the tests of that function."
5. `doc/architecture-spine.md`, AD-8, rule (3): after "derives the WebAuthn challenge from its canonical hash (AD-13)", add "and a non-secret session handle, the request carrying a random identifier and its canonical bytes being what is executed (new decision record; set in `webauthn-rs` 0.5.5 through its serialized authentication state)".
6. `doc/architecture-spine.md`, Stack table, row `webauthn-rs`: replace "0.5.5" with "0.5.5 (feature `danger-allow-state-serialisation`, for the step-up challenge only)".
