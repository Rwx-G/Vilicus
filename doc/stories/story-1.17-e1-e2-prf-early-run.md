---
title: 'E1 and E2 PRF half: early run'
epic: 1
story: 17
status: 'in-progress'
author: Rwx-G
created: 2026-10-16
implements: [E1, E2]
---

# Story 1.17: E1 and E2 PRF half: early run

As the owner,
I want the WebAuthn PRF extension tried early on the household's real phones,
So that the later decision on PRF unlock is informed, without gating anything in V0.1.

**Acceptance Criteria:**

**AC1 (E1)**
**Given** a prototype app under `spikes/e1-e2-prf/` using the Android credential API (Credential Manager) with a platform and a roaming authenticator
**When** PRF is evaluated with the same salt across several sessions on each household phone
**Then** the record states whether the output is a stable 32-byte value per credential, without any phone model in the record

**AC2 (E2)**
**Given** a minimal server on `webauthn-rs` and a page on the supported browsers
**When** the PRF extension is requested at registration and assertion
**Then** the record states whether the library exposes PRF and whether each browser returns a reproducible output per credential

**AC3 (E1, E2)**
**Given** either result
**When** it is recorded
**Then** it gates nothing in V0.1, because PRF unlock comes after V0.1 and passphrase unlock is the V0.1 path

**Spike plan:**
- Question: does PRF work through the Android credential API (E1), and do `webauthn-rs` and the target browsers expose a reproducible PRF output (E2, PRF half)?
- Method: prototype app and minimal server and page, run on the household's real phones and the supported browsers.
- Pass criterion: stable 32-byte output per credential and salt across sessions.
- Timebox: 3 working days.
- Fallback on failure: passphrase unlock stays the only unlock path, which is already the V0.1 design.
- Result record: E1 and E2 PRF half status in `doc/research-notes.md`. Non-gating for V0.1.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E1, E2), section 1 (WebAuthn PRF), section 1.1 (WebAuthn library)
- `doc/prd.md` section 4.4, section 9
- `doc/key-management.md` section 3 (passkey wrapping details)

## Implementation Notes

Spike code: `spikes/prf-probe/`, a standalone crate (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`). AC1 names `spikes/e1-e2-prf/`; the spike lives under `spikes/prf-probe/` instead, by the instruction that launched this story. It does not touch `spikes/passkey-stepup/` (story 1.5).

Scope of this pass: everything that can run without the household's phones. The real result (AC1, and the browser half of AC2) needs the household devices; `spikes/prf-probe/RUNBOOK.md` reduces it to opening a page on each device.

What it holds:

- `src/server.rs`: an HTTPS relying party (hyper 1 over rustls) on the passkey API of `webauthn-rs` 0.5.5. Registration and login are verified by `webauthn-rs`; one credential per login (`allowCredentials` holds it alone), a fresh random user per registration, named `vilicus-prf-probe <label>` so the test passkey can be found and deleted. A ceremony session is used once, then removed, whatever the outcome. Every request type it deserializes refuses unknown fields. The page and script are served with `default-src 'self'` and no inline script.
- `static/probe.js`: adds `prf` with two fixed salts (SHA-256 of two fixed labels) to the options `webauthn-rs` returns, asks for a discoverable credential, evaluates PRF at registration and at each login, and sends the SHA-256 and length of each output in a separate `probe` object, never the output; the credential it posts carries empty client extension results. It also sends the transports, the user agent and the names (not values) of the client extension results.
- `src/authdata.rs`: re-reads the signed authenticator data after verification (AAGUID, user verified, backup eligible and backup state flags, authenticator extension keys such as `hmac-secret`), because `webauthn-rs` keeps the AAGUID and the extension outputs of a passkey private.
- `src/probe.rs`: validation of the report from the page (digest-shaped values only, bounded fields, restricted label) and the per-credential verdict and Markdown table. A credential is `stable` after at least two logins, each with both outputs, equal per salt across logins and with the outputs of the registration when present, 32 bytes long, and different between the two salts; the other verdicts are documented on `Verdict`.
- `src/store.rs` and `src/pki.rs`: registrations (public keys only) and records in a data directory, so a login days later still finds its credential; a local CA name-constrained to the host name of the probe, whose private key is never written, and a server certificate valid for a year. A data directory generated for another host name is refused.
- `docker/` and `run.sh`: the end-to-end check described under Result. `serve.sh`: builds and runs the probe on the LAN for the household run (`start`, `ca`, `report`, `stop`), with its data in the Docker volume `vilicus-prf-probe-lan`.

`webauthn-rs` and PRF: `webauthn-rs` 0.5.5 has no `prf` extension. Its request and response extension types carry the CTAP-level `hmacCreateSecret` and `hmacGetSecret` names instead, with its own comments saying browsers do not support retrieving the secret, and its passkey API fixes the extensions it requests. It is used as the verifier anyway: the page adds `prf`, and `webauthn-rs` accepts the response because the client extension results it receives are empty and it keeps unrecognized signed authenticator extensions (such as `hmac-secret` output bytes) without failing. That second point is shown by its own parser in unit tests, not yet by a real authenticator. Test `registration_options_carry_no_prf_and_a_fresh_session` pins the absence of `prf` in its options.

Dependencies and why:

| Crate | Version (Cargo.lock) | Why |
|---|---|---|
| webauthn-rs | =0.5.5 | The relying party; the version story 1.5 uses. Pulls OpenSSL (the openssl crate 0.10.81 over the system OpenSSL of the Debian 13 build image) |
| webauthn-rs-core | =0.5.5, already in the tree | Public parser of the signed authenticator data |
| serde_cbor_2 | =0.13.0, already in the tree | Reads `authData` out of the attestation object |
| tokio, hyper, hyper-util, http-body-util | 1.53.3, 1.12.0, 0.1.21, 0.1.5 | HTTPS server, the pins of the E3 and E22 spikes |
| rustls, tokio-rustls | 0.23.45 (aws-lc-rs 1.18.2), 0.26.6 | TLS, the pins of the spine |
| rcgen, time | 0.14.10, 0.3.55 (already in the tree) | Local CA and server certificate, validity dates |
| serde, serde_json | 1.0.229, 1.0.154 | Request and record encoding |
| sha2 | 0.10.9 | Short credential identifiers in the records |

Images, pinned by digest: `rust:1-trixie` (build and server), `mcr.microsoft.com/playwright:v1.64.1-noble` with the matching `playwright@1.64.1` npm package, as in the E3 spike.

Open decision tasks settled (recommended answers, recorded here):

1. **The native Credential Manager app of AC1 is not built.** It needs an Android toolchain on the dev host and a Digital Asset Links file for the relying party domain, which Google Play services is expected to fetch from a publicly reachable HTTPS origin (not verified here); the household LAN probe has neither. Recommendation: run the browser rows first; on Android 14 and later the browsers reach third-party passkey providers through Credential Manager, so they exercise it indirectly. Build the app only if PRF unlock is scheduled and the browser rows leave Android in doubt. What this gives up: a direct answer to E1 as worded, for the native app path.
2. **Separate browser contexts with the same credential**: not possible with the PRF secret of the virtual authenticator. A CDP credential export carries the private key, not the PRF secret, so an imported credential signs but returns no PRF output. The virtual run therefore checks the two later sessions in the same tab with cookies cleared and the page reloaded, and checks the cross-context login for its signature only. Stability across contexts, browsers and reboots is exactly what the household run measures.
3. **Signed evidence of PRF**: recorded, not required. The Chromium virtual authenticator returns PRF outputs with no authenticator extension in the signed data, so the absence of `hmac-secret` proves nothing; a password manager acting as provider may behave the same way. The record keeps the extension keys so the household run shows which providers leave a signed trace.

## Result

Run on 2026-10-16 on the Windows dev host with Docker Desktop: `bash spikes/prf-probe/run.sh` printed `RESULT PASS` (exit 0): fmt, clippy with `-D warnings`, 17 unit tests passed with none ignored (the count is enforced), the release build, 19 end-to-end checks, and a check that the server log holds no digest; it left no container or compose volume behind (only the cargo target volume, as the other spikes do). `serve.sh start`, `ca`, `report` and `stop` were run once against a test host name and port; the page and `/ca.crt` were fetched over TLS verified against the exported CA, whose name constraint and `pathlen:0` were checked with `openssl x509`. `cargo audit` was not run (not installed in the build image).

What the virtual authenticator showed (Chromium 156.0.8078.4, CDP `WebAuthn.addVirtualAuthenticator` with `hasPrf`, CTAP 2.1, internal transport):

- Registration verified by `webauthn-rs`; `prf.enabled` true, and outputs already returned at registration (evaluation at creation), 32 bytes each.
- Two later sessions (cookies cleared, page reloaded, new server session each): both verified, both returned two 32-byte outputs; the digests were equal per salt across the two logins and equal to those of the registration, and different between the two salts. The report called the credential `stable`.
- A second credential on the same authenticator gave a different output for the same salt: the secret is per credential, as `key-management.md` (Passkey wrapping details) assumes.
- The raw outputs captured inside the page hashed to the posted digests, and no request body held any raw output in hex, base64 or base64url (4 outputs, 13 requests, 0 matches). A replayed login was refused (HTTP 400).
- The virtual authenticator put no extension in the signed authenticator data, at registration or at login (flags without the extension-data bit): the PRF outputs it returns leave no signed trace.
- A credential exported over CDP and imported into an authenticator in another browser context logged in (signature verified) but returned no PRF output; the report then flagged the credential `intermittent`, as designed for a session without outputs.

This proves the probe, not the property: PRF on a virtual authenticator says nothing about a phone, a platform authenticator or a password manager.

**AC1: Not run here: needs the household devices.** The probe and `RUNBOOK.md` are ready for Chrome and Firefox on Android with the platform authenticator and each password manager, and a roaming authenticator over NFC or USB if the household has one. The native Credential Manager app is not built (decision task 1). The record will hold labels the owner chooses and AAGUIDs, no phone model: the table carries no user agent, and `results.jsonl`, which holds the user agents, stays in the Docker volume.

**AC2: partly met.** Whether the library exposes PRF: it does not; `webauthn-rs` 0.5.5 has no `prf` extension, and PRF works beside it with the page adding `prf` and reporting digests separately (shown with the virtual authenticator only). Whether each browser returns a reproducible output per credential: **Not run here: needs the household devices**; the pipeline that will measure it passed with the Chromium virtual authenticator. Command: `bash spikes/prf-probe/run.sh`.

**AC3: met.** Nothing in V0.1 waits on this story: PRF unlock comes after V0.1 and the passphrase unlocks in V0.1 (PRD section 4.4). The story stays `in-progress` only until the household run fills AC1 and the browser half of AC2.

## Proposed design document updates

Not applied: this spike does not edit shared design documents. Items 1 and 2 can be applied now; item 3 waits for the household run.

1. `doc/research-notes.md`, section 1.1, row "WebAuthn library": replace the claim with "`webauthn-rs` 0.5.5 has no `prf` extension (its extension types carry the CTAP-level `hmacCreateSecret` and `hmacGetSecret` names, and its passkey API fixes the extensions it requests); PRF can still be used beside it, with the page adding `prf` to the options and sending the output outside the credential it verifies" and the status "Reported" with "Verified in source and with a virtual authenticator (story 1.17, `spikes/prf-probe/`); not yet with a real authenticator".
2. `doc/key-management.md`, section 3, Passkey wrapping details, after the bullet that ends "This is stated everywhere as a limit (R3 in `architecture.md`).": add the bullet "The PRF output is an unsigned client extension result: the Core cannot verify that it came from the authenticator, and the signed authenticator data may carry no trace of the evaluation (a CTAP `hmac-secret` output appears only when the browser uses that extension, and the Chromium virtual authenticator leaves none). The only check on the output is that the AEAD unwrap of the DEK succeeds; a wrong output fails it. Observed in E2 (story 1.17)."
3. After the household run, `doc/research-notes.md`, section 3, rows E1 and E2, Pass criterion column: append "**Run** (story 1.17, `spikes/prf-probe/`, <date>): <the per-credential table from `serve.sh report`, by label and AAGUID provider name, with the verdict>" and, for E1, state that the native Credential Manager app was not built and which browser rows reached third-party providers through Credential Manager. If no household provider is `stable`, add a new decision record stating that PRF unlock stays deferred until a household provider passes E1 or E2, with passphrase unlock as the only path; if one is, no decision changes.
