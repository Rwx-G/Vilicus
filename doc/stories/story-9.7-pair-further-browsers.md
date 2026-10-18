---
title: 'Pair further browsers'
epic: 9
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-16, AD-21, D35, D77, E22, FR-56, D122, D123]
---

# Story 9.7: Pair further browsers

As a member,
I want to pair another browser with a short-lived code from a paired device or from the host,
So that I can use Vilicus on a second device without a QR scan and without the code being usable by someone watching the network.

**Acceptance Criteria:**

**AC1 (FR-16, D35)**
**Given** a paired browser older than 24 hours
**When** the member asks it for a pairing code
**Then** the Core issues a code that is single use, expires after 2 minutes and allows 3 attempts
**And** a browser paired less than 24 hours ago is refused when it asks for a code

**AC2 (FR-16, D77, FR-56)**
**Given** root at the host
**When** `vilicus device pair <member>` runs with that member's own passphrase at the prompt
**Then** it prints a pairing code with the same limits, the passphrase of another adult is refused, and the member is notified on every paired device and on the out-of-browser notification channel

**AC3 (FR-16, AD-21)**
**Given** a valid code typed in the new browser
**When** pairing runs
**Then** OPAQUE (`opaque-ke` in the Core, its WASM build in the browser) binds the code to the new browser device key registration, so a party that observes or relays the traffic cannot use it
**And** the pairing page is a separate document whose CSP alone adds `'wasm-unsafe-eval'`

**AC4 (FR-56)**
**Given** a successful pairing from any source
**When** it completes
**Then** the member receives an out-of-browser alert stating how many passkeys and paired devices they now have, and the pairing is audited

**AC5 (E22, D123)**
**Given** the PAKE fallback of D107 is taken, because E22 fails on Android (its desktop part passed, D122) or a check of AC8 fails (D123)
**When** a paired device asks for a code
**Then** pairing codes are issued only by `vilicus device pair`, and the member web says so

**AC6 (D122, FR-16)**
**Given** a pairing code
**When** it is issued and redeemed
**Then** it is `HHH-SSSS-SSSS`: a 3-digit handle that names the pending pairing and is not secret, and an 8-digit secret drawn by the issuer with rejection sampling (`crypto.getRandomValues` in the issuing browser, the Core's RNG for `vilicus device pair`), which is the OPAQUE password, so an online guess succeeds with probability 3 in 10^8 per code
**And** every OPAQUE login start gets an answer, OPAQUE's fake one for an unknown, used, expired or exhausted handle, so a client cannot tell it from a wrong secret; a start on a live pairing spends one of its 3 attempts; each run is kept under its own login identifier, so a second start never cancels a run in flight; every start is charged to its source address, at most 10 per 60 seconds; and the code is used up once the Core verifies the third OPAQUE message, whatever the binding outcome
**And** the lock-out after 3 attempts stays a denial-of-service lever, bounded by the uniform answers and the per-source limit, after which the member issues another code (D122).

**AC7 (D122, AD-21)**
**Given** a pairing run
**When** the code is bound to the new browser
**Then** OPAQUE uses ristretto255, 3DH with SHA-512 and Argon2id at 64 MiB, 3 passes and 4 lanes on the client, with one credential identifier per pairing (`vilicus/v1/pair/` and 16 random bytes)
**And** the new browser sends its public key with an HMAC-SHA-256 tag under a key derived by HKDF-SHA-256 from the OPAQUE session key (empty salt, info `vilicus/v1/pair/bind`) over the label, the handle, the login identifier and the key, plus a proof of possession; a relay that substitutes its key is refused (`binding_mismatch`) and the code is used up
**And** the Core signs each registration response (`vilicus/v1/pair/registration`, the handle and the response) with an identity key the issuing device pinned when it was registered, at enrollment by trust on first use, when paired by code under a tag of its binding key (`vilicus/v1/pair/core-key`); the issuing device refuses an unsigned or wrongly signed response, which is the only check that catches a relay replacing the OPRF evaluation while keeping the Core's server public key (Story 1.3, finding 4); a device finishes only an issuance it started
**And** the relay, replay, expiry, rate-limit and fake-answer cases of `spikes/browser-device-key/tests/core_flows.rs` and of its browser driver pass against the product code.

**AC8 (D123, D28)**
**Given** the OPAQUE libraries under the exception to D28
**When** FR-16 code is written
**Then** before it: `opaque-ke` is pinned `=4.0.1` and the `opaque-ke` version built into the WASM is recorded; the WASM is built from pinned source in CI and matches the npm artifact of `@serenity-kit/opaque` byte for byte, or Vilicus serves its own build; the RFC 9807 Appendix C test vectors run on both sides; a cross-test runs the WASM client against the Core's server, the fake-record path and negative cases included
**And** `opaque-ke`'s key stretching function (`Ksf`) is implemented over the Core's `argon2` 0.6, so the `argon2` 0.5 that `opaque-ke` 4.0.1 pulls is gone and `deny.toml` needs no duplicate entry for it; no document calls these libraries audited at their pinned versions; an external review comes before V1 (gate E22-2).

**Dependencies:**
- Story 9.1 (a paired browser)
- Story 8.1 (out-of-browser alerts)
- Story 7.7 (device key, proof of possession)

**References:**
- `doc/prd.md` FR-16, FR-56
- `doc/architecture-spine.md` AD-19, AD-21, Stack (opaque-ke, @serenity-kit/opaque)
- `doc/architecture.md` sections 6 and 7.3
- `doc/research-notes.md` E22
- `doc/decisions.md` D28, D35, D77, D107, D122, D123
- `spikes/browser-device-key/` (`src/pairing.rs`, `src/core.rs`, `web/pair.html`, `web/static/pair.js`, `browser/driver.mjs`)
- `doc/qa/gates/1.3-e22-browser-device-key-pake-and-signed-confirmations.yml` (E22-1, E22-2)
