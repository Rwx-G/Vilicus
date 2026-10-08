# Research notes

Status: design phase, no code yet. This file separates what is reported by desk research, what is assumed, and what must be tested before the design commits to it. Nothing here has been proven by a prototype. Statuses:

- **Reported**: gathered from documentation and public sources during design research (October 2026). The sources were not re-opened for this repository, so treat each item as a claim to re-check before relying on it.
- **Assumed**: a design assumption with no source.
- **To test**: an experiment with a pass criterion (section 3).

## 1. Reported facts the design leans on

| Topic | Claim | Status | Used in |
|-------|-------|--------|---------|
| WebAuthn PRF | The PRF extension (over CTAP hmac-secret) returns a secret specific to each credential; support is good on recent Android, Windows 11 and macOS/iOS 18.4 or later, but varies by authenticator and by password manager acting as provider | Reported | `key-management.md`, section 3 |
| Per-credential secret | Because the PRF secret is per credential, each authenticator needs its own wrapper; a passkey cannot be the only unlock path | Reported | D4 |
| Transaction display | WebAuthn does not prove what the user saw; the transaction-authorization extensions are abandoned in practice | Reported | D10, D12 |
| Secure Payment Confirmation | Available only in Chrome and Edge | Reported | D12 |
| Android Protected Confirmation | Exists as `ConfirmationPrompt`; hardware support is uneven and must be tested at runtime with `isSupported()` | Reported | D12 |
| SQLCipher KDF | SQLCipher does not implement Argon2; raw keys can be supplied | Reported | D2 |
| TLS hybrid | `X25519MLKEM768` is available in rustls with the aws-lc-rs provider (`prefer-post-quantum` option) | Reported | D27 |
| PQ signatures | No public CA issues post-quantum certificates; WebAuthn support is in drafts | Reported | D27 |
| WASI | WASI 0.3 was released in June 2026 | Reported | D18 |
| Google OAuth | Restricted Gmail scopes require a yearly security assessment, which makes a shared verified application unrealistic for a small project | Reported | D24 |
| Jev (TypeSafe AI) | Proprietary, API only, English first, not self-hostable; good calibration on its Choice primitive in one academic study, weak recall at a fixed threshold | Reported | D17 |
| Graphiti | Python, Apache-2.0, needs a graph database server | Reported | D23 |
| Recipe-to-cart services | Such services in France work through retailer partnerships, which a household project cannot reproduce | Reported | D25 |
| Retailer terms | Consumer retail sites generally restrict automated access and may suspend accounts; many deploy bot detection | Reported | D25, README disclaimer |

## 2. Assumptions

| Assumption | Why it matters | Risk if wrong |
|------------|----------------|---------------|
| A household volume (thousands to low millions of rows) fits SQLite comfortably | Allows file-per-module-per-partition | Performance rework |
| A 3 to 4 billion parameter quantized model can classify structured states well enough after recalibration | Controller viability | Controller dropped to a deterministic-only path |
| Users will keep a printed recovery secret | Recovery model | More lost partitions |
| Households with children will run one adult at least as admin | Admin model | Admin recovery complexity |
| Android is the first native platform | Tier 2 | iOS households cannot confirm until a native iOS app exists (open: not planned) |
| A small number of tier 2 requests per week is acceptable | Fatigue | Friction, shadow IT |
| Modules compiled in the Core process are acceptable at v1 | Simplicity | R2 |

## 3. Experiments (to test before committing)

Each experiment records: question, method, pass criterion, fallback if it fails.

| ID | Question | Method | Pass criterion | Fallback |
|----|----------|--------|----------------|----------|
| E1 | Does PRF work in the native Android credential API (Credential Manager)? | Prototype app evaluating PRF with a platform and a roaming authenticator | Stable 32-byte output across sessions for the same salt | Passphrase unlock on Android; passkey for login only |
| E2 | Does `webauthn-rs` expose PRF, and do target browsers return it? | Minimal server and page on Chromium, Firefox, Safari and mobile | Output per credential, reproducible | Handle PRF client side in own code, or passphrase-only unlock |
| E3 | Does every client negotiate the hybrid key exchange? | Real handshake against the rustls server from: current Chrome, Firefox, Safari, Android system WebView, OkHttp, Cronet, the app's own rustls build | Observed negotiated group per client recorded | Document which clients lose the hybrid exchange; keep classical fallback |
| E4 | How available is Protected Confirmation on real phones? | Call `isSupported()` on several devices and OS versions | Result table; usable on at least the owner's phone | Remains optional reinforcement |
| E5 | Can the app sign with a Keystore key requiring per-use user verification, with attestation, on StrongBox and non-StrongBox devices? | Prototype | Key invalidated on biometric change; attestation verifiable by the Core | Weaker policy on devices without StrongBox, flagged in the device record |
| E6 | Controller quality and latency in French on CPU | Build a labelled set of structured cases (legitimate and trapped); run a 3 to 4 billion parameter model in GGUF Q4 on a small CPU host; measure false accept rate, false reject rate, ECE, latency | False accept rate on trapped cases below an agreed threshold with conservative cut-offs; latency compatible with interactive use | Deterministic rules plus human only; no controller in v1 |
| E7 | Is Tauri mobile mature enough for the Android shell? | Build a shell with QR scanning, Keystore access and notifications | Works without native plugin gaps | Native Kotlin shell for Android; Tauri for desktop only |
| E8 | What do the Google and Microsoft OAuth procedures cost a household that brings its own client? | Walk through both consoles for a personal project | Documented steps, time, and any fee or review | IMAP/SMTP and CalDAV only |
| E9 | How do work accounts behave under corporate policy? | Test with a consenting account: app passwords, OAuth consent, conditional access | Documented outcomes by provider | Declare work accounts best effort |
| E10 | Does the fixed systemd profile work for a plugin that needs a socket, one credential and an egress proxy? | Reference plugin under `DynamicUser`, `LoadCredential`, `SystemCallFilter=@system-service`, `IPAddressDeny=any` | Plugin works; direct sockets fail; peer identity verified | Relax individual options with a documented list |
| E11 | Does the SQLite authorizer block `ATTACH`, `DETACH`, unsafe `PRAGMA` and extension loading in the migration connection? | Unit tests with hostile migrations | All forbidden statements rejected | Move to a vetted statement parser |
| E12 | What Argon2id parameters fit a small host? | Benchmark on target hardware | Unlock under a target latency with memory above the published floor | Lower concurrency, raise the memory floor, or prefer passkey PRF |
| E13 | Is a persistent connection or UnifiedPush reliable enough for content-free notifications on Android? | Run both for several days on a test phone | Delivery rate and latency recorded | Polling when the app is open; accept delay |
| E14 | Does CONNECT-based domain filtering hold for the plugins' real traffic (HTTP/2, QUIC, redirects)? | Reference plugin and proxy | No bypass of the allowlist; no breakage of normal flows | Per-plugin IP ranges as a second filter |
| E15 | Can per-record keys coexist with full-text search for mail and documents? | Prototype with SQLCipher FTS5 | Search works on non-shredded fields; shredded records disappear from the index | Shred whole conversations, keep search on metadata |
| E16 | Does locked memory and zeroization behave as designed in the Rust runtime, including on crash? | Tests with core dumps disabled; inspection of process memory after key drop | No key material found after drop in tested paths | Reduce key lifetime further |
| E17 | Does `secure_delete` plus WAL behavior match the shredding claims? | Delete records, inspect files and WAL | No plaintext of deleted records in the file or WAL | Vacuum after shredding; document backup caveat |
| E18 | Do the target grocery stores publish an official partner or developer API? | Read their developer portals by hand | Written answer per store | Semi-manual flow; no plugin |
| E19 | Is canonical (deterministic) CBOR hashing identical between the Rust Core and the Kotlin app? | Cross-language test vectors, fuzzing | Identical bytes and hashes on a large corpus | Switch the canonical form |
| E20 | Can the native app and the Core establish an inner encrypted channel that the Gateway cannot read? | Prototype with a pinned Core key | PRF output and confirmations unreadable by the Gateway | Accept R3 for the app too |

## 4. Open design questions that depend on experiments

- Whether PRF unlock is offered on Android in v1 (E1).
- Which clients get the hybrid exchange (E3) and what the README can honestly say.
- Whether the controller ships in v1 (E6).
- Whether Tauri is used on Android (E7).
- Whether cart preparation can be relaxed from tier 2 (D25, E18).

## 5. How to update this file

Move an item from "reported" or "to test" to "verified" only with a link to a test result or a dated source that was actually re-read. When an experiment fails, record the fallback taken in `decisions.md`.
