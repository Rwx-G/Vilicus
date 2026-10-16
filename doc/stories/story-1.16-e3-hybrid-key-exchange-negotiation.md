---
title: 'E3: hybrid key exchange negotiation'
epic: 1
story: 16
status: 'done'
author: Rwx-G
created: 2026-10-16
implements: [E3, D27, NFR-7]
---

# Story 1.16: E3: hybrid key exchange negotiation

As the owner,
I want the negotiated TLS group recorded for each client against the rustls server,
So that the README transport wording says exactly which clients get the hybrid key exchange (X25519MLKEM768), within the D27 wording.

**Acceptance Criteria:**

**AC1 (E3, D27)**
**Given** a rustls 0.23.45 server with the aws-lc-rs provider preferring X25519MLKEM768, under `spikes/e3-tls/`
**When** current Chrome, Firefox, Safari, Android System WebView, OkHttp and Cronet complete a real handshake
**Then** the negotiated group is recorded per client and version

**AC2 (E3, NFR-7)**
**Given** the recorded table
**When** the README transport wording is checked
**Then** it claims the hybrid exchange only for the clients that negotiated it, keeps the classical fallback for the others, and makes no claim beyond D27

**AC3 (E3)**
**Given** the result
**When** it is recorded
**Then** it informs the README wording only and blocks no other V0.1 work

**Spike plan:**
- Question: does every client negotiate the hybrid key exchange (E3)?
- Method: real handshakes against the rustls server from each listed client.
- Pass criterion: the negotiated group per client is recorded; the result informs the README wording of the transport claim.
- Timebox: 2 working days.
- Fallback on failure: document which clients lose the hybrid exchange; keep the classical fallback.
- Result record: E3 table in `doc/research-notes.md`; README wording checked against it.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E3), section 1.1 (TLS hybrid)
- `doc/decisions.md` D27
- `doc/architecture.md` section 15
- `doc/prd.md` section 9

## Implementation Notes

Spike code: `spikes/hybrid-kex/`, a standalone crate (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`). AC1 names `spikes/e3-tls/`; the spike lives under `spikes/hybrid-kex/` instead, by the instruction that launched this story. Nothing else depends on the path.

What it holds:

- `src/server.rs`: a TLS 1.3 only server on rustls with the aws-lc-rs provider and its default key exchange groups (`X25519MLKEM768`, `X25519`, `secp256r1`, `secp384r1` in that order, printed by the server at start from its configuration). ALPN `http/1.1`. For each connection it logs one `HANDSHAKE` line: the client name taken from a `GET /client/<name>` request, the negotiated protocol version and group (both read from rustls), whether a HelloRetryRequest was needed (`hrr`, from rustls `handshake_kind()`, and `hrr_inferred`, from the captured key shares, as a cross-check), the groups the client offered and those it sent key shares for, ALPN, SNI and the user agent. Client-controlled text (user agent, error) has control characters replaced and quotes swapped, so it cannot forge a log line. The response body is the same line, so each client also prints the server's record.
- `src/client_hello.rs`: reads the raw ClientHello off the socket before rustls sees it (reassembled across records) and replays the bytes to rustls. rustls 0.23.45 exposes the offered `supported_groups` but not the key shares, and the key shares decide between a direct answer and a HelloRetryRequest.
- `src/pki.rs`: a throwaway test CA and a server certificate signed by it (rcgen), written to the run's scratch volume and deleted with it.
- `src/probe.rs`: the rustls client (the library and provider the native app is expected to use), with the provider's default groups or X25519 only.
- `tests/handshake.rs`: in-process handshakes (the default client gets the hybrid group, X25519-only and P-256-only clients still connect, the server follows the client's group order, a client whose only key share is for a group the server does not list costs a HelloRetryRequest, a TLS 1.2-only client is refused with a protocol version refusal on both sides). The ClientHello parser has unit tests for two key shares, a split record, a truncated extension, a message beyond the 64 KiB cap and a first handshake message that is not a ClientHello.
- `docker/` and `run.sh`: a compose project with the server and every client. `run.sh` runs the crate checks in the Debian 13 Rust container, starts the server, runs each client once, prints one `PASS` or `FAIL` line per check and the per-client table (per client: handshake, TLS 1.3, rustls HRR equal to the inferred one, first mutual group, expected group or HRR where set, the group the rustls probe, Node and Go report on their side equal to the server's, non-empty version string; the server log is polled for up to 5 seconds per record), fails on any ignored or missing test, and removes its compose project and scratch volume on exit. Only the named cargo target volume `vilicus-hybrid-kex-target` is kept, for incremental builds, as the other spikes do.

Dependencies and why:

| Crate | Version (Cargo.lock) | Why |
|---|---|---|
| rustls | =0.23.45 | The spine's pin (stack table); features `aws_lc_rs` and `prefer-post-quantum` named explicitly, `tls12` only so a test shows a TLS 1.2 client is refused |
| tokio-rustls | =0.26.6 | The spine's companion pin; drives rustls on tokio sockets |
| aws-lc-rs | 1.18.2 (aws-lc-sys 0.46.0), as pulled by rustls | The provider D27 names; `.cargo/config.toml` sets `AWS_LC_SYS_PREBUILT_NASM=1` for the Windows dev host |
| tokio | 1.53.3 | Async runtime for the server and the probe |
| rcgen | 0.14.10, aws-lc-rs backend | Test CA and server certificate only; the aws-lc-rs backend avoids pulling ring next to aws-lc-rs |

Client images, pinned by digest in `docker/compose.yaml` (tags as pulled on 2026-10-16): `rust:1-trixie`, `debian:trixie-slim` and `debian:bookworm-slim` (curl and OpenSSL from each release's own packages, installed at build), `node:24-trixie-slim`, `golang:1-trixie`, `mcr.microsoft.com/playwright:v1.64.1-noble` (with the matching `playwright@1.64.1` npm package). Package versions in the Debian images are not pinned; each run prints them, and the table below carries the ones of this run.

The browsers load the page with `ignoreHTTPSErrors`, because the test CA is not in their trust store. That skips certificate validation only; the key exchange is the browser's normal one. The other clients verify the server against the test CA.

Finding that changes a sentence of the design: rustls 0.23.45 does not impose its own group order in TLS 1.3. It selects the first group of the client's `supported_groups` that it supports (`choose_suite_and_kx_group` in `rustls/src/server/hs.rs`), then answers with a HelloRetryRequest if the client sent no key share for that group. The provider's order (`prefer-post-quantum` puts `X25519MLKEM768` first) decides what a rustls client offers, not what a rustls server picks. A client that supports the hybrid group but lists it after X25519 gets X25519 (test `server_follows_the_client_group_order`). Every hybrid-capable client tested lists the hybrid group first, so the observed effect is the same today, but "the server prefers" in `architecture.md` section 15 is not accurate. `run.sh` checks the rule on every recorded handshake (`client_order.<client>`).

Open decision tasks settled (recommended answers, recorded here):

1. **Clients that cannot run on this host** (Safari, Android System WebView, Chrome for Android, OkHttp, Cronet, the native app's own build): recorded as "Not run here" with the manual procedure below, not inferred from a desktop engine. Playwright's WebKit on Linux is reported as its own row and is not Safari: it uses the WebKitGTK network stack, not Apple's TLS stack. Recommendation: the README names only the clients that were run; the Android and Apple clients are run by hand before the README lists them.
2. **Server-side group order**: accept rustls's client-order selection; do not patch or wrap rustls to force the hybrid group. This keeps the server free of custom TLS code (D28); it gives up the hybrid exchange for a client that supports it but lists it second, and none was observed. The README and the architecture both say the hybrid exchange is used when the client prefers it, that is lists it before any other group the server supports, and D27 gets a clarifying sentence (item 6 below).
3. **Classical fallback**: kept and checked. A client without the hybrid group (rustls restricted to X25519, curl with `--curves X25519`, curl and OpenSSL 3.0 on Debian 12, WebKit on Linux) connects with a classical group; nothing is refused for lacking ML-KEM.
4. **TLS 1.2**: the spike server is TLS 1.3 only, as D27 says; a TLS 1.2-only client is refused (test `tls12_only_client_is_refused`). No client in the table needed TLS 1.2.

Manual procedure for the clients not run here (Android System WebView, Chrome for Android, OkHttp, Cronet, Safari on iOS or macOS, the native app):

1. On the dev host, from `spikes/hybrid-kex/`: `cargo run --release -- serve 0.0.0.0:8443 <scratch directory outside the repository> <host LAN address, for example 192.0.2.10>`. The server prints its `SERVER` line, writes `ca.pem` into the scratch directory, and logs one `HANDSHAKE` line per connection. Open TCP 8443 on the host firewall for the LAN only.
2. Browsers and WebView on a phone on the LAN, or on a Mac: open `https://192.0.2.10:8443/client/<client>-<version>` (for example `android-chrome-<version>`, `android-webview-<version>` from any app that renders a WebView, `safari-ios-<version>`), and accept the certificate warning or install `ca.pem` as a user CA. The page shows the server's record; the same line is in the server log.
3. OkHttp and Cronet: a minimal Android test app requesting the same URL with each library, trusting `ca.pem` through a network security configuration; read the server log.
4. The native app: once it exists, point its rustls build at the same server; the in-process `rustls-default` row is the library baseline, not a substitute.
5. Record each `HANDSHAKE` line's `group`, `offered`, `key_shares` and `hrr` fields with the client version in the E3 table, then delete the scratch directory.

## Result

Run on 2026-10-16 on the Windows dev host with Docker Desktop: `bash spikes/hybrid-kex/run.sh` printed 100 `PASS` lines, no `FAIL`, and `RESULT PASS` (exit 0), then left no container or compose volume behind. Host checks from `spikes/hybrid-kex/`: `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` (19 passed, 0 ignored), all clean; `run.sh` repeats them in the Debian 13 Rust container.

Per-client table from `run.sh` (server: rustls 0.23.45, aws-lc-rs 1.18.2, groups `X25519MLKEM768,X25519,secp256r1,secp384r1`, TLS 1.3 only). "Offered groups" is the client's `supported_groups` in its own order, GREASE removed; "HRR" says whether the server had to send a HelloRetryRequest.

| Client | Version | Offered groups | Key shares | Negotiated | HRR |
|---|---|---|---|---|---|
| rustls-default | rustls 0.23.45 (aws-lc-rs 1.18.2), provider default groups | X25519MLKEM768, X25519, secp256r1, secp384r1 | X25519MLKEM768, X25519 | X25519MLKEM768 | no |
| rustls-classical | rustls 0.23.45 (aws-lc-rs 1.18.2), X25519 only | X25519 | X25519 | X25519 | no |
| curl-debian13 | curl 8.14.1, OpenSSL 3.5.7, Debian 13 | X25519MLKEM768, X25519, secp256r1, X448, secp384r1, secp521r1, ffdhe2048, ffdhe3072 | X25519MLKEM768, X25519 | X25519MLKEM768 | no |
| curl-debian13-x25519 | curl 8.14.1, OpenSSL 3.5.7, `--curves X25519` | X25519 | X25519 | X25519 | no |
| openssl-debian13 | OpenSSL 3.5.7 `s_client`, Debian 13 | X25519MLKEM768, X25519, secp256r1, X448, secp384r1, secp521r1, ffdhe2048, ffdhe3072 | X25519MLKEM768, X25519 | X25519MLKEM768 | no |
| openssl-debian13-hrr | OpenSSL 3.5.7 `s_client`, `-groups X25519MLKEM768:*X25519` | X25519MLKEM768, X25519 | X25519 | X25519MLKEM768 | yes |
| curl-debian12 | curl 7.88.1, OpenSSL 3.0.22, Debian 12 | X25519, secp256r1, X448, secp521r1, secp384r1, ffdhe2048 to ffdhe8192 | X25519 | X25519 | no |
| openssl-debian12 | OpenSSL 3.0.22 `s_client`, Debian 12 | X25519, secp256r1, X448, secp521r1, secp384r1, ffdhe2048 to ffdhe8192 | X25519 | X25519 | no |
| node | Node.js v24.22.0, bundled OpenSSL 3.5.8 (client side also reports X25519MLKEM768) | X25519MLKEM768, X25519, secp256r1, X448, secp384r1, secp521r1, ffdhe2048, ffdhe3072 | X25519MLKEM768, X25519 | X25519MLKEM768 | no |
| go | Go 1.27.2 `crypto/tls` defaults (client side also reports X25519MLKEM768) | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, secp256r1, secp384r1, secp521r1 | X25519MLKEM768, X25519 | X25519MLKEM768 | no |
| chromium | Chromium 156.0.8078.4, headless (Playwright 1.64.1) | X25519MLKEM768, X25519, secp256r1, secp384r1 | X25519MLKEM768, X25519 | X25519MLKEM768 | no |
| firefox | Firefox 157.0, Playwright build, headless | X25519MLKEM768, X25519, secp256r1, secp384r1, secp521r1 | X25519MLKEM768, X25519, secp256r1 | X25519MLKEM768 | no |
| webkit-linux | WebKit 27.2 on Linux, Playwright build (not Safari) | secp256r1, secp384r1, secp521r1, X25519, X448, ffdhe2048 to ffdhe8192 | secp256r1, X25519 | secp256r1 | no |
| Safari (macOS, iOS) | - | Not run here | - | - | - |
| Android System WebView | - | Not run here | - | - | - |
| Chrome for Android | - | Not run here | - | - | - |
| OkHttp | - | Not run here | - | - | - |
| Cronet | - | Not run here | - | - | - |
| Native app (its rustls build) | - | Not run here: the app is not built; `rustls-default` is the library baseline | - | - | - |

**AC1: partly met.** The negotiated group is recorded per client and version for every client that can run on this host: Chromium and Firefox (Playwright's builds, standing in for current Chrome and Firefox desktop), the rustls client, curl and OpenSSL 3.5 (Debian 13) and 3.0 (Debian 12), Node.js and Go. Safari, Android System WebView, OkHttp and Cronet, which AC1 names, are "Not run here": they need an Apple device or an Android device or test app, and the manual procedure above records them. The server is rustls 0.23.45 with the aws-lc-rs provider and `X25519MLKEM768` first in its configured groups (test `server_lists_the_hybrid_group_first_and_keeps_x25519`, `SERVER` line of every run), under `spikes/hybrid-kex/` instead of `spikes/e3-tls/`. Evidence: the `handshake.<client>`, `group.<client>`, `hrr.<client>` and `client_order.<client>` checks and the table above. Command: `bash spikes/hybrid-kex/run.sh`.

**AC2: met, with a wording change proposed.** The current README sentence ("TLS 1.3 with a hybrid X25519 plus ML-KEM key exchange when both the client and the TLS terminator support it. ... No claim of quantum safety is made") makes no claim beyond D27 and the table does not contradict it: every client that listed the hybrid group first negotiated it, and every client without it still connected with a classical group. Since it names no client, it claims the hybrid exchange for no client in particular. The proposed wording below names the tested clients that negotiated it, says that the others fall back to a classical exchange, says which clients are untested, and keeps every D27 limit; it never calls the product "post-quantum" or "quantum-safe". Evidence: the table; the `client_order.*` checks show the rule the wording describes.

**AC3: met.** The result changes wording only: the README transport sentence, a precision in `architecture.md` section 15, and the E3 records in `research-notes.md`. No V0.1 story waits on it, no fallback is taken (the classical fallback D27 keeps is confirmed), and no decision changes.

## Proposed design document updates

Not applied: this spike does not edit shared design documents.

1. `README.md`, the **Transport** bullet of the security list: replace it with "**Transport**: TLS 1.3 with the hybrid X25519MLKEM768 key exchange when the client prefers it (lists it before any other group the server supports) and Vilicus itself terminates TLS. In testing on 2026-10-16, Playwright builds of Chromium 156 and Firefox 157, curl and OpenSSL 3.5, Node.js 24 (OpenSSL 3.5) and Go 1.27 negotiated it; clients without it, such as those on OpenSSL 3.0 or WebKit on Linux, connect with a classical exchange instead. Safari and Android clients are not tested yet. Signatures and WebAuthn remain classical, and a third-party reverse proxy that terminates TLS removes the end-to-end benefit. No claim of quantum safety is made".
2. `doc/architecture.md`, section 15, first sentence of the TLS bullet after "TLS 1.3.": replace "The server prefers the hybrid key exchange X25519MLKEM768 (rustls with aws-lc-rs and its `prefer-post-quantum` option) when the client offers it, tested by real handshake on every supported client." with "The server negotiates the first group in the client's list that the server also supports (rustls follows the client's group order in TLS 1.3), and its groups (rustls with aws-lc-rs) include the hybrid key exchange X25519MLKEM768, so a client that lists X25519MLKEM768 first gets it; every hybrid-capable client tested in E3 does. Tested by real handshake on the desktop and command-line clients (E3); Apple and Android clients pending."
3. `doc/research-notes.md`, section 1.1, row "TLS hybrid": replace the claim with "rustls with the aws-lc-rs provider lists `X25519MLKEM768` first in its default key exchange groups; as a TLS 1.3 server, rustls 0.23.45 selects the first group of the client's list that it supports" and the status "Reported" with "Verified (story 1.16, `spikes/hybrid-kex/`)".
4. `doc/research-notes.md`, section 3, E3 row, Pass criterion column: after "the run itself is what V0.1 requires", add: "**Run** (story 1.16, `spikes/hybrid-kex/`, 2026-10-16): X25519MLKEM768 negotiated by Chromium 156 and Firefox 157 (Playwright builds), curl 8.14.1 and OpenSSL 3.5.7 (Debian 13), Node.js 24.22 (OpenSSL 3.5.8), Go 1.27.2 and rustls 0.23.45; X25519 by curl 7.88.1 and OpenSSL 3.0.22 (Debian 12) and by clients restricted to X25519; secp256r1 by WebKit 27.2 on Linux (not Safari); every classical client connected. Safari, Android System WebView, Chrome for Android, OkHttp, Cronet and the native app are still to run, by the manual procedure in story 1.16."
5. `doc/research-notes.md`, status line: in "Apart from the AD-36 construction (D119), nothing here has been proven by a prototype.", also name E3 as run for the desktop and command-line clients; at the end of the update paragraph, add "Story 1.16 then ran E3 for the desktop and command-line clients; the Apple and Android clients remain." If another spike has changed this sentence first, merge both.
6. `doc/decisions.md`, D27: no new decision record; after "where the client supports it, tested by real handshake on each client;", add the clarifying sentence: "The server takes the first group in the client's list that it also supports, so the hybrid exchange is used when the client prefers it (lists it before any other group the server supports); a client that lists a classical group first gets that classical group (E3)."
