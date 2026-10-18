---
title: 'Epic 1 QA report: V0.1 spikes'
author: Rwx-G
date: 2026-10-17
target: 'V0.1 spikes'
epic: 1
run: 'e2e/results/20261017T083324Z-6665c6b'
---

# Epic 1 QA report: V0.1 spikes

Author: Rwx-G. Date: 2026-10-17. Target: V0.1 spikes (Epic 1, stories 1.1 to 1.17).

This report rests on one end-to-end campaign, `bash e2e/run.sh --keep-going` at commit
`6665c6b798591d42df3e9f3f323ed770303f74cf`, and on the Result, Implementation Notes and review
sections of the 17 story files. Gates are under [`gates/`](gates/), one per story. A gate never
claims more than this run showed.

## 1. Executive summary

- **All 17 phases passed**: 7 230 `PASS` lines, 0 `FAIL` lines, 27 `KNOWN-FAIL` lines (all in
  the unsanitized control of story 1.14, by design), in 61 minutes, phases run one after the
  other, the CPU-sensitive ones only on an idle engine.
- **Gates: 4 PASS, 12 CONCERNS, 1 FAIL.**
  - PASS: 1.1 (AD-36 construction), 1.7 (E11 authorizer), 1.9 (E19 Rust and TypeScript),
    1.11 (E17 secure delete).
  - FAIL: 1.12 (E14). Every AC check passed, but the spike's own pass criterion, "no bypass of
    the allowlist", is not met: domain fronting on a shared front end bypasses the hostname
    allowlist. The documented fallback (per-plugin IP ranges) does not close it; the SNI check
    closes half, and D134 waits for the owner.
  - CONCERNS: every other story. Each passed what ran, but its own criterion needs a run this
    environment cannot do: Android and Safari (1.3, 1.4, 1.5, 1.14, 1.16), the reference host
    (1.8, 1.10, 1.15), a Debian 13 host (1.6), a CI job (1.2), the household's phones for 7 days
    (1.13), the household's devices (1.17).
- **What this environment is**: Docker Desktop on a Windows development host, Linux containers on
  the WSL2 kernel 6.18 (not Debian 13's 6.12), Debian 13 userland and systemd 257 inside
  containers, a 4-CPU and 8 GB quota emulating the reference host, headless desktop Linux
  browsers (Chromium and Firefox builds, some vendor builds), virtual WebAuthn authenticators,
  test CAs. No Android device, no Apple device, no real authenticator, no reference host, no
  Debian 13 host or VM, no CI.
- **Owner decisions pending**: 11 Proposed decision records (D121, D123, D125, D127, D128, D129,
  D134, D135, D136, D137, D138), listed in section 10. Three of them are Proposed only until a
  rerun on the target system (D125, D128, D136); the other eight need an owner choice.
- **Experiments still open** after this epic: E1, E13 (not measured at all), and the device or
  host halves of E2, E3, E10, E12, E14, E16, E22, E24, E26, E32, plus the Kotlin part of E19 and
  the HPKE CI job (section 11).

## 2. Scope: what was run, and what was not

| Dimension | What ran here | What the stories ask for, not run here |
|---|---|---|
| Host | Docker Desktop 29.8.2, Windows development host, 24 CPUs, Linux VM on the WSL2 kernel 6.18.33.2 | Reference host (4 physical cores, 8 GB, SSD, no GPU, Debian 13 amd64, D113) |
| Operating system | Debian 13 userland in containers; systemd 257 as PID 1 in privileged containers | A Debian 13 host or VM with kernel 6.12, AppArmor active, `systemd-coredump` |
| CPU and memory | `--cpus=4 --memory=8g` CFS quota on a larger desktop CPU | 4 physical cores and their memory bandwidth |
| Storage | overlayfs on a virtual disk file on the desktop's SSD | The reference host's SSD |
| Browsers | Headless Chrome for Testing 155 and 154, Playwright Chromium 156 and 153, Playwright Firefox 157 and 155, Mozilla Firefox 158.0, 157.0 and 157.0.1, Playwright WebKit on Linux | Chrome and Firefox on Android, Safari on macOS and iOS, branded Chrome on Windows and macOS |
| Authenticators | CDP and WebDriver virtual authenticators | Platform authenticators, password managers acting as passkey providers, security keys |
| PKI | Test CAs installed in each browser's NSS store | A real public CA (built-in root, Certificate Transparency), a real DNS-01 certificate |
| Phones | None | The household's Android phones (E13 for 7 days, E1 PRF) |
| CI | None exists (spine AD-33) | The HPKE vectors and cross-test job of D61 |

Every story names its gaps under "Not run here"; section 4 lists them per story.

## 3. Coverage

| Story | Suite (phase) | Spike | Assertions | Failed | Gate | Result in one line |
|---|---|---|---|---|---|---|
| 1.1 | `ad36` | `spikes/ad36-key-prototype/` | 48 | 0 | PASS | AD-36 construction holds against a disk writer without HK; 44 tests |
| 1.2 | `hpke` | `spikes/hpke-review/` | 12 | 0 | CONCERNS | Vectors and 10 000-case cross-test against two providers pass; CI job absent, review dispositions await the owner |
| 1.3 | `device-key` | `spikes/browser-device-key/` | 271 | 0 | CONCERNS | E22 passes on four desktop browsers; Android not run |
| 1.4 | `naming` | `spikes/naming-options/` | 199 | 0 | CONCERNS | Three naming options pass on desktop Linux with virtual authenticators; Android, real authenticators, two-passkey Firefox open |
| 1.5 | `passkey` | `spikes/passkey-stepup/` | 112 | 0 | CONCERNS | Login and action-bound step-up pass on four desktop browsers; Android, Safari, real authenticators not run |
| 1.6 | `sandbox` | `spikes/sandbox-profile/` | 146 | 0 | CONCERNS | Profile and peer identity hold under systemd 257 in a container; Debian 13 host rerun pending |
| 1.7 | `authorizer` | `spikes/sqlite-authorizer/` | 255 | 0 | PASS | Every hostile statement refused, nothing written |
| 1.8 | `argon2id` | `spikes/argon2id-params/` | 10 | 0 | CONCERNS | m = 384 MiB, t = 3, p = 4 under target on the emulation; reference host pending |
| 1.9 | `cbor` | `spikes/canonical-cbor/` | 39 | 0 | PASS | Rust and TypeScript agree on bytes, hashes and rejections behind the profile layer |
| 1.10 | `locked-memory` | `spikes/locked-memory/` | 66 | 0 | CONCERNS | No key material after drop in the Core shape; reference host and pipe `core_pattern` pending |
| 1.11 | `secure-delete` | `spikes/secure-delete-wal/` | 29 | 0 | PASS | No deleted plaintext after `secure_delete` ON plus a TRUNCATE checkpoint |
| 1.12 | `egress` | `spikes/egress-filter/` | 189 | 0 | FAIL | ACs pass; "no bypass" criterion not met (domain fronting) |
| 1.13 | `push` | `spikes/push-delivery/` | 78 | 0 | CONCERNS | Tooling proven in simulation; no E13 measurement exists |
| 1.14 | `separate-origin` | `spikes/separate-origin/` | 5 590 | 0 | CONCERNS | Isolation holds with the sanitizer on every desktop browser, option and proxy; Android not run |
| 1.15 | `core-execution` | `spikes/core-execution/` | 41 | 0 | CONCERNS | D116 p99 met in emulation; reference host pending |
| 1.16 | `hybrid-kex` | `spikes/hybrid-kex/` | 100 | 0 | CONCERNS | Groups recorded for desktop and command-line clients; Apple and Android clients not run |
| 1.17 | `prf-probe` | `spikes/prf-probe/` | 45 | 0 | CONCERNS | Probe proven with a virtual authenticator; household devices not run |

Gate totals: **4 PASS, 12 CONCERNS, 1 FAIL**.

## 4. Per-story results

Each entry states what the run showed, what remains "Not run here", and the gate. Numbers are
from this campaign unless the story's own run is named.

### 1.1 Key prototype: AD-36 public-key authentication (gate PASS)

- Shown: 44 tests in Debian 13 (rustc 1.99.1), with `fmt` and `clippy` clean. A substituted
  member or inbox public key, an edited tag or enrollment wrap, a permanent MAC edited after the
  first wrap, and a wrong or reused token are refused; an honest enrollment receives HK.
  Known-answer tests pin the byte layouts. D119 is Accepted and key management section 2 holds
  the encodings.
- Not run here: nothing the story's criterion asks for. By design outside the spike: the
  passphrase and DEK layer, delay and veto, token expiry, alert delivery, inbox MACs (home
  milestone), the Gateway limit of step 7.
- Open: `wrappers.db` is not authenticated as a whole (deletion and rollback undetected), in
  `doc/stories/deferred-work.md`; D121 (Proposed) adds an HK commitment at unlock and leaves the
  first receipt open.

### 1.2 HPKE internal review and cross-test (gate CONCERNS)

- Shown: `run.sh` in the pinned Debian 13 image: the RFC 9180 vector of the AD-18 suite for
  `hpke` 0.13.0 and for `hpke-rs` 0.8.0 with both providers, the 10 000-case two-way
  cross-test against the RustCrypto and the libcrux providers, error paths, sender
  substitution, `zeroize` features and the dependency tree. `REVIEW.md`: 13 findings, none
  High, each closed or accepted. D120 is Accepted.
- Not run here: the CI job D61 requires (no CI exists); `cargo audit` inside the container
  (run on the host only, the story reports 0 vulnerabilities and one unmaintained warning).
- Open: the review's dispositions become final when the owner approves `REVIEW.md`; F12 (base
  mode authenticates no sender) leads to D121.

### 1.3 E22: browser device key, PAKE pairing and signed confirmations (gate CONCERNS)

- Shown: 271 checks: 27 Rust tests, then 58 checks per browser on Chrome for Testing 155 and
  154 and Firefox 158 and 157, headless, certificates validated. Non-extractable key survives
  reload and restart and refuses export; AD-21 signatures verify in Rust; replay, tampering and
  out-of-order arrival refused; a pairing code binds the new browser's key; relayed, replayed
  and substituted-registration runs refused; light confirmations approve only their request.
  D122 is Accepted.
- Not run here: Android (Chrome and Firefox, current and previous), which the pass criterion
  names; Safari (best effort); field trials of a user's Chrome; clearing site data.
- Open: D123 (OPAQUE libraries under an exception to D28) awaits the owner.

### 1.4 E24: passkeys and PWA with each naming option (gate CONCERNS)

- Shown: 199 checks: 10 Rust tests, 13 DNS and reachability checks, 48 checks per Chrome and
  36 per Firefox on Chrome 155 and 154 and Firefox 158 and 157. The three FR-65 options pass
  registration and login; Chrome reports them installable. Every browser refuses WebAuthn on an
  IP origin; over the self-signed certificate the outcome is refusal or a credential bound to a
  host unusable on the instance name, except that `localhost` runs the ceremony.
- Not run here: Android, Windows and macOS desktops, Safari, real authenticators, a real public
  CA, installability on Firefox, mDNS for `.local`.
- Open: Firefox's virtual authenticator refused every allow list of two credentials; the story
  holds the E24 gate until Firefox is tried with a real authenticator. D137 and D138 await the
  owner.

### 1.5 E2 login half: passkey login and action-bound step-up (gate CONCERNS)

- Shown: 112 checks: 32 tests (17 ceremony, 15 unit), then 17 checks per browser on Playwright
  Chromium 156 and 153 and Firefox 157 and 155, virtual authenticators, certificate validated.
  The step-up challenge is derived from the request hash and a session handle; another
  request, another hash, a replay, an expired request, another session and a missing user
  verification are refused. D124 is Accepted.
- Not run here: Android (named by D107 as supported), Safari, real authenticators and password
  manager providers; vendor release channels (Playwright builds stand in for Chrome and Firefox).
- Open: `webauthn-rs` 0.5.5 has no API to set a challenge; the state-serialization workaround is
  guarded by tests until upstream provides one.

### 1.6 E10: sandbox profile and peer identity (gate CONCERNS)

- Shown: 146 checks: 11 tests and 131 systemd checks under systemd 257 (Debian 13) as PID 1.
  The reference plugin works under `DynamicUser=yes`, `LoadCredential=`, the full template
  profile and `IPAddressDeny=any`; every direct socket fails, with a control unit showing each
  outcome is the profile's. The Core accepts the expected unit and refuses another unit with
  the same uid, a spoofed cgroup leaf name, a process outside any unit and a reused pid.
- Not run here: a Debian 13 host or VM (kernel 6.12, AppArmor). The run's kernel is 6.18, and
  finding 2 (a late pidfd is returned) already differs from what 6.12 is expected to do.
- Open: D125 stays Proposed until the host rerun.

### 1.7 E11: SQLite migration authorizer (gate PASS)

- Shown: 255 checks: 28 test functions and 223 individual checks. The 23 hostile statements end
  a migration with nothing written; 25 are refused on read and write connections while `SELECT`
  succeeds; controls without the authorizer show each statement would run. The extension loading
  C API, invisible to the authorizer, is turned off at open. D126 is Accepted.
- Not run here: the compile-out build (`SQLITE_OMIT_LOAD_EXTENSION`), handed to Story 3.1.
- Open: D127 (FTS5 virtual tables in migrations) awaits the owner; E15 checks the shadow tables.
- The story file records no review triage, so this report cannot cite its review findings.

### 1.8 E12: Argon2id parameters on the reference host (gate CONCERNS)

- Shown (this campaign, emulation profile): 13 tests, RFC 9106 and reference vectors, the floor
  and ceiling. m = 384 MiB, t = 3, p = 4 on a 2-thread pool: median 384.5 ms, p95 398.2 ms; two
  simultaneous unlocks under a limit of 1: slower median 747.9 ms, max 815.3 ms, against a
  2 000 ms target. The selection rule picked the constant. A burst of 8 under the 4 s bound
  served 8, peak resident memory 386 MiB.
- Not run here: the reference host, which is E12's pass criterion. A CPU quota on a 24-core
  desktop is not 4 physical cores, and Argon2id is bound by memory bandwidth.
- Open: D128 (parameters, Proposed until the reference host), D129 (exception to D28 for
  `argon2` and `rayon`), and the conflict with D136 on the Argon2id pool (section 8).

### 1.9 E19: canonical CBOR in Rust and TypeScript (gate PASS)

- Shown: 39 checks: `dcbor` 0.25.2 and `cbor2` 2.4.0 behind the profile layer agree on bytes and
  SHA-256 over the committed corpus (722 values) and a fresh one (24 122), refuse all 90
  hand-written inputs, and give the same verdict on 2 507 committed and 100 007 fresh fuzzed
  inputs, both on Unicode 17.0. The vectors are committed under `spikes/canonical-cbor/vectors/`.
  D130 is Accepted.
- Not run here: the Kotlin part, which the story assigns to the native app milestone.
- Open: `dcbor` brings `paste` (RUSTSEC-2024-0436, unmaintained), to be listed in `deny.toml`.

### 1.10 E16: locked memory and zeroization (gate CONCERNS)

- Shown: 66 checks (6 steps, 60 checks) in four containers with different capabilities. In the
  Core shape no key or derived secret is found after drop on any tested path, while the default
  shape's residue on the same path is asserted as the control. No crash path writes a core
  dump; a panic outside a handler and SIGTERM wipe the pool. D131 is Accepted.
- Not run here: the reference host (FR-13 names it); a pipe `core_pattern` with
  `systemd-coredump` (the run's `core_pattern` was a file, and AC2's "no core dump" is shown for
  that case only); the passphrase through the Gateway and IPC, the async runtime, the recovery
  and backup secrets, SQLCipher's internal key handling.
- Accepted limits: abort paths without user code keep keys until exit; registers beyond ymm15;
  kernel-side copies.

### 1.11 E17: secure_delete and WAL behaviour (gate PASS)

- Shown: 29 checks: 5 tests and 24 checks on decrypted pages and WAL frames. With `secure_delete`
  ON and a TRUNCATE checkpoint, no run of 8 bytes or more of a deleted row or destroyed wrapped
  key remains; without the checkpoint, rows persist in the WAL until a TRUNCATE checkpoint, the
  last close or a WAL restart under `journal_size_limit`. D132 is Accepted.
- Not run here: filesystem and SSD remanence (ciphertext only, outside the claim); concurrent
  readers making a checkpoint busy. The measurement is of file content, which does not depend on
  the host.

### 1.12 E14: egress proxy domain filtering (gate FAIL)

- Shown: 189 checks: 43 tests and 140 network checks. HTTP/1.1, HTTP/2, IPv6, websocket, a
  64 MiB download and 50 concurrent tunnels work; QUIC cannot leave without the proxy;
  redirects, IP literals and the other attempts of the 34 `bypass.*` checks are refused; a rebinding name is refused at
  connect time; direct connections fail under `IPAddressDeny=any`. D133 is Accepted.
- Failed criterion: domain fronting. On a shared front end an allowlisted hostname carries
  requests to another tenant named in SNI or in the Host header. Per-plugin IP ranges, the
  documented fallback, do not close it. The per-caller SNI check closes the SNI half; Host-header
  fronting remains (R54, T67). D134 awaits the owner.
- Not run here: the Debian 13 VM run of the direct-connection checks; file descriptor
  exhaustion; a real CDN; Encrypted Client Hello end to end.

### 1.13 E13: push delivery reliability (gate CONCERNS)

- Shown: 78 checks: 37 tests and 37 network checks on a simulated network with two ntfy 2.31.0
  servers and two simulated phones. Content-free payloads as stored by each server, anonymous
  records, topic access control, and the verdict rules (99 % in 10 minutes, completeness
  conditions) work; an injected fault fails the run. The simulated report's public server FAIL
  is the designed fault, labelled `criterion=simulation`.
- Not run here: **the measurement itself**. No household phone has run for 7 days; no E13
  result exists, and the story stays `in-progress`. CONCERNS here means "tooling ready, gate
  open"; E13 gates V0.1 and is not passed.
- Open: D135 (no token in the push payload, server reachable off the household network).

### 1.14 E26: separate origin by port for external content (gate CONCERNS)

- Shown: 5 590 checks with six harnesses: 1 110 per Playwright browser (Chromium 156 and 153,
  Firefox 157 and 155) and 558 per Mozilla Firefox (158.0, 157.0.1), on nine names (three naming
  options times direct, Caddy and nginx). In production (sanitizer, CSP, sandbox) no script,
  form, popup, navigation, subresource, preconnect or DNS prefetch reached any server, and
  content-started requests were cross-site without the cookie. D139 is Accepted.
- Anomalies: 27 `KNOWN-FAIL` lines and 22 Firefox 155 retries, explained in section 9.4.
- Not run here: Android (Chrome and Firefox), Safari, branded Chrome; a real public CA (the stand-in
  CA is installed in the browsers).

### 1.15 E32: Core execution model (gate CONCERNS)

- Shown (this campaign, gate run `ad9`, 600 s, 3 permits): member probe p99 21.18 ms (max
  58.89 ms), token probe p99 25.21 ms (max 61.77 ms), all actions p99 22.51 ms over 23 687
  samples, against D116's 100 ms; rule wake to dispatch p99 0.022 ms; 1 366 unlocks, 275 backup
  cycles, 0 errors, audit chain verified (18 135 entries); 0 throttled CFS periods. The
  sensitivity run with 4 permits stays under the criterion (p99 28.35 ms, informational).
- Not run here: the reference host. Not modelled: the AD-12 handshake, CBOR framing, MCP, peer
  identity, outbox delivery, systemd units, the real `hpke` crate, the final Argon2id parameters.
- Open: D136 (Proposed until the reference host), and its conflict with D128 (section 8).

### 1.16 E3: hybrid key exchange negotiation (gate CONCERNS)

- Shown: 100 checks: 19 tests and the per-client table. X25519MLKEM768 is negotiated by
  Chromium 156 and Firefox 157 (Playwright builds), curl 8.14.1 and OpenSSL 3.5.7, Node.js 24,
  Go 1.27.2 and rustls 0.23.45; classical clients (OpenSSL 3.0, WebKit on Linux, X25519-only)
  connect classically. rustls as a TLS 1.3 server follows the client's group order.
- Not run here: Safari, Android System WebView, Chrome for Android, OkHttp, Cronet, the native
  app, all named by AC1.
- The README transport wording stays within D27; a more precise sentence is proposed in the story.
- The story file records no review triage.

### 1.17 E1 and E2 PRF half: early run (gate CONCERNS)

- Shown: 45 checks with Chromium 156 and a virtual authenticator with PRF: 32-byte outputs stable
  per salt across sessions, different per credential, never posted raw; `webauthn-rs` 0.5.5 has
  no `prf` extension and PRF works beside it.
- Not run here: the household's devices (AC1 and the browser half of AC2); the native Credential
  Manager app is not built. The story stays `in-progress`. It gates nothing in V0.1 (AC3).
- The story file records no review triage.

## 5. What a green unit suite could not see

The stories found these only because the run reached a real browser, a real systemd, a real
file on disk or real process memory. Each would have passed a unit suite.

- **Chrome lets DevTools-protocol code run `eval` despite the CSP** (1.3). A probe called
  through `page.evaluate` reported `eval` allowed; probing from the page's own module shows it
  blocked. A CSP browser test must probe from the page.
- **A virtual authenticator changes what Chrome allows** (1.4). The CDP authenticator lets Chrome
  run a ceremony over a certificate error that Chrome otherwise refuses; a CI run with it cannot
  show the D76 refusal.
- **Firefox preconnects despite CSP** (1.14). Without the sanitizer, `<link rel=preconnect>`
  made Firefox 157 and 158 resolve the attacker's name; CSP and `X-DNS-Prefetch-Control` did not
  stop it.
- **`ProtectProc=invisible` hides `/proc/<pid>/cgroup` from the Core** (1.6), so the peer
  identity method of AD-24 as written did not work under the Core's own profile.
- **`LoadCredential=` mounts nothing in a container with a private root mount** (1.6): the
  credential directory is set but empty, with no error.
- **The bundled SQLCipher build enables the extension loading C API** (1.7), which the
  authorizer cannot see.
- **`dcbor` accepts integral floats, recurses without a bound and collapses NFC-equal keys**
  (1.9); the fuzzer and a stack overflow found the first two.
- **`argon2` 0.6.0 frees its blocks without wiping them** (1.8, 1.10), and an HPKE call leaves its
  key schedule on the stack (1.10).
- **A PASSIVE checkpoint leaves deleted rows in the WAL** (1.11), unbounded in time while
  connections stay open.
- **`IPAddressDeny=any` drops rather than rejects** (1.6, 1.12): a direct TCP connect times out.
- **`0.0.0.0` reaches the proxy host's own listeners** (1.12).
- **systemd 257 prints the `IPAddressDeny` prefixes in an order that varies per boot** (1.6); an
  independent run failed on order alone until the check compared sets.

## 6. Failure patterns worth naming

- **Measuring the wrong process.** The CSP probe through DevTools (1.3), the virtual
  authenticator bypass (1.4), and a scan that counted unreadable mappings instead of failing
  (1.10) each reported a property of the test tool, not of the product. Fix pattern: a positive
  control that shows the detector fires, and a negative control that shows the absence is real.
- **A comparison over the same channel.** The first pairing design compared the OPAQUE server
  key with one fetched over the same channel (1.3); it proved nothing. A relay on the issuer's
  path is caught only by a Core signature with a pinned key.
- **Library defaults that are not the design.** Extension loading on (1.7), `secure_delete` ON
  only when keyed (1.11), `webauthn-rs` checking the counter against a per-state snapshot (1.5),
  rustls following the client's group order (1.16). Each needs an explicit setting read back.
- **Contention in the measurement.** The first E12 and E32 runs shared the Docker VM with other
  spikes; one E12 run picked a different parameter set. The campaign runs CPU-sensitive phases
  only on an idle engine, and its numbers are lower than the stories' (section 9.3).
- **Order and timing flakes in assertions.** `IPAddressDeny` prefix order (1.6), a shutdown race
  of the token probe (1.15), a burst bound set before measuring (1.8). Each was fixed in the
  check, not by retrying.

## 7. Reviews

Each spike had one combined review pass by independent review agents and one fix round before
its recorded run. The story files record the review outcome for 13 of the 17 stories; 1.7, 1.13,
1.16 and 1.17 hold no review triage, so this report does not cite findings for them. Classes of
defects the reviews caught, without listing every finding:

- **Verification gaps**: encodings checked only by round trip (1.1); refusal branches never the
  failing check (1.1); proof of possession, challenge for another device and expiry paths
  untested (1.3); browser checks not counted against an expected number (1.3); stack copies and
  scrub depth without a positive control, thread stacks never exercised (1.10); no positive
  control for the self-signed refusals (1.4).
- **Overclaims**: a drift test weaker than claimed (1.1); "E10 validates this on Debian 13" for a
  container run (1.6); "browsers refuse WebAuthn over the self-signed certificate", false on
  `localhost` (1.4); the Unicode skew direction (1.9); the latency tail attributed to backup
  pauses when idle files showed it too (1.15); "CSP reports" treated as enforcement evidence
  (1.14).
- **Fail-open paths**: certificate validation off in the browser driver (1.3); the browser signing
  whatever bytes it received (1.3); unauthenticated login starts spending a live code's attempts
  and revealing live handles (1.3); a panic hook that could not tell a caught panic from a fatal
  one, and error paths that skipped the Argon2id wipe and the stack scrub (1.10); a floor rule
  that let a below-floor set be recommended (1.8); `dcbor` silently collapsing map keys (1.9).

## 8. Cross-cutting findings

- **The Argon2id pool is specified twice, inconsistently.** D128 (story 1.8) proposes a separate
  two-thread pool with parallel lanes, which needs the `parallel` feature and `rayon` (D129). D136
  (story 1.15) sizes the blocking pool at cores minus one on the condition that Argon2id lanes run
  on one pool thread, without `parallel`. D128 and D136 both say they are settled together. Until
  the owner decides, Story 5.1 has no single execution model to build.
- **Exceptions to D28 accumulate.** HPKE (D61, D120), OPAQUE (D123, proposed), `argon2` (D129,
  proposed). Each is a recorded exception with a review and a cross-test; none of the three
  libraries is audited at the version pinned.
- **Every browser result is desktop Linux, headless, with Playwright or vendor test builds.**
  E2, E22, E24, E26 and E3 all wait on Android; the same manual device session can cover them
  together.
- **Every systemd result is systemd 257 in a privileged container on kernel 6.18.** E10, the
  E14 direct-connection checks and the E16 pipe `core_pattern` all wait on a Debian 13 host;
  Story 2.3's VM harness can run them together.
- **Every performance result is an emulation.** E12 and E32 wait on the reference host and should
  run there in the same session, with the Argon2id pool decision applied.
- **Downstream stories do not carry the spike results yet.** Stories 2.5, 3.1, 3.6, 4.2, 5.1, 5.3
  and 5.5 hold none of the proposed AC changes (checked by search for the key terms on
  2026-10-17).
- **Dependency hygiene**: `rustls` 0.23.45 is flagged by RUSTSEC-2026-0346 to 0349 (fixed in
  0.23.46, used by 1.3 and 1.4; 1.5, 1.13, 1.14, 1.16 and 1.17 still use 0.23.45); `paste`
  unmaintained through `dcbor`; `argon2` 0.5 duplicated through `opaque-ke`.

## 9. End-to-end run

### 9.1 Run context

From `run-info.txt` of `e2e/results/20261017T083324Z-6665c6b/`:

| Field | Value |
|---|---|
| Date (UTC) | 2026-10-17T08:33:24Z to 2026-10-17T09:34:52Z |
| Commit | `6665c6b798591d42df3e9f3f323ed770303f74cf` (branch `feat/epic-1-spikes`) |
| Uncommitted paths | 1 (the untracked `spikes/ad36-key-prototype/.cargo/`, redundant per story 1.1, left for the owner to delete) |
| Docker server | 29.8.2 |
| Docker engine | 24 CPUs, 50 182 365 184 bytes |
| Host | 24 CPUs, 97 666 MiB, MINGW64_NT-10.0-26200 |
| Kernel seen by the containers | 6.18.33.2-microsoft-standard-WSL2 |
| Results directory | `e2e/results/20261017T083324Z-6665c6b` (ignored by git) |

### 9.2 Exact command

```sh
git checkout 6665c6b798591d42df3e9f3f323ed770303f74cf
bash e2e/run.sh --keep-going
```

Phases run one after the other; CPU-sensitive phases (`argon2id`, `core-execution`) wait for an
idle engine. See `e2e/README.md` for the replay procedure.

### 9.3 Phase table

From `summary.tsv`. "Assertions" is the count of `PASS` lines; "Failed" of `FAIL` lines.

| Phase | Story | Status | Assertions | Failed | INFO | Duration (s) |
|---|---|---|---|---|---|---|
| ad36 | 1.1 | PASS | 48 | 0 | 1 | 3 |
| hpke | 1.2 | PASS | 12 | 0 | 0 | 43 |
| device-key | 1.3 | PASS | 271 | 0 | 86 | 56 |
| naming | 1.4 | PASS | 199 | 0 | 155 | 211 |
| passkey | 1.5 | PASS | 112 | 0 | 15 | 46 |
| sandbox | 1.6 | PASS | 146 | 0 | 75 | 19 |
| authorizer | 1.7 | PASS | 255 | 0 | 4 | 5 |
| argon2id | 1.8 | PASS | 10 | 0 | 6 | 376 |
| cbor | 1.9 | PASS | 39 | 0 | 27 | 15 |
| locked-memory | 1.10 | PASS | 66 | 0 | 21 | 6 |
| secure-delete | 1.11 | PASS | 29 | 0 | 4 | 33 |
| egress | 1.12 | PASS | 189 | 0 | 7 | 102 |
| push | 1.13 | PASS | 78 | 0 | 12 | 74 |
| separate-origin | 1.14 | PASS | 5 590 | 0 | 3 990 | 1 695 |
| core-execution | 1.15 | PASS | 41 | 0 | 51 | 951 |
| hybrid-kex | 1.16 | PASS | 100 | 0 | 2 | 39 |
| prf-probe | 1.17 | PASS | 45 | 0 | 12 | 11 |
| **Total** | | **17 PASS** | **7 230** | **0** | **4 468** | **3 685** |

Harness verdict: "all selected phases passed". A phase passing means the spike's own `run.sh`
exited 0; the gate verdict is separate and stated in section 3.

### 9.4 Anomalies, each explained

- **27 `KNOWN-FAIL` lines in `separate-origin`.** All are
  `<option>.<deployment>.unsanitized.ac2.blocked.preconnect`: nine names each for Playwright
  Firefox 157 and Mozilla Firefox 158.0 and 157.0.1. They are the unsanitized control of story 1.14
  finding 2 (Firefox resolves a preconnect host despite CSP when content is not sanitized). The
  harness fails the run if a listed check passes, is not run, or if any other check fails; none
  did. No production check is among them.
- **22 retries of Firefox 155 (Playwright 1.63) in `separate-origin`.** Each is an `INFO
  firefox-previous.retry ... attempt=1: page.goto: Timeout 30000ms exceeded`; the harness restarts
  that browser on the same profile and retries once with a new run id. No visit needed a second
  retry (no `attempt=2` line) and the four Playwright harnesses each reported 1 110 of 1 110
  checks. Story 1.14's own run had 13 such retries; no other browser needed one. The cause, a
  page load that never reaches DOMContentLoaded in that build, is not established.
- **`argon2id` has 10 assertions; story 1.8 records 11** for its final run while naming 10 checks.
  The campaign's 10 match the 10 named checks; the story's count looks like a slip in the story.
- **Measured values are lower than the stories' runs.** E12: single derivation median 384.5 ms
  here against 515.9 ms in the story's final run; E32: member probe p99 21.18 ms against
  28.01 ms, fsync p50 1.70 ms against 4.1 ms. The stories ran with other spike containers
  sharing the VM; the campaign ran each phase alone. Both are emulations; neither is the
  reference host.
- **E13 prints a public-server FAIL inside a passing phase.** It is the designed fault of the
  simulation (`criterion=simulation`, "this is not an E13 result").
- **`.cargo/` untracked in `spikes/ad36-key-prototype/`.** The one dirty path at run time;
  redundant, not used by the phase (which runs the built-in cargo gates in the container), and
  left for the owner because `rm` is denied in this workspace.

### 9.5 Not covered by the run

Real devices, the reference host, a Debian 13 host, CI, and the household phones: section 2,
and "Not run here" in each story, which carries the manual procedure.

## 10. Proposed decision records that need the owner

Settled on 2026-10-18; outcomes in section 17.

| Record | One line | Waits on |
|---|---|---|
| D121 | Commit to HK and its version under a DEK-derived key and refuse a different HK at later unlocks; how the first receipt of HK is confirmed stays open | Owner decision before FR-8 code |
| D123 | Use `opaque-ke` 4.0.1 and `@serenity-kit/opaque` under a recorded exception to D28, with a review and cross-test before FR-16 code | Owner decision |
| D125 | Identify a peer by cgroup membership of the unit's `ControlGroup` then pidfd liveness, watch the pidfd for the connection's life; default template profile; IP filter startup check | Rerun of E10 on a Debian 13 host |
| D127 | Allow `CREATE` and `DROP VIRTUAL TABLE` in module migrations for the `fts5` module only | Owner decision; E15 for shadow tables |
| D128 | Argon2id m = 384 MiB, t = 3, p = 4, floor and ceiling, one global FIFO limiter on a two-thread pool, 4 s refusal, per-member bound and backoff | E12 on the reference host; settled with D129 and D136 |
| D129 | Exception to D28 for `argon2` and `blake2`, with a review, vectors and a cross-test in CI; approve `rayon` or drop the `parallel` feature | Owner decision |
| D134 | Refuse a tunnel whose SNI differs from the CONNECT host or that offers ECH; do not adopt per-plugin IP ranges; Host-header fronting a named risk | Owner decision |
| D135 | No redeemable token in the push payload; a self-hosted push server reachable from phones off the household network | Owner decision |
| D136 | Blocking pool of cores minus one with Argon2id lanes on one thread; per-file backup pauses up to 32 MiB, online backup above; audit ack in every latency; `synchronous = FULL` | E32 on the reference host; settled with D128 |
| D137 | Keep 100.64.0.0/10 out of FR-6's private interface list; document that the overlay option bootstraps from a LAN peer | Owner decision |
| D138 | The temporary self-signed certificate names IP addresses only, never a host name | Owner decision |

## 11. Experiments still open

| Experiment | State after this epic | What closes it |
|---|---|---|
| E1 | To test; probe ready, Credential Manager app not built | Household devices (non-gating) |
| E2 login half | Passed on desktop with virtual authenticators | Android, Safari, real authenticators |
| E2 PRF half | Library behaviour known; browser outputs not measured | Household devices (non-gating) |
| E3 | Desktop and command-line clients recorded | Safari, Android WebView, Chrome for Android, OkHttp, Cronet, native app |
| E10 | Passed in a container | Debian 13 host (D125) |
| E12 | Passed in emulation | Reference host (D128) |
| E13 | **To test**: no measurement | 7 days on each household phone, both servers |
| E14 | **Not met** (domain fronting); direct-connection checks in a container | Owner decision on D134; Debian 13 VM run |
| E16 | Passed in containers | Reference host; pipe `core_pattern` |
| E19 | Rust and TypeScript passed | Kotlin part, before the native app milestone |
| E22 | Desktop passed | Android |
| E24 | Desktop Linux passed with virtual authenticators | Android, Safari, real authenticators, real public CA, two-passkey Firefox |
| E26 | Desktop passed with the sanitizer | Android, Safari |
| E32 | Passed in emulation | Reference host (D136) |
| HPKE (D61) | Passed locally and in a pinned container | CI job and its first green run; owner approval of `REVIEW.md` |

Closed by this epic within its stated scope: the AD-36 construction (D119), E11 (D126), E17
(D132), and the Rust and TypeScript part of E19 (D130).

## 12. Backlog movement

- Sprint status: 15 stories at `review`; 1.13 and 1.17 at `in-progress` because their
  measurement needs the household's devices. Epic 1 stays `in-progress`.
- Decision records D119 to D139 written: 10 Accepted (D119, D120, D122, D124, D126, D130, D131,
  D132, D133, D139), 11 Proposed (section 10).
- `doc/stories/deferred-work.md`: whole-store authentication of `wrappers.db` (story 1.1).
- New risks and threats recorded in the design documents: R54 and T67 (domain fronting), R55 and
  T68 (HK substitution at first receipt).
- Not yet moved: the proposed AC changes for Stories 2.5, 3.1, 3.6, 4.2, 4.4, 4.6, 5.1, 5.3, 5.4
  and 5.5 that each spike lists under "Proposed design document updates".

## 13. Residual risks accepted

These are stated by the stories or the Accepted records and are not closed by any run:

- `wrappers.db` is authenticated per record, not as a set: deletion and rollback raise no alert
  (D119, deferred).
- Host-header domain fronting on a shared front end (R54; D134 proposed).
- The pairing lock-out after 3 attempts is a denial-of-service lever, bounded by uniform answers
  and a per-source limit (D122); an enrolled browser's pin of the Core identity key is trust on
  first use (D122).
- Abort paths without user code leave keys in memory until exit, without a dump; a process that
  opened the Core's memory before hardening keeps access; registers beyond ymm15 and kernel-side
  copies are outside the claim (D131).
- Deleted rows remain in backups and migration cold copies until those expire; freed filesystem
  blocks may hold old ciphertext (D132).
- Inside a CONNECT tunnel the request rate to an allowlisted host is unbounded by the proxy
  (D133).
- Mail bodies render without images, styles or in-place links (D139).
- A signer on newer Unicode tables may refuse a confirmation with code points new to the Core's
  version, failing closed (D130).
- The `hpke` crate leaves copies of secrets in freed memory, covered by the scrub rules (D120,
  D131).

## 14. Recommendations

1. **Decide the Argon2id pool first** (D128, D129, D136 together): either `parallel` with
   `rayon` and a dedicated two-thread pool, or lanes on one blocking pool thread. Then run E12 and
   E32 on the reference host in one session, so Story 5.1 builds on one measured model.
2. **Decide D134 and record E14's outcome**: E14's criterion is not met; the owner either accepts
   Host-header fronting as a named risk with the SNI check, or narrows allowlists to dedicated
   infrastructure. Until then the 1.12 gate stays FAIL.
3. **Run one Android and Apple device session** covering E22, E24, E2, E26 and E3 with the manual
   procedures in stories 1.3, 1.4, 1.5, 1.14 and 1.16, plus the two-passkey Firefox case with a
   real authenticator.
4. **Run the Debian 13 host checks together** once Story 2.3's VM harness exists: E10 (`checks.sh`),
   the E14 `ac3.*` commands, and the E16 `noptrace` group with `systemd-coredump`.
5. **Start the E13 7-day run** with `spikes/push-delivery/RUNBOOK.md`, over mobile data as well as
   at home; E13 gates V0.1 and has no result.
6. **Add the HPKE CI job** with the first CI story and link its first green run; have the owner
   approve `spikes/hpke-review/REVIEW.md`.
7. **Carry the spike results into the build stories** listed in section 12 before they are
   started, so the tests the spikes proved become acceptance criteria.
8. **Move the remaining spikes to `rustls` 0.23.46** and update the spine's pin.
9. **Investigate the Firefox 155 load stalls** only if Firefox 155 stays in the supported list;
   otherwise record the retry count per run as now.

## 15. Debian 13 VM run (2026-10-17)

A second, partial campaign on a Debian 13 virtual machine, for the phases whose result depends
on the host: `sandbox` (1.6), `locked-memory` (1.10), `egress` (1.12), `argon2id` (1.8) and
`core-execution` (1.15). Sections 1 to 14 describe the Docker Desktop campaign and are not
edited; the gate changes are listed here and in each gate file. Recommendation 4 of section 14
is done by this run, except for the reference host.

### 15.1 Run context

| Field | Value |
|---|---|
| Harness | `e2e/vm/` (README there): QEMU 10.0.13 with KVM in a container on Docker Desktop, `-cpu host` |
| Guest image | `debian-13-genericcloud-amd64-20261015-2632.qcow2`, SHA512 in `e2e/vm/IMAGE.lock`, fresh qcow2 overlay per boot |
| Guest | Debian 13.7, kernel `6.12.111+deb13-cloud-amd64`, systemd 257.13-1~deb13u1 as PID 1 (`running`), AppArmor enabled, cgroup v2, `systemd-coredump` pipe `core_pattern`, no swap |
| CPU and memory | 4 vCPUs (Intel Core Ultra 9 285K), 7 947 MiB |
| Storage | 60 GiB virtio-blk, ext4 root, qcow2 `cache=none` on a volume of Docker Desktop's VM |
| Docker in the guest | 26.1.5+dfsg1, Compose 2.26.1-4, buildx 0.13.1, all from the Debian archive |
| Commit | `5130fe96fc018337c5e359df305af4fca8642649`, checked out in the guest from a git bundle of HEAD (committed content only) |

### 15.2 Commands and phase table

Main run, clean tree, every phase alone on the guest's engine:

```sh
bash e2e/vm/vm.sh up
bash e2e/vm/vm.sh sync
E2E_TIMEOUT_SCALE=2 \
E12_IMAGE=rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a \
  bash e2e/vm/vm.sh e2e sandbox locked-memory egress argon2id core-execution
```

`E12_IMAGE` pins `argon2id` to the digest the other spikes use (its `run.sh` defaults to the
`rust:1.99-trixie` tag). Results: `e2e/results/vm-20261017T100711Z-5130fe9`.

| Phase | Story | Status | PASS | FAIL | INFO | Duration (s) | Cause of the failure |
|---|---|---|---|---|---|---|---|
| sandbox | 1.6 | PASS | 146 | 0 | 75 | 58 | |
| argon2id | 1.8 | FAIL | 9 | 1 | 6 | 342 | `selection_matches_constant` picked m = 512 MiB (15.4) |
| locked-memory | 1.10 | FAIL | 64 | 1 | 21 | 37 | `harness-swap`: no swap in the guest (15.4) |
| egress | 1.12 | FAIL | 188 | 1 | 7 | 85 | Compose log escape (15.3) |
| core-execution | 1.15 | PASS | 41 | 0 | 51 | 995 | |

Follow-up runs on the same VM and commit:

| Run | Command | Results | Uncommitted paths | Outcome |
|---|---|---|---|---|
| Pipe restored | `bash e2e/vm/vm.sh e2e locked-memory` after `systemctl restart systemd-sysctl` | `vm-20261017T103320Z-5130fe9` | 0 | 63 PASS, 1 FAIL (`harness-swap`) |
| Swap file | same, with a 2 GiB swap file for that run | `vm-20261017T103338Z-5130fe9` | 0 | 65 PASS, 0 FAIL |
| Compose fix | `bash e2e/vm/vm.sh e2e egress` with the `run.sh` fix | `vm-20261017T103545Z-5130fe9` | 1 | 189 PASS, 0 FAIL |
| Both fixes | `bash e2e/vm/vm.sh e2e sandbox locked-memory egress` with the three spike changes | `vm-20261017T103921Z-5130fe9` | 3 | sandbox 146/0, locked-memory 63/1 (`harness-swap`), egress 189/0; guest pipe intact afterwards |
| argon2id again | `E12_IMAGE=<digest> bash e2e/vm/vm.sh e2e argon2id` | `vm-20261017T104405Z-5130fe9` | 0 | 9 PASS, 1 FAIL (`selection_matches_constant`, m = 512 MiB again) |
| E10 on the host | story 1.6 manual procedure: `checks.sh` as root under the guest's systemd | `host-e10-checks.log` in the main folder | 0 | RESULT PASS: 131 PASS, 0 FAIL |
| E14 ac3 on the host | `host-e14-ac3.sh`: the `ac3.*` matrix with `systemd-run` on the guest against the compose test network | `host-e14-ac3.log` in the main folder | 0 | RESULT PASS: 22 PASS, 0 FAIL |

The fixed spike scripts were copied into the guest checkout for the runs marked with
uncommitted paths; `run-info.txt` of those runs records the count.

### 15.3 Spike changes made for a plain Linux Docker host

Uncommitted at the time of this section; each was run in the VM and on Docker Desktop (sandbox
146 PASS, egress 189 PASS on Docker Desktop after the changes).

- `spikes/egress-filter/run.sh`: Debian's Compose 2.26 starts every `logs` line with an
  erase-line escape (`ESC [2K`), even into a pipe. The anchored `logs.*` checks then failed
  (`logs.internal_target_reached_only_by_named_destinations`) or passed whatever the log said
  (`logs.forbidden_upstream_never_reached_through_the_proxy`, a count of 0). Every log read now
  strips the escape.
- `spikes/sandbox-profile/Dockerfile.systemd` and `spikes/egress-filter/compose/Dockerfile`:
  `systemd-sysctl.service` masked. A privileged container that boots systemd shares the host's
  `/proc/sys`; Debian's `10-coredump-debian.conf` replaced the guest's `systemd-coredump` pipe
  with `core` until the next boot, so `locked-memory`, which runs after `sandbox`, tested the
  file case on a pipe host. Reproduced on its own; with the mask the pipe survives both phases.
  The same mechanism very likely produced the `core` the Docker Desktop runs recorded.

### 15.4 Results that matter

- **1.6, E10 on Debian 13:** all checks pass in the container on 6.12 and under the guest's own
  systemd with AppArmor active. `LATE_PIDFD kernel=6.12.111+deb13-cloud-amd64
  late_pidfd=refused(EINVAL)`: 6.12 refuses a pidfd for a reaped peer, where 6.18 returned one;
  the reused pid is still refused (`reason=peer-exited`). The startup IP filter check passes;
  `IPAddressDeny=any` blocks UDP with `EPERM` and makes TCP time out, on loopback and the own
  address, with controls open. `systemd-analyze security` 0.4 and 0.2.
- **1.10, E16:** under the pipe `core_pattern`, the hardened subjects leave no `coredumpctl`
  entry; each run leaves exactly the control (`COREFILE present`, about 30.6 KiB) and the
  `RLIMIT_CORE`-only subject (`COREFILE none`: the kernel pipes the image whatever the limit and
  `systemd-coredump` does not store it, so `LimitCORE=0` alone is not the barrier on Debian;
  non-dumpable is). With a pipe, `core-file-excludes-locked-pool` cannot run; it ran under `core`
  in the main run (pool key 0 times, heap DEK once). The `swap` group needs swap: it fails on the
  swapless guest and passes with a swap file.
- **1.12, E14:** the 25 `ac3.*` checks pass on 6.12 in the container, and the same matrix passes
  22 of 22 under the guest's systemd. Domain fronting (finding 2, D134) is unchanged.
- **1.8, E12:** the recommended set stays far under target (single median 340.2 and 291.9 ms,
  slower of a limit-1 pair 691.8 and 587.2 ms), but four dedicated vCPUs are faster than the CFS
  quota emulation and the selection rule picks m = 512 MiB (slower-of-pair median 907.7 and
  784.5 ms, under the 1 000 ms emulation margin) in both runs. Machine sensitivity of the pick, as
  the story's contended run already showed; the constant is decided on the reference host, not
  here.
- **1.15, E32:** D116 holds with less margin: member probe p99 60.53 ms, token probe p99
  70.62 ms, all actions p99 62.01 ms (max 329.78 ms, on an idle file, all in the write stage).
  `fsync` p50 3.72 ms, p99 5.95 ms on the virtual disk against 1.70 ms on Docker Desktop; unlocks
  are faster (p50 328 ms). Storage, not CPU, sets the tail; the reference host's SSD decides it.

### 15.5 Gate changes

| Story | Before | After | Why |
|---|---|---|---|
| 1.6 | CONCERNS | **PASS** | The only missing evidence was a Debian 13 host; it passed there. D125 can now be accepted by the owner. |
| 1.8 | CONCERNS | CONCERNS | Reference host still missing; VM numbers and the m = 512 MiB pick recorded (E12-5). |
| 1.10 | CONCERNS | CONCERNS | Pipe `core_pattern` now covered (E16-2 resolved); reference host still missing (FR-13); E16-4 and E16-5 added. |
| 1.12 | FAIL | FAIL | D134 still with the owner; E14-2 resolved on Debian 13; E14-5 (Compose escape) added. |
| 1.15 | CONCERNS | CONCERNS | Reference host still missing; VM numbers recorded; E32-4 raised to medium. |

Gates after this run: 5 PASS, 11 CONCERNS, 1 FAIL.

### 15.6 What this run is not

A KVM guest on a 24-core desktop CPU, with that CPU's caches and memory bandwidth, and a virtual
disk through two virtualisation layers. It is the right kernel line (the cloud flavour of 6.12;
a physical host runs the generic flavour), the right systemd and the right Docker packages; it is
not the reference host, so 1.8, 1.10 and 1.15 still wait for it. Not exercised here either: an
unprivileged user manager creating a cgroup with a system unit's name (E10-3), and the core file
that `systemd-coredump` stored for the control was not scanned.

## 16. Android emulator run of E13 (2026-10-17)

A run for story 1.13 only, on the same Windows development host: the real ntfy Android app
1.25.2 (F-Droid build) on an Android 15 emulator (emulator 37.2.12, `google_apis` x86_64 image r9,
KVM, headless, 4 cores, 4 GiB), fed by the unchanged sender from the self-hosted ntfy 2.31.0
server on an internal network, while a scenario forces screen off, battery unplugged, deep Doze
with and without the battery optimisation exemption, standby buckets, network loss, a force-stop
and a reboot. A host-side observer reads the app's notifications over adb in place of MacroDroid.
Every image and the APK are pinned in `spikes/push-delivery/android/android.lock`; the Android SDK
licence is accepted by building the image. Procedure: `spikes/push-delivery/android/README.md`.
It is labelled `criterion=simulation` and is **not an E13 result**.

| Run | Command | Duration | Checks | Alerts | In time | Late | Lost |
|---|---|---|---|---|---|---|---|
| Smoke | `bash spikes/push-delivery/android/run.sh --smoke` | about 20 min | 24 PASS, 0 FAIL | 70 | 70 | 0 | 0 |
| Compressed | `bash spikes/push-delivery/android/run.sh` | 3 h 11 min | 24 PASS, 0 FAIL | 479 | 471 | 8 | 0 |

- Every forced state delivered 100 % within 10 minutes, at a p99 of 1.2 s under Doze and in every
  standby bucket, except the 13-minute network outage (27 of 35 in time, 8 late, 0 lost): the app
  resumed from its last message id after every outage, force-stop and reboot.
- Doze did not hold alerts for a maintenance window or for the exit, with or without the
  exemption: the app's instant delivery is a foreground service, which keeps its network in Doze.
  Forced standby buckets reverted to `active` within a minute.
- A force-stopped app received nothing until it was reopened; on a phone whose vendor force-stops
  background apps, that is the delay the household run must watch for.
- The app writes each message body to logcat and its database, which strengthens the first half
  of D135 (story 1.13, proposed update 6). Nothing here argues for revisiting D118.
- Not covered: carrier networks, radio power states, vendor battery management, idleness reached
  naturally, 7 days. Gate 1.13 stays CONCERNS; gates after this run are unchanged (5 PASS,
  11 CONCERNS, 1 FAIL).

## 17. Decisions settled (2026-10-18)

The owner delegated the eleven Proposed records to the best technical choice after online research; all are now Accepted in `doc/decisions.md`, with their sources in `doc/research-notes.md` section 1.2.

| Record | Outcome |
|---|---|
| D121 | First receipt of HK closed: a confirmation key derived from the enrollment key, wrapped under the new member's DEK, authenticates the first HK; a DEK-keyed commitment covers every later unlock. HK rotation stays open (R55, T68 narrowed to it) |
| D123 | OPAQUE kept, under a D28 exception: `opaque-ke` `=4.0.1`, WASM built from pinned source and matched byte for byte, RFC 9807 vectors, a WASM-against-Core cross-test, `Ksf` over the Core's `argon2` 0.6, external review before V1 |
| D125 | Peer identity by `cgroup.procs` then pidfd, accepted after the Debian 13 VM rerun; a failed `SO_PEERPIDFD` refuses, kernel 6.5 or later required, `NoExecPaths=/` and `ExecPaths=/usr` in the template, `io_uring` denied on every unit |
| D127 | `fts5` virtual tables only, in migrations, under `SQLITE_DBCONFIG_DEFENSIVE` (amends D126), with an argument allowlist and `secure-delete` on |
| D128, D129, D136 | `argon2` 0.6.0 without `parallel` (no `rayon`), lanes in order on one blocking-pool thread, a FIFO limiter of two derivations, memory at most limit x m <= 1 GiB; m picked on the reference host from {256, 384, 512} MiB; D28 exception with a cross-test over p in {1, 2, 4, 8} and OpenSSL as a second oracle |
| D134 | SNI check and ECH refusal as built; Host-header fronting accepted as the named risk R54 and T67; front ends that do not refuse a mismatched Host need a stated reason in the allowlist review. Gate 1.12 stays FAIL against its own criterion, with the residual risk accepted |
| D135 | No token in the push payload; the server keeps alerts for offline phones; off-network reachability by D60's tunnel or a published endpoint with per-phone read-only tokens (the V0.1 path); iOS needs an upstream server, which sees timing (D118 amended) |
| D137 | 100.64.0.0/10 private only on one overlay interface the operator names, with the Gateway socket bound to it (DC-78) |
| D138 | IP-only temporary certificate, destroyed after setup; the relying party accepts only the instance name and its origin, so `localhost` and IP ceremonies are refused server side (DC-79) |

New open questions: how a new HK version is confirmed after a rotation (before FR-9 code), and how the enrollment test notification proves receipt without a token in the payload (before Story 8.1). Gate verdicts are unchanged; their top issues now cite the accepted records.
