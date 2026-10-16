# Research notes

Status: Revision 2, design phase, no code yet. This file separates what is reported by desk research, what is assumed, and what must be tested before the design commits to it. Apart from the AD-36 construction (D119), nothing here has been proven by a prototype. Statuses:

- **Reported**: gathered from documentation and public sources during design research (October 2026). The sources were not re-opened for this repository, so treat each item as a claim to re-check before relying on it.
- **Assumed**: a design assumption with no source.
- **To test**: an experiment with a pass criterion (section 3).

Update of 2026-10-16: E29 added from the PRD spike table, the V0.1 experiment order stated, and an open question added (HPKE cross-test). Revalidation of the same day: E23 gets a pass criterion and a fallback (D70), E24 now confirms that no WebAuthn ceremony is needed over the temporary self-signed certificate (D76), E25 tests the local model runtime in the shape of D83, and E27 covers the Zigbee cutover (D79). A later update of the same day sets the fallbacks of E22 and E26 and makes E13 a gate of V0.1. A last update of the same day adds E30 for the Claude subscription connector (D97). The second revalidation of the same day (D101 to D115) aligns the V0.1 gate list and order with the PRD, gives E13 a threshold, E22 three fallbacks and E24 a supported browser list (D105, D107), moves E23 to the conversation milestone, sets pass criteria or fallbacks for E2, E3, E10, E12, E16, E17 and E28, extends E19, E27 and E30, and adds E31 (signed boot policy, D108) and E32 (Core execution model). The owner decisions taken after the V0.1 stories (D116 to D118) give E32 a pass criterion, set fallbacks for the AD-36 construction and the E2 login half, and make E13 measure the default self-hosted push server and a public one. The key prototype then passed the AD-36 construction (D119).

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
| Claude subscription | Anthropic's pages read on 2026-10-16: a plan's usage limits cover `claude -p`, the Agent SDK and third-party apps; a third party may not offer Claude account sign-in nor collect, store or relay its credentials, while a user may sign in to the unmodified Claude Code binary. Re-read before each release that ships the connector | Reported | D97 |

### 1.1 Desk research for the architecture spine

Re-checked during desk research on 2026-10-09 and 2026-10-15 for `architecture-spine.md`. These are still reported claims, not results: move one to verified only as section 5 says.

| Topic | Claim | Status | Used in |
|-------|-------|--------|---------|
| TLS hybrid | rustls with the aws-lc-rs provider prefers `X25519MLKEM768` in its key exchange groups | Reported | D27; E3; spine stack |
| SQLCipher in rusqlite | The SQLCipher build bundled by `rusqlite` lags the upstream SQLCipher release | Reported | D2; spine open item on the SQLCipher version |
| WebAuthn library | `webauthn-rs` 0.5 has no PRF extension support | Reported | E2; PRD section 4.4 (passphrase unlock in V0.1) |
| HPKE | No audited Rust implementation of HPKE (RFC 9180) exists | Reported | D61; spine AD-18 |
| Trusted Types | Among the compared front-end frameworks, only Lit ships its own Trusted Types policy | Reported | D26; spine AD-19 |
| PAKE in the browser | OPAQUE is the only PAKE with a maintained browser implementation | Reported | D35; E22; spine AD-21 |
| systemd devices | `PrivateDevices=yes` hides serial devices even when `DeviceAllow=` grants them | Reported | D54; E27; spine AD-38 |
| systemd IP filter | `IPAddressAllow=` and `IPAddressDeny=` depend on cgroup eBPF support and are one layer only, not a boundary on their own | Reported | D54; E10; E27 |
| Presence detection | ARP-based presence detection needs raw network rights | Reported | D54; E27; spine AD-38 |
| WireGuard | WireGuard is in the Debian 13 kernel, and its protocol has been formally analysed | Reported | D60; E28 |
| Android VPN | Android allows one active VPN per profile | Reported | D60; E28 |

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
| E1 | Does PRF work in the native Android credential API (Credential Manager)? | Prototype app evaluating PRF with a platform and a roaming authenticator, run early on the household's real phones | Stable 32-byte output across sessions for the same salt | Passphrase unlock on Android; passkey for login only. V0.1 already unlocks with the passphrase and adds PRF unlock later (PRD section 4.4); E1 decides when PRF unlock can follow |
| E2 | Does `webauthn-rs` expose PRF, and do target browsers return it? | Minimal server and page on Chromium, Firefox, Safari and mobile | PRF half: output per credential, reproducible. Login half: passkey login and a step-up whose challenge derives from an action hash (D71) succeed on every supported browser (D107) | Handle PRF client side in own code, or passphrase-only unlock. Split by the PRD: the login half (passkey login through the chosen WebAuthn library) gates V0.1, and a browser that fails it leaves the supported list; if every supported browser fails, TOTP (D33) temporarily becomes the primary second factor (D117); the PRF half is tied to the deferral of PRF unlock past V0.1 (PRD section 4.4), and `webauthn-rs` 0.5 is reported without PRF support (section 1.1) |
| E3 | Does every client negotiate the hybrid key exchange? | Real handshake against the rustls server from: current Chrome, Firefox, Safari, Android system WebView, OkHttp, Cronet, the app's own rustls build | Observed negotiated group per client recorded; the result informs the README wording of the transport claim, and the run itself is what V0.1 requires | Document which clients lose the hybrid exchange; keep classical fallback |
| E4 | How available is Protected Confirmation on real phones? | Call `isSupported()` on several devices and OS versions | Result table; usable on at least the owner's phone | Remains optional reinforcement |
| E5 | Can the app sign with a Keystore key requiring per-use user verification, with attestation, on StrongBox and non-StrongBox devices? | Prototype | Key invalidated on biometric change; attestation verifiable by the Core | Weaker policy on devices without StrongBox, flagged in the device record |
| E6 | Controller quality and latency in French on CPU | Build a labelled set of structured cases (legitimate and trapped); run a 3 to 4 billion parameter model in GGUF Q4 on a small CPU host; measure false accept rate, false reject rate, ECE, latency | False accept rate on trapped cases below an agreed threshold with conservative cut-offs; latency compatible with interactive use | Deterministic rules plus human only; no controller in v1 |
| E7 | Is Tauri mobile mature enough for the Android shell? | Build a shell with QR scanning, Keystore access and notifications | Works without native plugin gaps | Native Kotlin shell for Android; Tauri for desktop only |
| E8 | What do the Google and Microsoft OAuth procedures cost a household that brings its own client? | Walk through both consoles for a personal project | Documented steps, time, and any fee or review | IMAP/SMTP and CalDAV only |
| E9 | How do work accounts behave under corporate policy? | Test with a consenting account: app passwords, OAuth consent, conditional access | Documented outcomes by provider | Declare work accounts best effort |
| E10 | Does the fixed systemd profile work for a plugin that needs a socket, one credential and an egress proxy? | Reference plugin under `DynamicUser`, `LoadCredential`, `SystemCallFilter=@system-service`, `IPAddressDeny=any` | Plugin works; direct sockets fail; peer identity verified | Relax individual options with a documented list. If `SO_PEERPIDFD` and the cgroup unit cannot be read, each first-party unit runs under its own static user and the Core checks the uid with `SO_PEERCRED`, recorded as weaker against a compromised unit of the same user |
| E11 | Does the SQLite authorizer block `ATTACH`, `DETACH`, unsafe `PRAGMA` and extension loading in the migration connection? | Unit tests with hostile migrations | All forbidden statements rejected | Move to a vetted statement parser |
| E12 | What Argon2id parameters fit a small host? | Benchmark on target hardware | Unlock under a target latency with memory above the published floor, on the reference host (4 cores, 8 GB RAM, SSD, no GPU, Debian 13 amd64, D113) | Lower the concurrency limit, keep the memory floor, accept a longer unlock |
| E13 | Is a persistent connection or UnifiedPush reliable enough for content-free notifications on Android? Gates V0.1 (PRD section 9) | Run on each household phone for 7 days, idle nights included, on the default self-hosted UnifiedPush server of the ntfy type, reached through a named private destination, and on a public server (D118) | 99 % of alerts delivered within 10 minutes over 7 days per phone (D105), on the default self-hosted server; a public server below the threshold is documented as not recommended and does not fail E13 (D118) | A second push distributor within the same webhook transport, plus maximum waits for member addition and recovery (D105); never polling as the only path |
| E14 | Does CONNECT-based domain filtering hold for the plugins' real traffic (HTTP/2, QUIC, redirects)? | Reference plugin and proxy | No bypass of the allowlist; no breakage of normal flows | Per-plugin IP ranges as a second filter |
| E15 | Can per-record keys coexist with full-text search for mail and documents? | Prototype with SQLCipher FTS5 | Search works on non-shredded fields; shredded records disappear from the index | Shred whole conversations, keep search on metadata |
| E16 | Does locked memory and zeroization behave as designed in the Rust runtime, including on crash? | Tests with core dumps disabled; inspection of process memory after key drop | No key material found after drop in tested paths | Lower the unlock window maximum and the web session maximum, and drop keys of idle partitions earlier |
| E17 | Does `secure_delete` plus WAL behavior match the shredding claims? | Delete records, inspect files and WAL | No plaintext of deleted records in the file or WAL. Protects the V0.1 claim that expired undo journal entries, which hold before-images, are deleted under `secure_delete` after 30 days (D113) | Vacuum after shredding; document backup caveat |
| E18 | Do the target grocery stores publish an official partner or developer API, and can the household's current recipe app export its recipes? | Read their developer portals and the recipe app's export options by hand | Written answer per store and for the recipe app | Semi-manual flow; no plugin |
| E19 | Is canonical (deterministic) CBOR hashing identical between the Rust Core, the Kotlin app and the TypeScript decoder that renders light confirmations (D113)? | Cross-language test vectors, fuzzing, under the canonical profile of spine AD-13 (no floating-point value, no indefinite-length item, listed tags only; non-canonical input rejected) | Identical bytes and hashes on a large corpus; every decoder rejects the same non-canonical inputs | Switch the canonical form |
| E20 | Can the native app and the Core establish an inner encrypted channel that the Gateway cannot read? | Prototype with a pinned Core key | PRF output and confirmations unreadable by the Gateway | Accept R3 for the app too |

The PRD (section 9) makes the AD-36 construction, the D61 review and cross-test, the login half of E2, E3, E10, E11, E12, E13, E14, E16, E17, E22, E24 and E26 gates of milestone V0.1; E1 and the PRF half of E2 run early without gating it. E18 is a check before the meals module starts. E32 (section 3.1) also runs during V0.1. E21 was never recorded in this file (see D49).

V0.1 experiments run in this order, because the first groups can invalidate the design: the AD-36 construction with the HPKE review and cross-test (key prototype), E22 (non-extractable device key in the browser), E24 (passkeys and installable web app with each naming option), E10 (sandbox and peer identity); then the others. E1 and E2 (PRF) run early on the household's real phones, but PRF unlock is not in V0.1, so they inform it without gating it.

The HPKE review and cross-test (D61) are done when the RFC 9180 test vectors pass, a cross-test against an independent implementation (dev-dependency only) agrees on 10 000 random cases, and a written review with every finding closed or accepted is committed. If the review finds a defect, it is fixed upstream and the fix pinned; failing that, V0.1 exits with UJ-2 limited to the first member and member addition ships in V0.1.x (D107). The AD-36 construction had the same fallback (D117); the key prototype passed it, with the encodings fixed in `key-management.md` section 2 (D119), so the fallback is not taken. The D61 review and cross-test remain open. Supported browsers for every V0.1 experiment: the current and previous releases of Chrome and Firefox, on desktop and Android; Safari is best effort (D107).

### 3.1 Experiments added by the PRD

Taken from the PRD spike table (section 9). Pass criteria and fallbacks are not set yet unless stated; each is written here before the experiment runs, and a failure is recorded in `decisions.md`.

| ID | Status | What it settles | Gates | Fallback |
|----|--------|-----------------|-------|----------|
| E22 | To test | Non-extractable device key in the browser, PAKE-bound code pairing, signed light confirmations (D35, D38; spine AD-21) | V0.1 | Three fallbacks (D107): if a non-extractable browser key is unusable, sessions are re-proven by a passkey assertion every 15 minutes of activity, stated to the user; if the PAKE fails, pairing codes are issued only by `vilicus device pair`; if signed light confirmations fail, approvals are made by a step-up bound to the request hash |
| E23 | To test | Rate of elevated tier 1 requests in real use (D38), under the taint rule of D70 as amended by D99 (structured fields of member-approved writes stored `trusted`, model-drafted free text from a tainted session staying `external`, structured `member` fields not tainting), and with the household writes drawn from personal context that D104 elevates. Pass criterion: under the PRD SM-4 threshold per member per day | The full conversation milestone (PRD section 6.2, step 4), measured over its first four weeks of household use; scheduled tasks of step 2 are counted from their first week. V0.1 ships only the counter of PRD FR-28 (SM-4) | If the rate stays above the threshold: first widen the low-risk exempt record kinds and the bounded-output rule, module by module; then bring the alignment controller forward (E6). Never loosen the taint rule itself (PRD SM-C2) |
| E24 | To test | Passkeys and PWA installation on Android and desktop browsers with each documented naming option: free dynamic DNS, private-network name, local certificate authority (PRD FR-65, D51); and that browsers refuse, or bind to an unusable host, a WebAuthn ceremony over the temporary self-signed certificate, which D76 therefore never runs. Run on the supported browsers of D107 (current and previous Chrome and Firefox, desktop and Android); Safari best effort | V0.1 | A naming option that fails is dropped from the documentation; the bootstrap order of D76 does not depend on the self-signed result |
| E25 | To test | Local model quality and latency on the reference host (4 cores, 8 GB RAM, SSD, no GPU, Debian 13 amd64) for the data types routed to it, and on the household's host, which is a reference for no other target (PRD FR-33, D48, D113), with the local model runtime in the shape of D83 (own unit, per-role Unix sockets, no network, no cache shared across members or roles, model files pinned by hash); records the latency the household accepts on a host without a GPU; also whether per-member runtime instances fit in memory (D110) | PRD FR-33 | Not set |
| E26 | To test | Separate origin by port for sandboxed external content, with each PRD FR-65 naming option and with reverse proxies (spine AD-19) | V0.1 | If a port-based origin is not workable, external content is shown as sanitized plain text, never as HTML |
| E27 | To test | Device adapters under the sandbox, on the target host: the USB serial unit profile with a dynamic user, enforcement of each grant by a negative connection test (an nftables rule per unit cgroup for private address ranges with ports, no loopback address grant, D115), including a negative test from an adapter to every other loopback port of the host, multicast discovery, presence from the router's leases or API and unprivileged ping, latency from a Zigbee event to an action (PRD FR-73, FR-76; D54); the Zigbee cutover of D79: handing the coordinator from the current software to Vilicus while keeping the network and its pairings, and the written rollback back to the current software | Home milestone, before it starts | A static user per adapter if a dynamic user cannot open the serial device |
| E28 | To test | WireGuard endpoint managed by Vilicus: peer changes applied live without root in the Core, the instance name resolving to the private address inside and through the tunnel (including resolvers that block private answers), the official client on Android and desktop, and the single VPN slot on Android (PRD FR-86, D60); a negative test that the WireGuard interface accepts only TCP to the Gateway's port on the instance address and forwards nothing; the client-generated key pair as default | Home milestone, before it starts | The documented reverse proxy or access proxy path becomes the default for remote access |
| E29 | To test | Real-time voice in the installed web client on Android: background audio, microphone released while Vilicus speaks, raw microphone in car mode, car Bluetooth media routing, test chime (PRD FR-94) | Personal journal milestone | Not set |
| E30 | To test | Claude subscription connector in the shape of D97 (spine AD-53): the unmodified binary in headless mode with every built-in tool disabled, whose only MCP server is the stdio bridge `vilicus mcp-bridge` to a per-session socket, one child per session, killed within the 5-second bound when its token is revoked; no settings, hooks or memory loaded from disk; no conversation content left in its state directory or the journal after a run, a forced error run included (canary on every writable path); sign-in in a transient unit and inference through the egress proxy via the forwarder in its private network namespace (D115), with a negative test to every other loopback port; request bodies inspected through a TLS-intercepting test proxy with a test CA (release check only, never in production), asserting that the offered tools are exactly the token's Vilicus MCP tools and that no account-level connector or provider-side capability is offered; the account identifier check (D110); the hostnames it needs; and the behaviour when the plan limit is reached (PRD FR-33). Rerun with a real plan for every pinned binary version, as a release check | Meals milestone, before the connector ships | If a built-in tool or the transcript cannot be turned off, the connector does not ship; a failure on a new binary version blocks that version |
| E31 | To test | Signed boot policy on Debian 13 (D108): unified kernel images measured by `systemd-measure`, systemd credentials sealed to PCR 7 plus a signed PCR 11 policy for the secrets that open the house, delivered to the coordinator daemon by `LoadCredentialEncrypted=`, surviving a signed kernel update; refusal to unseal from a stock live image; a pcrlock hook re-sealing the instance key (PCR 7) before a Secure Boot database or SBAT update | Home milestone, before a security adapter ships | Security adapters do not run on a host where the signed policy fails; the instance key keeps its PCR 7 sealing and the recovery runbook (D96) |
| E32 | To test | Core execution model (spine AD-9): home rule latency while two members unlock concurrently and a backup runs, with one writer thread per open file, a bounded blocking pool for Argon2id, HPKE, copies and migrations, and a dedicated rule thread. Pass criterion (D116): p99 under 100 ms for one action through the full pipeline (policy, write, audit) on the reference host (4 cores, 8 GB RAM, SSD, no GPU, Debian 13), under a simulated load of two active adults plus the testbed | V0.1 | The execution model is revised before the Core process is built (Epic 5 of the V0.1 backlog, D116); first candidates: give the rule thread priority over the blocking pool, lower the blocking pool's concurrency, and throttle backup copies |

## 4. Open design questions that depend on experiments

- When PRF unlock is added after V0.1, and whether on Android (E1, E2).
- Which clients get the hybrid exchange (E3) and what the README can honestly say.
- Whether the controller ships in v1 (E6).
- Whether Tauri is used on Android (E7).
- Cart preparation is no longer tier 2 (see D44); E18 still decides whether an official store API exists before the meals module starts.
- Whether passkeys, PWA installation and the port-based separate origin work with each naming option (E24, E26).
- Whether the elevated tier 1 rate stays under the threshold under the taint rule of D70 as amended by D99, or the E23 fallback is needed.
- Whether the device adapter sandbox and the remote access endpoint hold on the target host (E27, E28).
- Whether real-time voice works in the installed web client on Android, in the background and in a car (E29).
- Whether the Claude subscription connector holds in the shape of D97: built-in tools off, no transcript kept, no provider-side capability, network through the egress proxy only (E30).
- Whether a signed boot policy works on the household's host, which decides whether it can drive physical security devices (E31, D108).
- Whether the Core's threading model keeps home rules responsive during unlocks and backups (E32).
- Whether the `hpke` crate agrees with an independent HPKE implementation and the RFC 9180 test vectors, as the cross-test in CI required by D61 must show (done state in D107; **open**: which independent implementation, to be named before the review starts); the internal review and, before V1, the external review of D61 come on top of it.

## 5. How to update this file

Move an item from "reported" or "to test" to "verified" only with a link to a test result or a dated source that was actually re-read. When an experiment fails, record the fallback taken in `decisions.md`.
