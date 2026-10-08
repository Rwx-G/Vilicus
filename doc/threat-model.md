# Threat model

Status: design phase, no code yet. Revision 1. Written to be attacked: every assumption below is a claim to challenge. Components are defined in [architecture.md](architecture.md); keys in [key-management.md](key-management.md); the assistant's rules in [ai-safety.md](ai-safety.md).

## 1. Scope

One Vilicus instance serves one household (one to several members). It stores sensitive personal data (finances, mail content, calendar, locations, children's information), holds credentials for external services, and hosts an AI assistant allowed to take actions on the household's behalf. It is reachable from the household's devices and possibly from the Internet.

Out of scope for this version: multi-tenant hosting, physical attacks on a running unlocked machine, adversaries who target the household specifically with state-level resources, CPU side channels.

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| Financial data (accounts, transactions, budget) | Privacy, fraud |
| Mail and calendar content, contacts | Privacy, social engineering, account takeover |
| Locations, routines, children's data | Physical safety, privacy |
| Data keys, KEKs, recovery secrets, passphrases | Compromise of everything in a partition |
| Connector credentials (mail, AI providers, messaging, stores) | Impersonation, spend |
| The ability to act (pay, send, delete, share, order) | Irreversible harm |
| Assistant memory (facts, episodes) | Poisoning changes future behaviour |
| Audit log and its anchors | Detection and forensics |
| Device signing keys | Forged confirmations |

## 3. Adversaries

| ID | Adversary | Capability |
|----|-----------|------------|
| A1 | Remote attacker via content | Sends a mail, message, calendar invitation, web page, recipe or file that the system or the AI will read |
| A2 | Remote attacker against the exposed surface | Scans, brute-forces, exploits the Gateway and web client |
| A3 | Malicious or compromised plugin | Runs inside the instance with the permissions it was granted |
| A4 | Curious or hostile household member | Legitimate account, wants to read another member's partition or push content into it |
| A5 | Lost or stolen device | Holds a paired client, possibly unlocked |
| A6 | Stolen or copied disk or backup | Offline access to files |
| A7 | Compromised host | Root on the machine, running instance |
| A8 | Supply chain | Malicious dependency, build or update |
| A9 | The model itself | Hallucinates, loops, misreads, or follows injected instructions (A1 by proxy) |
| A10 | The operator | Misconfiguration, accidental exposure, weak passphrase |
| A11 | Compromised Gateway or TLS terminator | Full control of the exposed process or of a reverse proxy in front of it |
| A12 | Malicious or coerced instance admin | Holds the admin role, not necessarily root |

## 4. Trust boundaries

1. Client (browser, app) to Gateway: untrusted network.
2. Gateway to Core: the Gateway is exposed, so it is lower trust than the Core and holds no keys.
3. Core to modules: modules are trusted code in the Core process; isolation is by data (own database, scoped handles), not by memory.
4. Core to AI processes and the alignment controller: untrusted by design.
5. Core to plugins: untrusted, separate sandboxed processes.
6. Instance to external services (mail, AI providers, stores): third parties, reached through the egress proxy.
7. Instance to disk and backups: at-rest boundary.
8. Paired native app to Core: the app pins the Core's public key; this channel carries tier 2 confirmations independent of the Gateway's honesty.

## 5. Security assumptions

- Passphrases are reasonably strong; recovery secrets are stored offline and apart from devices.
- After unlock the key material is in the Core's memory: at-rest encryption protects against A6, not against A7. The system is **not zero-knowledge**.
- Audited cryptographic libraries are used; no custom protocols.
- A paired native phone is not fully compromised at the time of a confirmation (otherwise only Protected Confirmation, where present, helps).
- The operator follows the exposure guidance; the default does not expose the instance to the Internet.
- Modules are reviewed code; the supply chain controls hold (A8).

## 6. Threats and mitigations

STRIDE per boundary, plus abuse cases specific to an acting assistant.

| # | Threat | Adversary | Mitigation (design) | Residual risk |
|---|--------|-----------|---------------------|---------------|
| T1 | Prompt injection via mail, web, file, plugin or another member's data makes the assistant exfiltrate or act | A1, A4, A9 | Model untrusted; reader/planner/drafter split; capability tokens; mandatory taint on all records; elevated tier 1; signed tier 2 in a separate queue for tainted sessions (`ai-safety.md`) | Medium: injection is contained, not prevented |
| T2 | Memory poisoning changes future behaviour | A1 | External-origin facts quarantined and never auto-promoted; promotion is tier 2; rollback | Medium |
| T3 | Confirmation spoofing: displayed action differs from executed action | A1, A9, A11 | Device recomputes and displays the canonical hash; Core recomputes and verifies; requests signed by the Core and checked against the pinned key; Gateway only relays | Low, except phone malware (T20) |
| T4 | Exfiltration through model output (links, images, tool arguments, notifications) | A1 | No fetching of model URLs; egress proxy with exact-hostname allowlist; recipient allowlists; notification templates and rate limits; outbound content check on tier 2 sends | Low to medium: covert low-bandwidth channels remain |
| T5 | Erratic model: loops, duplicate orders, wrong amount or date | A9 | Strict schemas; deterministic idempotency keys; caps; loop detection; dry-run; kill switch; date and zone injected by Core | Low |
| T6 | Cross-partition read or write by a household member | A4 | Per-partition keys; Core enforces partition on every call; writes across partitions are tier 2; the AI inherits the caller's scope; other members' data is `member` taint | Low if keys are correctly separated |
| T7 | Cross-module data access | A3, A9 | One database per module and partition; no cross-module SQL; registered APIs only; migrations through an authorizer | Low |
| T8 | Malicious plugin steals credentials or data | A3 | Separate process; fixed systemd profile; exact network allowlist through the egress proxy; one secret per plugin; manifest bound to binary hash; rights changes need a diff and a passkey | Medium |
| T9 | Brute force or exploitation of the Gateway | A2 | Passkey authentication; rate limiting; device pairing; minimal surface; strict CSP; Internet exposure opt-in with blocking warning | Medium |
| T10 | Session or device theft | A5 | 15 minute sessions, `__Host-` cookies, immediate server-side revocation, device keys in hardware, 24 hour delay for new devices, biometric or PIN per confirmation | Medium |
| T11 | Disk or backup theft | A6 | SQLCipher with application-derived keys; wrapped keys only; metadata under the instance key (TPM when present); encrypted backups | Low |
| T12 | Host compromise | A7 | Not mitigable once unlocked; limits: memory hygiene, process separation, audit anchors on devices, no keys in plugins or AI | High, accepted and documented |
| T13 | Harvest now, decrypt later on transport | A2 | Hybrid X25519MLKEM768 key exchange when client and terminator support it; AES-256 at rest. Signatures and WebAuthn stay classical; a third-party TLS terminator removes the benefit | Low to medium; no "post-quantum" claim |
| T14 | Malicious dependency or update | A8 | `cargo deny` and `cargo vet`; vendoring; build.rs and proc-macro allowlist; `forbid(unsafe_code)` in modules; signed releases with anti-rollback; reproducible builds as a goal | Medium |
| T15 | Tampering with or deleting the audit log | A7, A3 | HMAC hash chain, separate process and key, anchors on devices at each tier 2 event, optional remote sink | Medium |
| T16 | Misconfiguration or weak passphrase | A10 | Safe defaults; wizard; passphrase check; Argon2id; exposure warnings | Medium |
| T17 | Third-party terms violation leads to account suspension (store connectors) | n/a | Isolated optional plugins; user session only; human validation; disclaimer | Accepted |
| T18 | Bootstrap hijack: someone completes first-run setup before the owner | A2, A10 | 128-bit one-time token on the console, 15 minute expiry, loopback and LAN only, certificate fingerprint printed, wizard disabled afterwards | Low |
| T19 | Pairing abuse: attacker adds their own device | A5, A2 | Pairing is human-only with step-up; 128-bit QR token valid 2 minutes, one use, bound to the session; validation code typed on the paired device; 3 attempts; notifications everywhere; 24 hour delay before tier 2 | Low to medium |
| T20 | Phone malware shows a false confirmation | A5 | Hardware-backed key with per-use user verification; Android Protected Confirmation where `isSupported()`; otherwise accepted | Medium |
| T21 | Confirmation fatigue or flood | A1, A9 | One pending request, batching, separate tainted queue, refusal counter suspends the task, controller removes tier 1 friction, weekly rate reported | Medium |
| T22 | Recovery abuse: attacker uses a stolen recovery secret | A5, A6 | Waiting period with alert on all devices and one-tap cancel; no admin reset; TOTP and passkey fallback invalid for recovery | Low to medium |
| T23 | Admin abuse: admin reads members' data or adds themself to the household partition | A12 | Admin has no data keys; adding an adult needs an unlocked adult's signed confirmation; no admin re-wrapping | Low, except root (T12) |
| T24 | Compromised Gateway tampers with the web front end or reads PRF output | A11 | No tier 2 on web; short sessions; native app pins the Core key; stated limit | Medium, accepted |
| T25 | Tainted session abuses the kill switch to deny service | A1 | Kill switch not triggerable by a tainted session; resume needs a passkey | Low |
| T26 | Background delegation sub-key stolen or abused | A7, A6 | Explicit creation, one module and partition, revocable with re-key, shown in the UI, audited | Medium, accepted trade-off |
| T27 | Unauthenticated Argon2id requests exhaust CPU or memory | A2 | Passphrase work only after first factor; global concurrency limit | Low |
| T28 | Alignment controller manipulated or wrong | A1, A9 | Structured input only; closed output; fail closed; never used for tier 2 or H; thresholds human-only; false accept rate as release gate | Medium |
| T29 | Rollback by restoring an old backup reopens used nonces | A7 | Device-held anchors; acknowledgement required before tier 2 | Low to medium |
| T30 | Malicious update of the model or prompt templates | A8 | Pinned versions, evaluation suite before switching | Medium |

## 7. Data flows to review first

1. Inbound mail to quarantined reader, to typed output, to planner, to proposal.
2. Tier 2 proposal to Core checks, to signed request, to native app, to signed confirmation, to execution and audit.
3. Bootstrap and pairing (token, QR, validation code, attestation, delay).
4. Unlock: PRF output or passphrase, KEK derivation, DEK in memory.
5. Plugin to external service and back, through the egress proxy.
6. Recovery and household key rotation.
7. Backup, restore and anchor reconciliation.

## 8. Questions from draft v0 and their status

| Question | Status |
|----------|--------|
| How are keys held for background tasks, and what is the re-lock policy? | Answered: unlocked members only, or explicit delegation sub-keys, otherwise wait (`key-management.md`, section 7) |
| What does the AI see on behalf of a member versus the household? | Answered: the caller's partition and the household partition; another member's data only as `member` taint; tier 2 for cross-partition writes |
| Which parts of the web client can be offered read-only on unmanaged computers? | Answered: none beyond the login page; unmanaged browsers do not get sessions with data access (open: a read-only guest view is not designed) |
| Backup format and key escrow | Answered in part: per-file backups of encrypted files, no escrow; threshold shares for the household key only (open, D7) |
| Recovery when the only paired device is lost | Answered: passphrase or recovery secret with a waiting period |

New open items are in `architecture.md`, section 20, and `research-notes.md`.

## 9. Review log

| Date | Reviewer | Notes |
|------|----------|-------|
| 2026-10-08 | Author, draft v0 | Initial version |
| 2026-10-08 | Author, revision 1 | Added adversaries A11 and A12, threats T18 to T30, trust boundary 8; honest transport wording; answers to v0 questions |
