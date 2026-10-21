# Decision log

Status: design phase, no code yet. Revision 2. Short records in an ADR style: context, decision, consequences. Status values: **Accepted** (settled for v1 design), **Proposed** (leaning, to confirm with a prototype), **Open** (not decided), **Rejected**, **Superseded** (replaced by the record named). "Amended by" names a later record that changes part of an accepted one. Detail lives in the documents each record points to; this file explains why. Records D34 to D118 come from the product requirements ([`prd.md`](prd.md), section 8.1, design changes DC-1 to DC-73) and the [architecture spine](architecture-spine.md); the design documents they amend are updated in the same change or listed as pending in [`prd.md`](prd.md) section 6.1. Records D119 to D139 record the results of the V0.1 spikes, D140 to D146 readings and choices settled while building (stories 2.1, 2.6, 2.7 and 3.1 to 3.4) (Epic 1 stories in [`stories/`](stories/)); those that change a requirement are design changes DC-74 to DC-81. A spike record that needs an owner choice, or a run not done yet (a Debian 13 host, the reference host, real phones), stays **Proposed** until then. The eleven spike records left Proposed (D121, D123, D125, D127 to D129, D134 to D138) were settled on 2026-10-18 by the best technical choice after online research, under the owner's delegation; their sources are in [`research-notes.md`](research-notes.md) section 1.

| ID | Title | Status |
|----|-------|--------|
| D1 | Rust, single binary, no container requirement | Accepted |
| D2 | SQLite with SQLCipher; PostgreSQL rejected | Accepted, amended by D132 |
| D3 | One database per module and per partition | Accepted |
| D4 | Key model: member DEK wrapped by several independent KEKs | Accepted |
| D5 | Instance admin separated from data keys | Accepted |
| D6 | Recovery by printed secret, waiting period and alerts | Accepted, amended by D39 |
| D7 | Household key: versioned, rotation, threshold recovery | Accepted, threshold part Open |
| D8 | Background tasks: unlocked members, delegation sub-keys, or wait | Accepted, amended by D36, D57 and D62 |
| D9 | Instance key protects Core metadata only | Accepted, amended by D53, D62 and D96 |
| D10 | Tier 2 only from a paired native app, with signature over a displayed hash | Accepted |
| D11 | The web client never does tier 2 | Accepted, session length amended by D90 |
| D12 | Protected Confirmation as reinforcement, Secure Payment Confirmation as bonus, transaction-authorization extensions dropped | Accepted |
| D13 | The model is untrusted; reader, planner and drafter roles | Accepted, amended by D49 |
| D14 | Taint is mandatory metadata on every record | Accepted, amended by D37, D45 and D70 |
| D15 | "Reversible" means without effect on a third party | Accepted, amended by D44, D56 and D67 |
| D16 | Local alignment controller as third layer | Accepted, realization Proposed |
| D17 | No dependency on Jev (TypeSafe AI) | Accepted |
| D18 | Plugins and AI in separate processes; systemd in v1, WASM in v2 | Accepted, amended by D92, D95 and D125; peer identity per spine AD-24 |
| D19 | Internal wire protocols: CBOR with closed types, MCP for AI processes | Accepted, amended by D130 |
| D20 | Event bus with stamped emitters and the outbox pattern | Accepted |
| D21 | Migrations: declarative SQL with authorizer, forward only | Accepted, amended by D84, D126 and D127 |
| D22 | Audit log: separate process, HMAC chain, off-machine anchors | Accepted, amended by D40 and D114 |
| D23 | Assistant memory behind `MemoryStore`; native backend by default | Accepted |
| D24 | Mail and calendar: IMAP/SMTP and CalDAV first; OAuth only bring-your-own-client | Accepted |
| D25 | Groceries: list first, cart prepared by an unofficial plugin, human validation | Accepted, cart tier settled by D44 |
| D26 | Front-end framework: Lit web components built with Vite | Accepted, amended by D139 |
| D27 | Transport: hybrid key exchange, no post-quantum claim | Accepted |
| D28 | Supply chain controls | Accepted, exceptions in D61, D123 and D129 |
| D29 | License: Apache-2.0 | Accepted |
| D30 | Messaging plugins are outbound only, for notifications | Superseded by D42 |
| D31 | Kill switch not available to tainted sessions | Accepted, amended by D86 |
| D32 | Bootstrap token and pairing protocol | Accepted, pairing amended by D35, order amended by D76 |
| D33 | Second factor: passkeys by default, TOTP as fallback only | Accepted, amended by D71 and D117 |
| D34 | Adding an adult from the CLI with a delay and a veto | Accepted, amended by D74, D77 and D88 |
| D35 | Browser pairing in an enrollment or by a PAKE-bound code | Accepted, amended by D122 |
| D36 | Unlock window chosen by the member; no delegation sub-key in V0.1 | Accepted, amended by D62 and D113 |
| D37 | Fields declared structured or free text; member taint as quoted data | Accepted, amended by D70, D98 and D104 |
| D38 | Elevated tier 1 calls go to a queue in the primary channel | Accepted, amended by D68, D104 and D122 |
| D39 | Recovery started on the host, finished in the browser | Accepted, amended by D75 |
| D40 | Audit anchoring by a remote sink until native devices exist | Accepted |
| D41 | Imported assistant memory is `external` | Accepted, amended by D112 |
| D42 | Secondary channels: bound senders, tier 0 and 1, outbound ceiling | Accepted, amended by D82 |
| D43 | Imported recipes are parsed into bounded fields, never promoted whole | Accepted |
| D44 | Cart preparation is tier 1 with light confirmation | Accepted |
| D45 | Promotion from `external` to `trusted` only from the host CLI | Accepted, amended by D112 |
| D46 | Tier 2 actions unregistered until the native app exists | Accepted, amended by D64 |
| D47 | A content-free out-of-browser notification channel per member | Accepted, amended by D105 and D118 |
| D48 | AI provider policy by data type | Accepted, amended by D80 and D103 |
| D49 | No MCP endpoint or other API for outside AI assistants | Accepted |
| D50 | Member context may shape household proposals | Accepted |
| D51 | Instance name fixed before enrollment; certificate chosen by the operator | Accepted, amended by D76 |
| D52 | Complete backups; a restore invalidates devices and sessions | Accepted, amended by D85 and D106 |
| D53 | Home partition under the instance key, sealed inboxes for locked partitions | Accepted, amended by D78, D93, D96 and D114 |
| D54 | Device adapters with named USB or local network grants | Accepted, amended by D78 and D115 |
| D55 | Household display: a paired device without a member | Accepted |
| D56 | Device action classes and the safe direction | Accepted, amended by D69, D72 and D91 |
| D57 | Home rules run unattended in the Core | Accepted |
| D58 | Rule and display principals | Accepted |
| D59 | Home failure behavior | Accepted, amended by D69 and D84 |
| D60 | Remote access by a WireGuard endpoint managed by Vilicus | Accepted |
| D61 | HPKE from an unaudited crate, with an internal review | Accepted, amended by D74, D107 and D120 |
| D62 | Delegation sub-keys for scheduled tasks after V0.1 | Accepted, amended by D94 and D111 |
| D63 | The researcher, a fourth AI role, contained | Accepted, amended by D73 |
| D64 | Disclosure grants between adults | Accepted, amended by D104 |
| D65 | Playbooks run by the Core without a model | Accepted, amended by D89 and D109 |
| D66 | Activatable modules and a per-member tool policy | Accepted |
| D67 | Own-account delivery as a named I13 exception class | Accepted, amended by D81 |
| D68 | A spoken confirmation approves elevated tier 1 only | Accepted, amended by D100 |
| D69 | Letting someone in or cutting infrastructure power: not before the native app | Accepted |
| D70 | Writes made or approved by a member are stored trusted | Accepted, amended by D99 and D104 |
| D71 | Step-up bound to the hash of one action | Accepted, amended by D124 |
| D72 | Safety-relevant from discovery | Accepted, amended by D109 |
| D73 | Researcher requests by a trusted fetcher without a model | Accepted |
| D74 | Member key pairs generated by the Core and authenticated at member add | Accepted, amended by D107, D117 and D119 |
| D75 | Out-of-browser acknowledgement by a one-time token | Accepted, amended by D135 |
| D76 | Bootstrap order: name and certificate before any passkey | Accepted, amended by D101, D105 and D138 |
| D77 | Re-enrollment and suspension from the CLI in V0.1 | Accepted, amended by D87 and D101 |
| D78 | Security adapter secrets sealed to the TPM | Accepted, amended by D108 |
| D79 | Zigbee cutover instead of a parallel run | Accepted |
| D80 | Data types per record kind; provider bound at token issuance; allergy filter | Accepted, amended by D103 |
| D81 | Own-account delivery follows the provider policy | Accepted |
| D82 | Secondary channel ceiling as an allowlist | Accepted, amended by D103 |
| D83 | The local model runtime as a component | Accepted, amended by D110 |
| D84 | Migrations on a copy, swapped in on success | Accepted |
| D85 | Unattended, verified, off-host backups | Accepted, amended by D106 |
| D86 | Core detectors suspend the offending task, never the whole assistant | Accepted |
| D87 | Lifting a suspension is approved in the app by another adult | Accepted |
| D88 | Member addition in a single-adult household | Accepted |
| D89 | Standing approval for own-account delivery in playbooks | Accepted |
| D90 | Web session: 15 minutes idle, 12 hours at most | Accepted |
| D91 | Life safety takes priority over the safe direction | Accepted |
| D92 | Only project-signed plugins before V1 | Accepted, amended by D102 |
| D93 | Sealed inbox rows are ingested as external by default | Accepted |
| D94 | Delegated runs read and write through the sealed inbox | Accepted, amended by D111 |
| D95 | Plugin persistent state | Accepted, amended by D111 |
| D96 | Instance key sealed to the Secure Boot state only | Accepted, amended by D108 |
| D97 | Claude subscription connector through the unmodified Claude Code binary | Accepted, amended by D101, D110 and D115 |
| D98 | Structured fields validated against their declaration on write | Accepted, amended by D104 and D146 |
| D99 | An approval does not launder free text | Accepted |
| D100 | Spoken yes after a template read-back | Accepted |
| D101 | V0.1 action surfaces and host-only paths | Accepted |
| D102 | First-party plugins in the main package until V1; a testbed for the gates | Accepted, amended by D141 |
| D103 | One data type taxonomy, carried by every record | Accepted |
| D104 | Structured means fixed at build time; assistant drafts readable as quoted data | Accepted, amended by D146 |
| D105 | Out-of-browser channel required at enrollment; named private destinations for the Core | Accepted, amended by D118, D133 and D134 |
| D106 | Backups to object storage, with passphrase wrappers sealed | Accepted |
| D107 | V0.1 events within one partition; crypto gates with done states and fallbacks | Accepted, amended by D117 |
| D108 | Secrets that open the house entered at the host CLI under a signed boot policy | Accepted |
| D109 | Relays fail closed; playbooks trigger only on trusted principals | Accepted |
| D110 | AI runtime isolation and an opt-in Claude subscription connector | Accepted |
| D111 | Delegated run descriptors; member-owned plugins only while unlocked | Accepted |
| D112 | Spoken provenance and per-item promotion of free text | Accepted |
| D113 | V0.1 values, named constants and new dependencies | Accepted, amended by D128, D130 and D132 |
| D114 | Audit and inbox files encrypted at rest | Accepted |
| D115 | No loopback address grants; per-port network isolation | Accepted |
| D116 | E32 pass criterion: one action through the pipeline under household load | Accepted; result in emulation and parameters in D136 |
| D117 | Fallbacks for the AD-36 construction and the passkey login half of E2 | Accepted |
| D118 | Out-of-browser channel defaults to a self-hosted UnifiedPush server | Accepted, amended by D135 |
| D119 | AD-36 construction validated by the key prototype, with fixed encodings | Accepted, amended by D121 |
| D120 | HPKE gate passed except its CI job: review, vectors and cross-test of the `hpke` crate | Accepted |
| D121 | Confirmation of the household key at its first receipt and at every unlock | Accepted |
| D122 | Browser device key, pairing code and light confirmation encodings | Accepted |
| D123 | OPAQUE libraries under a recorded exception to D28 | Accepted |
| D124 | Step-up challenge derivation and its setting in `webauthn-rs` | Accepted |
| D125 | Peer identity by cgroup membership and pidfd; default template profile | Accepted |
| D126 | Extension loading off on every connection; authorizer setup order | Accepted, amended by D127 and D144 |
| D127 | FTS5 virtual tables allowed in module migrations, under `SQLITE_DBCONFIG_DEFENSIVE` | Accepted, amended by D144 |
| D128 | Argon2id parameters and unlock concurrency | Accepted |
| D129 | Exception to D28 for the `argon2` crate, without its `parallel` feature | Accepted |
| D130 | Canonical CBOR profile and libraries | Accepted |
| D131 | Key memory rules from E16 | Accepted |
| D132 | Deletion is `secure_delete` ON plus a TRUNCATE checkpoint | Accepted |
| D133 | Egress proxy budgets in tunnels, ranged private destinations, allowlist before lookup | Accepted |
| D134 | Domain fronting: SNI check, IP-range fallback not adopted, Host-header fronting a named risk | Accepted |
| D135 | No acknowledgement token in the push payload; push server reachable off the household network | Accepted |
| D136 | E32 result in emulation and execution model parameters | Accepted |
| D137 | Overlay network addresses: private only on a named overlay interface | Accepted |
| D138 | Temporary certificate names IP addresses only; relying party checks the instance name | Accepted |
| D139 | External content sanitized with `ammonia`, then rendered on the port-based separate origin | Accepted |
| D140 | Crate graph read by reachability; `unsafe` confined to four named crates | Accepted, amended by D143 |
| D141 | The testbed starts the test doubles instead of linking them | Accepted |
| D142 | A fuzz crate outside the crate graph, on a dated nightly in its own job | Accepted |
| D143 | SQLCipher 4.19.0, self-built from a vendored amalgamation | Accepted |
| D144 | A module file registers only if its stored schema is exactly its declaration | Accepted |
| D145 | Tool declarations and the capability matrix check | Accepted |
| D146 | Field validation on write, reviewed-vocabulary labels and the envelope's stored form | Accepted |

## D1. Rust, single binary, no container requirement

Context: a household cannot operate a stack of services. Decision: one Rust executable with subcommands, installed by a package or a copy, run as several systemd services. Consequences: memory safety for the exposed parts; no Docker needed; process isolation is by systemd units, not containers.

## D2. SQLite with SQLCipher; PostgreSQL rejected

Context: encrypted storage with no external service. Decision: SQLite and SQLCipher, keys derived by the application with Argon2id because SQLCipher does not provide it. PostgreSQL is an external service, has no native transparent encryption, and a household's data volume is tiny. Consequences: file-level backups and encryption; no server-side concurrency features; careful use of `secure_delete`, and crypto-shredding where deletion must be real.

## D3. One database per module and per partition

Context: the brief called for one file per module and for partitions isolated by keys; a SQLCipher file has exactly one key. Decision: one file per (module, partition) plus Core files; the same module code opens several files. Consequences: cross-partition queries are done by the Core by opening several files; key rotation is per file; the link table lives in the partition of the data it links.

## D4. Key model: member DEK wrapped by several independent KEKs

Context: a single secret is either lost too easily or too weak. Decision: a random DEK per member wrapped by one KEK per enrolled passkey (WebAuthn PRF with HKDF and a per-credential salt, domain-separated), one from a mandatory Argon2id passphrase, one from an offline recovery secret. At least two authenticators, or one plus the printed secret, at enrollment. Consequences: no single point of loss; PRF is evaluated on the client and the Core receives the key, so this is not zero-knowledge, which is stated in all documents.

## D5. Instance admin separated from data keys

Context: an admin who can reset keys can read everything. Decision: the admin role manages the system and has no key; no reset re-wraps a member's key. Consequences: forgotten secrets are permanently lost; adding an adult to the household partition needs an unlocked adult. Limit: a host root can still do anything.

## D6. Recovery by printed secret, waiting period and alerts

Decision: every member gets a recovery secret at enrollment. Any recovery starts a waiting period (proposal 48 hours) with alerts on all devices and a cancel action. Total loss of every factor destroys the personal partition, and this is documented. Consequences: a stolen recovery secret is visible for two days; legitimate recovery is slow on purpose.

## D7. Household key: versioned, rotation, threshold recovery

Decision: a versioned household key wrapped once per adult. Rotation when a member leaves, with deferred re-encryption. Recovery by Shamir shares, 2 adults of N. Consequences: rotation protects only future and re-encrypted data. Open: for two-adult households the threshold adds little; whether it ships in v1 is undecided.

## D8. Background tasks: unlocked members, delegation sub-keys, or wait

Decision: tasks run for members who are unlocked, or through an explicit, scoped, revocable delegation sub-key that dies with the member's revocation, or wait for an unlock (maximum duration, then cancel and log), with a content-free notification. Consequences: a delegated module is decryptable with the instance key; the default is no delegation.

## D9. Instance key protects Core metadata only

Context: the Core must start unattended to show a login page. Decision: an instance key from a systemd credential, TPM-sealed when possible, protects `core.db` metadata and seals delegation sub-keys. It never opens member data. Consequences: disk theft without a TPM may reveal metadata, never data.

## D10. Tier 2 only from a paired native app, with signature over a displayed hash

Decision: the app receives the Core-signed request, computes and displays the canonical hash, signs it with a hardware-bound key under user verification, nonce, expiry under 2 minutes; the Core recomputes and verifies; the Gateway relays only. Consequences: the Gateway can only deny service; the app must know each action type's template; unknown types fail closed.

## D11. The web client never does tier 2

Decision: web sessions never confirm tier 2, are limited to 15 minutes, and unmanaged browsers do not get data sessions. Reason: WebAuthn does not prove what was displayed, and the Gateway is not trusted. Consequences: a user without the Android app cannot approve tier 2; the desktop app with a TPM or Secure Enclave key is an intermediate case.

## D12. Protected Confirmation, Secure Payment Confirmation, extensions

Decision: Android Protected Confirmation as reinforcement for the most sensitive actions where `isSupported()` at runtime; Secure Payment Confirmation as an opportunistic bonus on Chrome and Edge; the WebAuthn transaction-authorization extensions are abandoned in practice and not used. Consequences: no design depends on any of these.

## D13. The model is untrusted; reader, planner and drafter roles

Decision: the model is a component that proposes; the Core decides. The reader returns only closed enums, bounded numbers and opaque identifiers resolved by the Core; notifications are static templates. A drafter handles reply writing with local, human-only output. Consequences: some usefulness is lost on purpose; ~~external MCP assistants get typed reader output by default~~ (withdrawn by D49).

## D14. Taint is mandatory metadata on every record

Decision: `source` and `taint` on every record of every module, inherited toward the most restrictive; derived summaries are tainted; promotion is tier 2; another member's data is `member` taint to a member's assistant. Consequences: storage-layer enforcement; taint creep may cause friction (R7).

## D15. "Reversible" means without effect on a third party

Decision: any outbound network effect (RSVP, moving an event with guests, external sync, sharing, sending) is tier 2. The only exception is a system notification (static template, own channel, rate limited). Consequences: more signed confirmations; batching is required to keep them rare.

## D16. Local alignment controller as third layer

Decision: a small local model, structured input only, constrained output with probability and confidence, after deterministic rules and before the human, fail closed, never for irreversible, financial or third-party actions, thresholds human-only. Proposed v1: 3 to 4 billion parameter model, GGUF Q4, grammar-constrained, logprob-based, recalibrated on household cases; v2: fine-tuned encoder. Consequences: quality in French and CPU latency are untested; false accept rate gates release.

## D17. No dependency on Jev (TypeSafe AI)

Decision: use it as a conceptual reference only (Choice, Score, Noul primitives). It is proprietary, API only, English first, not self-hostable. Consequences: at most an optional connector for non-sensitive data.

## D18. Plugins and AI in separate processes; systemd in v1, WASM in v2

Decision: no third-party code in the Core process. A Unix socket per plugin created by the Core with `SO_PEERCRED`, a fixed sandbox profile tested in CI, an egress proxy with an exact-hostname allowlist. Signed manifest bound to the binary hash; rights changes need a diff and a passkey. WASM (WASI 0.3) later behind the same interface. Consequences: process management cost; kernel escapes remain possible (R10).

## D19. Internal wire protocols

Requirements: closed types with `deny_unknown_fields`, bounded frames, timeouts, mandatory taint. Decision: CBOR with closed types and length-prefixed bounded frames on every socket between the Core and the Gateway, the audit writer, the egress proxy and plugins; MCP only between AI processes and the Core, behind a framing layer that bounds message size. CBOR is already needed for canonical hashing, so one codec serves both. Consequences: third-party plugins are written against the plugin SDK, not by hand in JSON (architecture spine AD-12 and AD-13).

## D20. Event bus and outbox

Decision: Core-stamped emitters, ACL per topic, plugin events always `external`, no tier 2 transition triggered by an event. Cross-module consistency by events and outbox; no cross-database transactions; opaque identifiers and a Core link table. Consequences: eventual consistency, idempotent consumers.

## D21. Migrations

Decision: declarative SQL embedded, hash frozen and signed in the registry, applied on a dedicated connection with an SQLite authorizer refusing `ATTACH`, `DETACH` and non-allowlisted `PRAGMA`; extension loading disabled; forward only; automatic backup before; the Core refuses a module whose database is newer than its code.

## D22. Audit log

Decision: HMAC hash chain written by a separate process with its own key; no sensitive parameters in clear; head hash anchored off the machine at every tier 2 event (device-held, optional remote sink); plugins cannot write. Consequences: root can rewrite back to the last anchor only.

## D23. Assistant memory behind `MemoryStore`

Decision: interface for episodes, entities, dated facts with validity, provenance, invalidation, quarantine, rollback. Native Rust backend on encrypted SQLite (full text and vectors) by default; Graphiti (Python, Apache-2.0, needs a graph server) only as an optional annex. Long-term memory is Markdown documents with frontmatter in the partition database. Consequences: the annex backend leaves the SQLCipher boundary and is opt-in per partition.

## D24. Mail and calendar connectors

Decision: IMAP/SMTP with application passwords and CalDAV in v1. Gmail and Outlook through OAuth only with a household-owned client, read-only by default. A shared verified application is unrealistic (Google's yearly security assessment for restricted Gmail scopes). Work accounts under corporate policy may be blocked. Refresh tokens are encrypted with the member's key.

## D25. Groceries

Decision: generated shopping list; cart prepared by an unofficial plugin acting in the user's own session; human validation before any order; no shared catalog or prices between households; no anti-bot circumvention; first step semi-manual; use an official API whenever one exists. ~~Open: cart preparation is tier 2 in the matrix (outbound effect on an external account); a per-plugin relaxation is possible once cart operations are proven reversible.~~ Settled by D44: tier 1 with light confirmation.

## D26. Front-end framework

Context: one responsive front end with a strict CSP (nonces, Trusted Types). Decision: Lit web components built with Vite, served as static files by the Gateway, no server-side rendering. Lit ships its own Trusted Types policy; Solid and Leptos write raw strings to `innerHTML`, and Svelte's policy passes HTML through. `unsafeHTML` and every other HTML-from-string path are banned by lint, and a CI browser test loads every page under the production CSP. Consequences: a thinner component ecosystem for calendars and drag and drop (architecture spine AD-19).

## D27. Transport: hybrid key exchange, no post-quantum claim

Decision: TLS 1.3 with X25519MLKEM768 through rustls with aws-lc-rs where the client supports it, tested by real handshake on each client; AES-256 at rest with Argon2id-derived keys; versioned algorithm identifiers. No post-quantum signatures in v1 (no public CA issues them, WebAuthn support is in drafts) and no extra application-layer encryption (young libraries, recent advisories). The documents never say "post-quantum" or "quantum-safe" as a property of the product. Clarified by E3 (story 1.16): the server takes the first group in the client's list that it also supports, so the hybrid exchange is used when the client prefers it (lists it before any other group the server supports); a client that lists a classical group first gets that classical group.

## D28. Supply chain controls

Decision: `cargo deny`, `cargo vet`, vendoring with `--locked`, allowlist for build scripts and proc macros, `forbid(unsafe_code)` in modules, minimal Core dependencies, SBOM, offline-signed releases with anti-rollback; reproducible builds by two builders as a goal.

## D29. License

Decision (owner, 2026-10-16): Apache-2.0, the license of the owner's other project, applied through the `LICENSE` file at the repository root. Consequences: permissive reuse with an explicit patent grant; every dependency must be compatible with Apache-2.0, which `cargo deny` checks.

## D30. Messaging plugins are outbound only

Decision: Telegram, Signal and WhatsApp plugins send notifications without sensitive content. Inbound messages are untrusted content that triggers no action. No tier 2 confirmation transits any plugin. Consequences: no chat-style control of the assistant over those channels in v1.

## D31. Kill switch not available to tainted sessions

Decision: only the human or a Core detector can trigger it; resuming needs a passkey. Reason: otherwise an injection can switch the system off at will.

## D32. Bootstrap token and pairing protocol

Decision: 128-bit one-time bootstrap token (15 minutes, loopback and LAN only, certificate fingerprint printed); device pairing with a 128-bit QR token (2 minutes, single use, bound to the initiator's session), a validation code typed on the already-paired device, 3 attempts, notifications to all devices, 24 hour delay before tier 2.

## D33. Second factor

Decision: passkeys by default; TOTP only as a login fallback, never for tier 2, pairing, recovery or step-up.

## D34. Adding an adult from the CLI

Context: the design asked every other adult to sign, which needs the native app. Decision: an existing adult authorizes a new adult from the host CLI with their passphrase; an enrollment token, a delay with notification and a passkey veto by any other adult follow, and the household key is wrapped at the next adult unlock after the delay. Removal follows the same pattern. Consequences: works before the native app; the instance admin alone can do nothing (PRD FR-8, FR-9).

## D35. Browser pairing

Amends D32. Decision: a browser becomes a paired device during an enrollment or with a short code bound to its key registration by a PAKE (OPAQUE), issued by a paired device or the CLI; it holds a non-extractable key that binds its sessions and signs light confirmations. No QR scan is needed. Consequences: protects against network observers and replay, not against a compromised Gateway, which serves the page's code (PRD FR-15, FR-16, section 8.2).

## D36. Unlock window

Amends D8. Decision: a member chooses at unlock how long their partition stays unlocked after the web session ends, up to a maximum; locking and the kill switch end it. No delegation sub-key in V0.1. Consequences: background work runs only inside a window; unlocked keys stay in memory longer (PRD FR-12, FR-57).

## D37. Structured and free-text fields

Amends D14. Decision: every schema field is declared structured or free text with a maximum length. Household data written by another adult reaches the planner as quoted data with its taint; `external` free text reaches it only as typed reader output. Consequences: injection between adults is contained by taint and confirmation, not prevented (PRD FR-58).

## D38. Elevated tier 1 queue

Decision: without the alignment controller, an elevated tier 1 call becomes a pending request in the app, with expiry, re-verification of state at approval, an approval signed by the device key, refusal counting and per-module low-risk exemptions. Consequences: friction is measured (PRD FR-28, SM-4).

## D39. Recovery from the host

Amends D6. Decision: recovery starts with the recovery secret at the host CLI, alerts every adult out of the browser, waits until the member's own channel acknowledges (capped), then finishes in the browser with an enrollment token. Consequences: a member without host access depends on the operator (PRD FR-14).

## D40. Audit anchoring by a remote sink

Amends D22. Decision: until native devices hold head hashes, an optional remote sink receives the head hash; the README claim says that tampering by root is detected only when a sink is configured (PRD FR-32).

## D41. Imported assistant memory

Decision: memory imported from a previous assistant is `external`; facts the member wrote and validated are promoted by batch from the host. Consequences: a knowledge graph extracted by a model is not used for planning (PRD FR-36).

## D42. Secondary channels

Supersedes D30. Decision: a member binds a sender identity on a messaging service from the app, proven by a challenge; one-to-one conversations only; a bound channel triggers tier 0 and tier 1 only; inbound content is untrusted and taints the session; outbound content stays under a per-channel ceiling, from templates, with a pointer to the app. Consequences: SIM swap or a compromised plugin acts within those limits (PRD FR-37, FR-38).

## D43. Recipe import

Decision: an imported recipe is never promoted as a whole; a deterministic parser, fuzzed in CI, yields bounded fields; ingredients map to a canonical table by a human; steps and descriptions stay `external` and never reach the planner (PRD FR-40).

## D44. Cart preparation tier

Amends D15. Settles D25's open point. Decision: preparing a cart in the member's own store account is tier 1 with light confirmation, under a named exception class of I13 (reversible external state, no effect visible to a third party); ordering and payment always stay with a human on the store's website (PRD FR-47, FR-48). The store connector searches by canonical ingredient name only; free-text items are listed to the member as not added.

## D45. Promotion from the host

Amends D14. Decision: promotion from `external` to `trusted` happens only through the host CLI, by batch and category after reviewing a sample, for data the member authored or imported; never through the Gateway (PRD FR-59).

## D46. Tier 2 unregistered before the native app

Decision: tier 2 actions are not registered at all until the native app exists, rather than degraded to a weaker confirmation; V0.1 lists the invariants it can test as release gates (PRD FR-60, FR-61).

## D47. Out-of-browser notification channel

Decision: each member configures at least one content-free channel that does not depend on an open browser, for security alerts; V0.1 ships a push webhook (PRD FR-56).

## D48. Provider policy by data type

Decision: health data (children's included), the private journal and the budget use the local model only; meals, plan, stock and the shopping list may use a remote provider configured by an adult; other data follows the strictest applicable rule. A call routed to an unconfigured provider fails closed (PRD FR-68).

## D49. No API for outside AI assistants

Amends D13. Decision: Vilicus exposes no MCP endpoint and no other API to outside AI assistants; MCP is internal between its AI processes and the Core. The README promise that any MCP-capable assistant drives Vilicus is withdrawn, and experiment E21 is dropped (PRD FR-25, section 5).

## D50. Member context in household proposals

Decision: the assistant may use the requesting member's context to propose household writes, executed as that member, without copying any free text of the member's personal partition into a household record (PRD FR-67).

## D51. Instance name and certificate

Decision: passkeys are bound to the instance name, so it is fixed before the first enrollment, with a certificate source chosen by the operator; a rename re-enrolls passkeys with a token and the passphrase, without data loss while passkeys do not wrap data keys (PRD FR-65, FR-66).

## D52. Complete backups

Decision: backups include `core.db`, the audit log and its key, and the instance key, both keys wrapped by a backup secret; a restore invalidates every device, web session, enrollment token and channel binding (PRD FR-53).

## D53. Home partition and sealed inboxes

Amends D9. Context: home automation must run with every member locked. Decision: a home partition whose keys derive from the instance key holds devices, rules, modes and current state; sensitive history, and history destined for a locked partition, is sealed to that partition's public inbox key and ingested at its next unlock. Consequences: root on the host, or the thief of a disk without a TPM, can read the home partition; it holds current state and a short event window, not history (PRD FR-71, FR-76; spine AD-37).

## D54. Device adapters

Decision: device adapters are plugins; a grant of a named USB device, Unix socket, loopback port or private address range is an H action; a daemon an adapter depends on runs on loopback only under Vilicus's management. Internet access stays behind the egress proxy (PRD FR-73; spine AD-38).

## D55. Household display

Decision: a wall tablet is a paired device without a member, enrolled by an adult through an H action, limited to the home domain and to tier 0 and tier 1 home actions on devices that are not safety-relevant (PRD FR-81; spine AD-40).

## D56. Device action classes

Amends D15. Decision: a physical action undone by restoring the previous state is tier 1 under a named I13 exception class; rules and tier 1 callers move safety-relevant devices only toward the safe state; unlocking, disarming, opening and cutting infrastructure power are H actions, never done by the assistant (PRD FR-80; spine AD-39).

## D57. Unattended home rules

Amends D8. Decision: home rules are deterministic code in the Core, running with every member locked under a rule principal, without a model and without a member key (PRD FR-78; spine AD-39).

## D58. Rule and display principals

Decision: two principals outside capability tokens bound to one member: a rule validated by a human, and a household display. Taint gating, caps and the kill switch apply to AI and plugin principals; the kill switch suspends rules of assistant origin but never the house (spine AD-8, AD-11).

## D59. Home failure behavior

Decision: the home partition migrates at the first start of a new version; disarm, unlock and pausing automations proceed while the audit writer is down; safety-relevant actions wait for a human after a clock jump; a heartbeat lets a monitor outside the host notice that the Core stopped (PRD FR-82, FR-84; spine AD-41).

## D60. Remote access by WireGuard

Decision: acting away from home goes through a WireGuard endpoint managed by Vilicus: the host network configuration owns the interface, a dedicated unit with only network administration rights applies the peer list the Core sends, and adding a peer is an H action tied to a device's pairing. TLS still ends at Vilicus. Consequences: one UDP port is forwarded on the router; on Android the tunnel takes the single VPN slot (PRD FR-86; spine AD-42).

## D61. HPKE from an unaudited crate

Context: wrapping the household key to a member's public key and sealing inboxes need HPKE, and no audited Rust implementation exists. Decision: an exception to D28 for the `hpke` crate, with an internal security review of the crate and of Vilicus's use of it before the code that wraps the household key, a cross-test against a second implementation and the RFC 9180 test vectors in CI, and an external review before V1; the documentation never calls it audited (spine AD-18).

## D62. Delegation sub-keys for scheduled tasks

Amends D8, D9 and D36. Context: the previous assistant runs a briefing and reminders on time; members are locked at night. Decision: after V0.1, a member may opt in, per scheduled task, to a sub-key that opens one module file in one partition, created by an H action (with delay and veto for a household-partition module), sealed by the instance key, revocable with re-keying. Every data type may be delegated. Consequences: delegated data is readable by root on the host, by the instance admin with a backup and its backup secret, or by the thief of a disk without a TPM; the owner accepts this internal risk (PRD FR-87, FR-88; spine AD-43, AD-44).

## D63. The researcher

Context: open web research is frequent and valuable, and a role that browses is an exfiltration path. Decision: a fourth AI role receives only the member's question, starts from a Core-templated query, may follow only links found verbatim in fetched pages (GET, no model-composed query string, no cookies, internal addresses blocked), parses pages inside its sandbox or an isolated browser plugin, and writes a report shown only to the human. The egress proxy gets a researcher mode (any public host, per-host budgets). Amends P7 and I4 for this role only (PRD FR-90, FR-105; spine AD-46).

## D64. Disclosure grants

Amends D46 for this case only. Decision: a member may share a minimal value derived from their own data with another adult through an H action that selects a derivation function registered in code, its fields, frequency, recipient and expiry; the Core computes it, keeps its source data type, stores it `trusted` with the granting member as author (so the recipient's assistant reads it as `member` taint), then seals it into the recipient's inbox; revocable; audited without the value (PRD FR-92; spine AD-49).

## D65. Playbooks

Context: the previous assistant gains skills by adding a file; modules are compiled code. Decision: declarative, versioned, schema-validated playbooks run by the Core under a `Playbook` principal with no model step, each step through the pipeline, at most tier 1 or a safe-direction home command, outbound only through system notifications or own-account delivery; assistant-origin playbooks are suspended by the kill switch (PRD FR-98; spine AD-45). A message step picks a template from the closed set shipped with Vilicus, or uses text the member typed in full (D99); its parameters are Core-resolved values of data types allowed on the destination channel; text drafted by the assistant is never a notification template.

## D66. Activatable modules and tool policy

Decision: modules that not every household needs are off until activated (household activation is H with delay and veto; per member, that member with step-up); a member's tool policy is a subset of the capability matrix intersected with every token issued for that member, widened only by the member (PRD FR-99, FR-100; spine AD-47).

## D67. Own-account delivery

Amends D15. Decision: a write to an account the member owns that nobody else sees (mail to themself, a file in a dedicated folder, an unpublished blog draft) is tier 1 with light confirmation, under the named I13 exception class `own_account_delivery`; the exception classes of I13 form a closed set (PRD FR-91, FR-101 to FR-103; spine AD-48).

## D68. Spoken confirmation

Amends D38. Context: the previous assistant accepts an oral yes. Decision: a spoken confirmation can approve an elevated tier 1 request that carries no I13 exception class, and nothing else: never a cart, own-account delivery, a rule, a scheduled task, a playbook, an H action or tier 2. Audio is transcribed locally only (PRD FR-94; spine AD-20).

## D69. Letting someone in: not before the native app

Amends D56 and D59. Context: before the native app, a step-up happens in a browser whose code the Gateway serves, so a compromised Gateway can show one action and have the member approve another. Decision: unlocking, disarming, opening and cutting infrastructure power are not offered by Vilicus at all until the native app exists; then they are tier 2 on the native app. Until then the household uses the device vendor's app or a physical gesture; Vilicus arms, locks, closes and alerts.

## D70. Writes made or approved by a member are stored trusted

Amends D14 and D37. Context: storing as `external` everything written by a session that read another adult's data would make household free text unusable for any planner. Decision: a write the member makes, or explicitly approves, is stored `trusted` with that member as author; structured fields of `member` taint do not taint the session; free text of `member` taint still does. E23 gets a fallback if friction stays high.

## D71. Step-up bound to one action

Amends D33. Decision: every step-up assertion signs a challenge derived from the hash of exactly one pending action; an assertion cannot be replayed for another action. Consequence: it does not stop a compromised Gateway from showing a different action, which is why D69 keeps the most dangerous actions off the web.

## D72. Safety-relevant from discovery

Amends D56. Decision: locks, alarms, cameras, gates, garage doors and covers of unknown kind are safety-relevant as soon as they are discovered; an adapter cannot change the class of a confirmed device; reclassifying is an H action.

## D73. Researcher requests by a trusted fetcher

Amends D63. Context: a proxy that does not decrypt TLS cannot enforce GET-only and verbatim-link rules, and a browser running page scripts makes its own requests. Decision: every researcher request is made by a trusted fetcher with no model, after the Core checks the URL; if a browser renderer is kept, it has no network and only renders bytes the fetcher returned.

## D74. Member key pairs and their authentication

Amends D34 and D61. Decision: the Core generates each member's key pair at enrollment; at `member add`, the Core derives a MAC key from the enrollment token and wraps it under a key derived from the authorizing adult's unlocked household key (key management, section 2); that key authenticates the new member's public key before the household key is ever wrapped to it. The construction (spine AD-36) and the internal HPKE review and cross-test (D61) gate V0.1.

## D75. Out-of-browser acknowledgement

Amends D39. Decision: each recovery alert carries a one-time token that the member redeems at the Core from a device they control; the limits are stated (a compromised device or Gateway can redeem it). Without a redeemed token, the waiting period runs to its cap.

## D76. Bootstrap order

Amends D32 and D51. Decision: bootstrap token, then instance name and certificate, then the instance admin's passkey, then the first member; no WebAuthn ceremony runs over the temporary self-signed certificate (E24 confirms browser behaviour).

## D77. Re-enrollment and suspension in V0.1

Amends D34. Decision: the V0.1 CLI adds `vilicus member reenroll` (an enrollment token for a lost passkey, after a rename or after a restore) and `vilicus member suspend` (sessions, devices, bindings and unlock window revoked, data kept, no household key rotation). `device pair`, `unlock` and `reenroll` require the target member's own passphrase.

## D78. Security adapter secrets sealed to the TPM

Amends D53 and D54. Decision: secrets of adapters that drive physical security devices are sealed to the host's TPM; a host without a TPM cannot run such adapters; these secrets are not restorable from a backup and are entered again after a restore on another host.

## D79. Zigbee cutover

Context: one coordinator cannot serve two stacks. Decision: the current home automation software keeps the coordinator until cutover day, then Vilicus takes it; the parity checklist runs in parallel for the other device families and on Zigbee after the cutover, with a written rollback to the current software (PRD FR-83).

## D80. Data types and the provider

Amends D48. Decision: every record kind declares its data type in the module registry; when a capability token is issued, the Core binds the provider from the data types the session may read; children's dietary constraints are applied by a deterministic Core filter before and after a remote meal-planning call, and the remote model never receives them.

## D81. Own-account delivery and the provider policy

Amends D67. Decision: own-account delivery follows the provider policy by data type and the outbound content check; local-only data types are never delivered to a hosted account. A delivery body is plain text, or HTML rendered by the Core from a template that references no remote resource. Model-composed text in a delivery, a deposited file or a draft contains no URL except URLs that appear verbatim in the source records it cites; a deposited HTML, Markdown or SVG file and a draft reference no remote resource; draft images are only files the member uploaded. An own-account delivery tool takes no destination argument: the Core resolves the destination from the member's account registered by an H action. A destination is hosted unless its host resolves to the Vilicus host or to an address range the household declared private by an H action.

## D82. Secondary channel ceiling as an allowlist

Amends D42. Decision: a secondary channel's ceiling lists the data classes Vilicus may send on it; presence, home state, alarm state, the calendar and children's data are excluded unless an adult adds them.

## D83. The local model runtime

Decision: the local model runtime is its own component: a separate unit with Unix sockets only, no network, no cache shared across members or roles, and model files pinned by hash (spine AD-51).

## D84. Migrations on a copy

Amends D21 and D59. Decision: each migration runs on a copy of the file that is swapped in only on success; a failure keeps the previous file, stops only that file's module for that partition and alerts the instance admin; `vilicus upgrade check` reports pending and failed migrations.

## D85. Unattended backups

Amends D52. Decision: backup keys are wrapped to a backup public key whose private key stays offline, so backups run unattended; a timer schedules them, an off-host target receives them, `vilicus backup verify` checks them, and CI runs a restore drill.

## D86. Core detectors suspend the offending task

Amends D31. Context: a detector that triggers the global kill switch lets an injected session lock the whole household by provoking denials. Decision: a Core detector (cap breach, loop detection, repeated denials) suspends only the offending task or AI session; only a human triggers the kill switch (PRD FR-30).

## D87. Lifting a suspension

Amends D77. Decision: lifting a member's suspension is an H action approved in the app by another adult with a step-up bound to that action (D71), followed by the delay and veto of adding an adult, with every adult notified (PRD FR-107). It needs no passphrase.

## D88. Member addition in a single-adult household

Amends D34. Decision: when no other adult exists, nobody can veto an addition; the authorizing adult is notified at each step and can cancel during the delay (PRD FR-8).

## D89. Standing approval for own-account delivery

Amends D65. Decision: a playbook may deliver to an account its owner owns without a confirmation at each run once the owner grants a standing approval for that destination; the approval is revocable, listed in the member's settings, and still follows the provider policy (D81) (PRD FR-98).

## D90. Web session length

Amends D11 on session length. Decision: a web session ends after 15 minutes without activity and lasts 12 hours at most; every request stays signed by the browser's device key, so a stolen cookie alone is useless; re-authentication is a passkey assertion.

## D91. Life safety first

Amends D56. Context: the safe direction protects against intrusion, not against fire, water or frost. Decision: while a smoke or water alert is active, lock, close and cut commands are suspended, shutters may open, and every adult is alerted; Vilicus still unlocks and disarms nothing (D69). A heating valve is never closed below a floor temperature. A closing command on a gate or a garage door relies on the device's own obstacle detection and is refused when the device reports none.

## D92. Plugins before and after V1

Amends D18. Decision: before V1, only plugins signed by the project's offline key can be installed. After V1, a third-party plugin signed by its author may be installed through an H action with delay and veto; any of its write operations that does not map to a row of the capability matrix is tier 2, and it can declare no I13 exception class.

## D93. Sealed inbox ingestion

Amends D53. Context: inbox rows are authenticated under a key derived from the instance key, so whoever holds that key can forge them. Decision: an ingested row is stored `external` unless it also carries a MAC under a key derived from the household key, which the instance key holder does not have; the Core adds that MAC only when it produces the row while an adult is unlocked (a disclosure grant computed while its owner is unlocked, D64), so such rows keep their stored taint. Ingestion is journaled and reviewable and runs continuously while the target partition is unlocked; the documents state that the inbox boundary protects confidentiality, not integrity, against the instance key holder for rows without that MAC. A row with a household-key MAC proves only that the Core of an unlocked adult produced it, which an operator who is an adult can also do (R19). Ingestion accepts such a row only when its grant identifier names a live grant the recipient was notified of at creation, its author is that grant's owner and never the recipient, and its fields match the grant's registered derivation. The MAC input binds the grant identifier, owner, recipient and a sequence number.

## D94. Delegated runs

Amends D62. Decision: a run that holds a delegation sub-key reads the delegated module file and writes only through the owner's sealed inbox; revoking a sub-key marks the file for re-keying at the owner's next unlock, and the sub-key copy in older backups stays usable until then (PRD FR-88).

## D95. Plugin persistent state

Amends D18. Decision: each plugin gets an encrypted state store in its own state directory, keyed from the instance key for household-owned plugins and from the owning member's partition key for member-owned ones; the store is part of backups, except the TPM-sealed secrets of security adapters (D78). A member-owned plugin runs only while its owner is unlocked or holds a delegation sub-key.

## D96. Instance key sealing

Amends D9 and D53. Decision: the instance key is sealed to the TPM's Secure Boot policy only (PCR 7), so kernel updates do not lock the house; after an unseal failure (firmware change, TPM reset), the instance admin restores the instance key from a backup with the backup private key, which the documentation states as part of the recovery runbook.

## D97. Claude subscription connector

Context: the owner's current assistant runs on a Claude plan, and the owner wants to keep using it with Vilicus. Decision: Vilicus ships a Claude subscription connector. It runs the unmodified Claude Code binary in headless mode, one unit per connected member, and serves only that member's own sessions and runs. Sign-in completes through Anthropic's own flow, started by the member at the host CLI; Vilicus never reads, copies, stores or backs up the credential. Every built-in tool of the binary is disabled, it sees only the Vilicus MCP tools of its token, keeps no transcript and reaches the network only through the egress proxy (spine AD-53). Connecting is the H action that configures any provider (PRD FR-68), and the provider policy by data type applies to it like any provider (D48, D80). Consequences: the credential sits outside the Core's key hierarchy and outside backups (R39); E30 tests the containment before the connector ships.

## D98. Structured field validation

Amends D37. Context: the rule that structured `member` fields do not taint a session (D70) holds only if a structured field cannot carry text; an identifier that accepts 200 characters is an injection channel. Decision: the storage layer validates every structured field against its declaration on every write: a closed type (an enumeration from a closed list, a bounded number, a date, an identifier of a fixed format and character set) and its maximum length; a value outside the declaration is refused, never truncated or coerced. A fuzz test drives every module write path with values outside their declaration (PRD FR-58, ai-safety I40).

## D99. An approval does not launder free text

Amends D70. Context: a tap can be given out of fatigue and, before the native app, forged by a compromised Gateway (R16), so a tapped approval must not turn injected text into trusted text. Decision: an approval authorizes the write and stores its structured fields `trusted`, but free text drafted in a tainted session keeps `external` whatever the approval, and editing the draft, by any amount, does not change that; only text the member writes in full in an empty field of the approval screen is stored `trusted`. No edit ratio is used: any threshold would be tuned by the same fatigue it guards against. Before the native app, the approval screen is served by the Gateway, so this rule bounds approvals given out of fatigue, not a compromised Gateway (R16). Structured fields of an approved write are stored `trusted` as before. E23 measures the friction under this rule.

## D100. Spoken yes after a read-back

Amends D68. Decision: before a spoken yes, Vilicus reads the request back from a fixed template filled only with the request's structured fields, never from model text, and the yes approves only the request read back, bound to its hash (D71). A request that cannot be read back from its structured fields cannot be approved by voice.

## D101. V0.1 action surfaces and host-only paths

Amends D76, D77 and D97. Context: the web client was said to cover every V0.1 account and administration task, yet about nine V0.1 actions had no stated surface, and before the native app a compromised Gateway can show one action and have the member approve another (R40). Decision: PRD FR-50 lists every V0.1 action with its actor, surface and confirmation. Four actions run only at the host CLI as root, because a compromised Gateway must not decide them: changing the listening address or exposure (`vilicus instance listen`, which rewrites the socket unit); redeeming the admin recovery code (`vilicus admin recover`, which prints a one-time admin enrollment token; the code is printed only on the host console at bootstrap, stored only as an Argon2id hash, and no web route accepts it); `vilicus member enroll-first` (root plus the admin recovery code, refused once a member exists); and, after V0.1, `vilicus ai connect claude <member>` (that member's passphrase, only after the provider configuration H action of PRD FR-68 has passed its delay). A host kill switch, `vilicus killswitch` (root, no passphrase), exists beside the web one. A member may suspend their own account: `vilicus member suspend` also accepts the member's own passphrase for their own account. Lifting any suspension stays as D87 states. In V0.1, provider configuration is reachable through the Core API only, exercised against the test double; its screen ships with the meals milestone. Consequences: an adult without host access needs the operator to change exposure, the same dependency as recovery (R21). Lifting a suspension stays a browser H action, so before the native app a compromised Gateway that shows one action while the member approves another can lift a suspension; the delay, the veto and the out-of-browser alerts bound it (R40).

## D102. First-party plugins in the main package until V1; a testbed for the gates

Amends D92. Context: the release gates and the V0.1 screens need the reference module and the test doubles, which are never linked into the shipped binary, and the V0.1 plugin signature rule had no install command. Decision: until V1, first-party plugins ship inside the signed main package, version-locked to the Core, so the signature rule of D92 is met by the package signature and V0.1 has no `vilicus plugin install` command. A `vilicus-testbed` binary, never packaged, links the reference module and the test doubles and accepts a CI test key; release gates that need a module or a double run against it, and every other gate runs against the shipped `.deb`. UJ-1 to UJ-3 run automated in the Debian VM with a virtual authenticator, and manually once per release on one Android phone and one desktop browser (PRD FR-109). The protocol handshake of spine AD-12 still lands in V0.1. Consequences: no install path, protocol version window or test key in V0.1; the plugin install H action is first exercised in the home milestone.

## D103. One data type taxonomy, carried by every record

Amends D48, D80 and D82. Context: the provider policy read a "data type" per record kind and the secondary channel ceiling a "data class"; neither closed set was written down, both feed V0.1 release gates (I15, I22, I36), and a type declared per record kind cannot describe a derived record such as a conversation turn, a memory fact or a digest. Decision: "data type" is the only term, and `vilicus-types` holds its closed set: `health`, `journal`, `budget`, `meals`, `meal_plan`, `stock`, `shopping_list`, `presence`, `home_state`, `alarm_state`, `calendar`, `child`, `mail_raw`, `household_other`, `personal_other`. A remote provider is allowed by default for `meals`, `meal_plan`, `stock` and `shopping_list`; `health`, `journal` and `budget` can never be widened to a remote provider. Every record stores the set of data types it contains; a record kind declares the types its fields may hold, and a derived record's set is the union of its inputs' sets, computed by the Core like taint (I43). A secondary channel ceiling is an allowlist of data types, applied as input gating when a token is issued for any session whose output may reach that channel. Consequences: one stored column, decided before the record envelope freezes in V0.1; a conversation that touched a local-only type stays on the local model, and its history is never loaded into a remote or Claude-connector session.

## D104. Structured means fixed at build time; assistant drafts readable as quoted data

Amends D37, D38, D64, D70 and D98; implements D99 without changing it. Context: the taint model rests on structured fields being unable to carry instructions, but run-time vocabularies and wide identifiers passed as structured, and the assistant's own approved drafts became unreadable to every planner. Decision: a field is structured only if its value set is fixed at build time: a compiled enumeration, a bounded number, a date, or an opaque UUIDv7. A run-time vocabulary (tags, categories, room, scene, mode or ingredient names) is free text, unless it is declared a reviewed vocabulary: an adult confirms each new label, at most 32 characters from a restricted alphabet, and only confirmed labels are accepted as structured values. A record kind exempt from the elevated queue (D38) accepts only structured fields from an AI principal. A member-approved assistant draft is stored `external` (D99) and reaches a planner as quoted data within its maximum length, tainting the session. A member-written field that contains 8 or more consecutive words of the assistant's draft is stored `external`; this is a verbatim test, not an edit ratio. A disclosure grant derivation returns closed types only, and its stored taint follows its inputs (I9). A household write from a session that has read personal free text is elevated. Consequences: one confirmation per new vocabulary label, and more elevated requests for household writes drawn from personal context, which E23 measures.

## D105. Out-of-browser channel required at enrollment; named private destinations for the Core

Amends D47 and D76. Context: the veto window and the recovery and suspension alerts rest on the out-of-browser channel, but no step required it, its experiment could not fail, and the egress proxy's block on internal addresses ruled out the self-hosted push server it offers. Decision: an enrollment or re-enrollment completes only after the member redeems the token of a test notification sent to their out-of-browser destination. The bootstrap order becomes: bootstrap token, instance name and certificate, the instance admin's passkey, the instance admin's destination confirmed the same way, then the first member. While an adult has had no working destination for 24 hours, every page shows a blocking banner, and the waits of member addition and recovery (PRD FR-8, FR-14) run to their maximum. E13 passes at 99 % of alerts delivered within 10 minutes over 7 days per phone, idle nights included; its fallback is a second push distributor within the same webhook transport, plus maximum waits. Core-originated traffic (push webhook, backup upload, remote audit sink, heartbeat) may reach a private host and port that the instance admin names through an H action with step-up, alerted to every adult; the egress proxy allows that destination to the Core and the backup caller only, never to an AI process or a plugin. Consequences: enrollment needs a working push setup first; one more H action.

## D106. Backups to object storage, with passphrase wrappers sealed

Amends D52 and D85. Context: the off-host target had no protocol, credential model, retention or configuration command; every backup carried passphrase wrappers open to offline guessing; a passphrase change or a recovery never reached older backups; and the backup secret was chosen by the instance admin. Decision: the off-host target is S3-compatible object storage reached through the egress proxy, with credentials that can write but not delete or overwrite, or object lock, configured at the host CLI by `vilicus backup target set` (root). Retention is 7 daily and 4 weekly backups, shown to every adult as a privacy setting. Within each backup, passphrase wrappers and file names are additionally sealed to the backup public key; recovery-secret and household-key wrappers stay as on the host. The backup secret is generated by the Core (at least 128 bits) and shown once, never chosen. Completing a recovery rotates the member's DEK, and a passphrase change declared as a suspected exposure offers it. Changing the target or the backup secret raises an out-of-browser alert to every adult and follows the delay and veto of rights changes. The remote audit sink receives an HTTPS POST of a CBOR record carrying the head hash, its sequence number, and the latest backup sequence number and manifest hash. The owner approves the S3-compatible client as a new dependency. Consequences: off-host copies survive a host compromise for the retention period; a DEK rotation after every recovery; a backup secret nobody can memorise.

## D107. V0.1 events within one partition; crypto gates with done states and fallbacks

Amends D61 and D74. Context: the spine sealed events for a locked consumer into an inbox and made inbox key authentication a V0.1 gate, while the PRD puts sealed inboxes after V0.1; the V0.1 crypto gates had no done state and no fallback, and E22's fallback covered only the device key. Decision: in V0.1, events are delivered only within their source partition; cross-partition delivery and sealed inboxes ship with the home milestone, and inbox key authentication is not a V0.1 gate. The HPKE gate (D61) is done when the RFC 9180 test vectors pass, a cross-test against an independent implementation, used as a dev-dependency only, agrees on 10 000 random cases, and a written review with every finding closed or accepted is committed. If the review finds a defect, it is fixed upstream and the fix pinned; failing that, V0.1 exits with UJ-2 limited to the first member and member addition (PRD FR-8) ships in V0.1.x. E22 gets three fallbacks: the 15-minute passkey re-proof, stated to the user; pairing codes issued only by `vilicus device pair`; approvals made by a step-up bound to the request hash. Supported browsers in V0.1 are the current and previous releases of Chrome and Firefox, on desktop and Android; Safari is best effort. Consequences: the inbox code and its review start later; adults on iOS are not a supported V0.1 target.

## D108. Secrets that open the house entered at the host CLI under a signed boot policy

Amends D78 and D96. Context: with PCR 7 alone, a stock live image signed under the same Secure Boot authorities unseals the instance key; security-adapter credentials had no entry channel, and the natural default, a web form, hands them to a compromised Gateway; the radio coordinator's network key normally sits in clear in its daemon's configuration. Decision: the instance key stays sealed to PCR 7 (D96); the documents state that a live image signed under the same Secure Boot authorities can unseal it, and a pcrlock hook re-seals it before a Secure Boot database or SBAT update. Secrets that let a device open the house (security-adapter vendor credentials, the coordinator's network key, and a router admin credential if one is used for presence) never transit the Gateway: they are entered only at the host CLI as systemd credentials sealed to PCR 7 plus a signed PCR 11 policy (unified kernel images measured by `systemd-measure`), so only a host that runs unified kernel images can drive physical security devices. The coordinator daemon receives its network key by `LoadCredentialEncrypted=`, with its own write-back of the key and its own backups disabled; where a daemon cannot take its key from a credential, the documents state that the radio key sits in clear in its configuration. A read-only router account is preferred for presence. E31 tests the signed policy on Debian 13. Consequences: no path from a compromised Gateway or a live image reaches the doors; whole-host theft still reveals home metadata and occupancy (R50); security adapters require a unified kernel image setup.

## D109. Relays fail closed; playbooks trigger only on trusted principals

Amends D65 and D72; D89 is unchanged. Context: a gate, garage door or door strike wired to a relay reports as a `switch`, which is not a fail-closed class, so a display, a rule or an assistant request could pulse it open before the native app, and an "undo" sends a second pulse; a tainted session's unapproved write could also trigger a playbook whose steps run ungated. Decision: an unclassified `switch`, `plug` or relay output accepts no command from a household display, the assistant or a rule until an adult classifies it. A `momentary` capability joins the closed set of device capabilities; it is safety-relevant from discovery, never tier 1, and when it drives an opener it follows the unlock and open rows (D69). A playbook triggers only on records written by a `Member`, `Rule`, `Adapter` or `Cli` principal (I41). Consequences: one classification step per relay at discovery; playbooks cannot react to assistant writes (T66).

## D110. AI runtime isolation and an opt-in Claude subscription connector

Amends D83, and D97 in its realisation only. Context: one runtime instance per role and member can multiply resident model memory on one GPU; one runtime process could serve hostile-content roles next to the planner; a hostname allowlist cannot tell the household's provider account from an attacker's; and the connector's binary had no stated custodian. Decision: the quarantined reader and the researcher never share a runtime process with the planner or the drafter. Within each group, one runtime instance serves every role and member, with cache reuse disabled and requests serialised; per-member instances run only where E25 shows the memory fits. Multi-tenant provider hosts are a named residual risk (R53). The Claude subscription connector is its own provider-policy entry and allows no data type by default: the member opts in data types of their personal partition, and each household-partition data type needs the agreement of every adult. The plan's account identifier is shown at sign-in, recorded, and checked at every start. The binary's hash and tested version ship in the signed Vilicus release and are installed by the root CLI into a read-only path. Consequences: serialised inference adds latency under load; a vendor deprecation breaks the connector until the next Vilicus release.

## D111. Delegated run descriptors; member-owned plugins only while unlocked

Amends D62, D94 and D95. Context: a delegated run could not read its own definition, which lives in the owner's locked partition; no delegation sub-key can open a plugin's state store; and everything a delegated run writes is ingested `external` (D93, D94), contrary to the promise of usable consolidated memory. Decision: for each delegated scheduled task, the Core keeps a run descriptor in `core.db`: the fire time and staleness limit in clear, and the structured definition sealed under the delegation sub-key; schedule times are therefore visible to the instance key holder (R34). D95's "or holds a delegation sub-key" is withdrawn: a member-owned plugin runs only while its owner is unlocked. Memory consolidation runs only inside its owner's unlock window; briefings and other output of a delegated run are stored `external` and shown as such. Consequences: member-owned messaging and mail plugins stop while their owner is locked; morning briefings are labelled external.

## D112. Spoken provenance and per-item promotion of free text

Amends D41 and D45. Context: a spoken approval is limited because a voice is not attributable, yet spoken content was stored as the member's own trusted words, so played audio could plant trusted facts; batch promotion of imported memory after a sample launders any fact a past injection planted. Decision: a transcribed turn carries `spoken` provenance. It does not taint the session, but a memory fact drawn from it is stored `external` until the member confirms it in the app with one tap (I42); writes made in a voice session are listed separately in the daily digest. Batch promotion from the host CLI applies only to records whose fields are all structured; a free-text record is promoted one by one, or retyped. Consequences: a tap per remembered spoken fact; slower migration of imported memory (T65).

## D113. V0.1 values, named constants and new dependencies

Amends D36. Context: stories need concrete values the PRD left as assumptions or did not state. Decision: the unlock window starts at unlock and ends at the unlock time plus the chosen duration, whatever the web sessions do; a web session that outlives it keeps working without partition access until the member unlocks again; extending sets a new end no later than now plus the maximum and needs the passphrase. The undo journal of PRD FR-29 keeps entries 30 days in personal and household partitions and deletes expired entries under `secure_delete`; the audit log is not affected. The reference host is 4 cores, 8 GB RAM, an SSD, no GPU, Debian 13 amd64; every latency target is measured on it, and E25 also runs on the household's host, which is a reference for no other target. The web client and the notification templates exist in French and English, the CLI in English only; the recovery secret is grouped characters with a checksum (PRD FR-110). A capability token lives 10 minutes; its V0.1 budget is a number of tool calls (default 50); I11 covers in V0.1 tool calls per task, system notifications per member per hour and consecutive refusals. Confirmed values are named constants in `vilicus-types`; only the backup schedule, the certificate alert lead time and the audit spool size are operator-tunable. Documentation (PRD FR-111) and release (PRD FR-112) are V0.1 requirements. The owner approves two new dependencies: a TypeScript CBOR decoder that renders light confirmations, and a passphrase-strength library. Consequences: the window and the retention may need retuning after real use.

## D114. Audit and inbox files encrypted at rest

Amends D22 and D53. Context: `audit.db` had integrity by its HMAC chain but no stated confidentiality, and an inbox row's record type travelled in clear. Decision: `audit.db` is a SQLCipher file under a key derived from the audit key (`vilicus/v1/audit/db`), opened only by the audit writer. Each `inbox.<partition>.db` is a SQLCipher file under a key derived from the instance key (`vilicus/v1/inbox/<partition>`), and a row's `record_type` and `payload_version` travel inside the sealed payload. Consequences: the audit file format is fixed before V0.1 freezes it; whoever holds neither key reads no audit or inbox metadata from the disk (R45).

## D115. No loopback address grants; per-port network isolation

Amends D54, and D97 in its realisation only. Context: systemd IP filters match address prefixes only, so a grant of one loopback port opens every loopback listener of the host to the unit that holds it. Decision: no unit receives `IPAddressAllow=` for loopback, and the egress proxy keeps no TCP listener. A device grant is a USB device, a Unix socket path, a shared private namespace with a named managed daemon, or a private address range with ports, the ports enforced per unit by an nftables rule matching the unit's cgroup, installed by the root CLI with the grant; `IPAddressAllow=` alone never implements a grant. A managed daemon listens on a Unix socket, or on loopback inside a namespace shared only with its adapter, and requires client authentication where it supports it. The Claude subscription connector unit runs with `PrivateNetwork=yes`; a Vilicus forwarder joins its network namespace, listens on 127.0.0.1 inside it only, and forwards to the egress proxy's Unix socket (spine AD-53). Consequences: E27 and E30 add negative tests from an adapter and from the connector to every other loopback port.

## D116. E32 pass criterion: one action through the pipeline under household load

Context: E32 (Core execution model, spine AD-9) runs during V0.1, but it had no pass criterion, and `research-notes.md` section 3.1 requires one before an experiment runs. Decision: E32 passes when one action through the full pipeline (policy, write, audit) completes with a p99 latency under 100 ms on the reference host (4 cores, 8 GB RAM, an SSD, no GPU, Debian 13 amd64, D113), under a simulated load of two active adults plus the testbed (D102). If it fails, the execution model is revised before the Core process is built (Epic 5 of the V0.1 backlog), and the revision and its new measurement are recorded in this file. Consequences: the threading model of AD-9 is proven or changed before the Core is built on it; the criterion measures the action pipeline, so the home milestone's event-to-action target (PRD section 7) still needs its own measurement.

## D117. Fallbacks for the AD-36 construction and the passkey login half of E2

Amends D33, D74 and D107. Context: the key prototype that settles the AD-36 construction and the login half of E2 both gate V0.1, and neither had a documented fallback, so a failure would stop the milestone with no planned exit. Decision: if the AD-36 construction does not hold, V0.1 exits with a single member, as under the HPKE fallback of D107, and member addition (PRD FR-8) ships in V0.1.x. For the login half of E2, a browser on which passkey login or the action-bound step-up fails leaves the supported browser list of D107; if every supported browser fails, TOTP (D33) temporarily becomes the primary second factor, until a supported browser passes. Consequences: V0.1 can exit without member addition; the supported browser list can shrink; under the TOTP fallback, login loses the phishing resistance of passkeys, the TOTP enrolment surface of PRD FR-50 becomes reachable, and the step-up of D71, which a TOTP code cannot bind to an action, is settled when the fallback is taken.

## D118. Out-of-browser channel defaults to a self-hosted UnifiedPush server

Amends D47 and D105. Context: PRD open question 8 left open whether the household's push server for the out-of-browser channel is self-hosted or public, and E13 could not run without the answer. Decision: the out-of-browser channel defaults to a self-hosted UnifiedPush server of the ntfy type, which the Core reaches through a named private destination (D105). A public push server is allowed when the household chooses it. E13 is measured on both and passes when the default self-hosted server passes; a public server below the threshold is documented as not recommended. A public server sees only delivery timing metadata; the content stays encrypted. Amended by D135: the payload is one generic text and an opaque reference, not encrypted (ntfy has no end-to-end encryption), so a server's operator sees that text and the delivery timing; with a self-hosted server, iOS members need forwarding through an upstream server, which also sees delivery timing. Consequences: the default setup needs a push server on the household's network and a named private destination before the first enrollment; E13 runs on two servers.

## D119. AD-36 construction validated by the key prototype, with fixed encodings

Amends D74. Context: D74 fixed how a member public key is authenticated from `vilicus member add` until HK is wrapped to it, but left the exact encodings to a key prototype, and the construction gates V0.1 and member addition (D74, D117). Decision: the construction is validated as built in `spikes/ad36-key-prototype/` with the AD-18 primitives only, and its encodings are fixed as stated in key management section 2: HKDF-SHA-256 derivations with no salt; a token check hash under its own label, `vilicus/v1/enroll-token-check/`; the enrollment key wrapped with AES-256-GCM under a key and additional data that bind the member identifier and the HK version, a wrap from another HK version being refused as stale rather than as tampering; one canonical, length-prefixed MAC input over the member identifier and both public keys in their stored encoding; the HK wrap's HPKE `info` binding the member and the HK version (`vilicus/v1/hk/wrap/`) and its additional data binding the permanent MAC; every stored value versioned with an algorithm identifier. The spike's tests, which model the attacker as raw edits of `wrappers.db` without HK, show that a substituted member or inbox public key, an edited tag or enrollment key wrap, a permanent MAC edited after the first wrap, and a wrong or reused token are all refused, and that an honest enrollment receives HK. The AD-36 gate is passed for the construction; the internal review and cross-test of the `hpke` crate (D61, D107) are separate and still gate the code that wraps HK. Consequences: the D117 fallback for the construction is not taken; the Core's key code implements these encodings, with the spike README as the byte-level reference; HK rotation (PRD FR-9) must verify every permanent MAC under HK n and rewrite it under HK n+1 before any wrap under n+1, and refuses pending enrollments made under n as stale, not as tampering, so those members are added again; member identifiers bound into the construction are the Core's binary 16-byte UUIDv7, never a display name; `wrappers.db` is not authenticated as a whole, so a deleted record raises no alert and a rolled-back file can restore a since-vetoed or suspended member's valid record; inbox key authentication (step 6) stays with the home milestone (D107).

## D120. HPKE gate passed except its CI job: review, vectors and cross-test of the `hpke` crate

Amends D61. Context: D61 and D107 gate the household key wrap on an internal review of the `hpke` crate, the RFC 9180 test vectors and a cross-test against an independent implementation, both in CI. Decision: the gate is passed except the CI job D61 requires, which closes with the first CI story: for `hpke` 0.13.0 as built in `spikes/hpke-review/` (story 1.2), the RFC 9180 vector of the AD-18 suite passes, a cross-test against `hpke-rs` 0.8.0, a dev-dependency only, with its RustCrypto and its libcrux providers agrees on 10 000 random cases in both directions for each, and the review (`spikes/hpke-review/REVIEW.md`) closes or accepts every finding; these runs are local and in a pinned Debian 13 container, not yet in CI. The exception covers `hpke` and the primitive crates it depends on, which are Core dependencies for `cargo deny` and `cargo vet`. The Core uses HPKE only under the review's usage rules U1 to U10, among them the `zeroize` features of the primitive crates, single-shot base mode only, a value unique per seal in `info`, in-place opening of wrapped keys into locked memory, and the confirmation of every opened key against an independently authenticated value (D121 proposes the household key's). Consequences: FR-8 code may start once the owner approves the review's dispositions; any change of the `hpke` version reopens the review; the CI job of the cross-test is added with the first CI story, and its first green run completes the gate; the external review before V1 stays required (D61); the copies of secrets that the crate leaves in freed memory are stated in key management section 10.

## D121. Confirmation of the household key at its first receipt and at every unlock

Amends D119. Context: HPKE base mode authenticates no sender (RFC 9180 section 5.1.1). A disk writer who holds a member public key, which `wrappers.db` stores in clear, can seal a household key HK' of its choice to it and compute the permanent MAC under HK' as well, so the member's open succeeds and the MAC verifies (review finding F12 of D120, `tests/sender_substitution.rs`). Decision: **first receipt**: at enrollment (key management section 2, step 3), before the enrollment key is discarded, the Core derives `K_conf = HKDF(enrollment key, info = "vilicus/v1/hk/confirm-key/" || member_id)` and stores it wrapped under a key derived from the new member's DEK. At step 4, after unwrapping the enrollment key with HK, the Core writes next to the HK wrap a tag `HMAC(K_conf, "vilicus/v1/hk/confirm/" || member_id || hk_version || C(HK))`, where `C(HK)` is an HKDF commitment to HK under its own label. At the member's first unlock the Core opens the HPKE wrap, unwraps `K_conf` with the DEK and verifies the tag against `C(opened HK)` before HK is used; a mismatch is refused and alerted to every adult. **Every later unlock**: once the first receipt verifies, the Core writes a commitment to HK and its version under a key derived from the member's DEK, erases `K_conf` and the tag, and at every later unlock refuses an opened HK that does not match the commitment, with an alert. For the first member, HK is created in the enrollment ceremony and the commitment is written at once. The DEK-keyed commitment is rewritten whenever the DEK rotates, on a completed recovery (D106) or on a passphrase change declared as a suspected exposure (FR-10), in the same transaction as the new DEK wrapper. HPKE stays in single-shot base mode, so review rule U10 holds. Rejected: HPKE Auth mode, because the sender's public key would itself live in `wrappers.db`, which is circular; PSK mode, because RFC 9180 requires a PSK of at least 32 bytes of entropy and the enrollment token has 16; any anchor under the instance key, because the instance admin who holds it could then choose HK'. **Open**: an HK rotation (PRD FR-9) is a new first receipt for every remaining member, which this construction does not cover; a candidate is a signature by adults whose public keys are pinned under each member's DEK, as MLS does for GroupInfo (RFC 9420); see `research-notes.md` section 4. Consequences: a disk writer without HK cannot make a member adopt HK' at enrollment or at any later unlock; the residual case is the rotation (R55, T68); `K_conf` derives from the enrollment token, so the Gateway limit of step 7 applies to it as to the enrollment tag; one more wrapped value and one tag per pending member.

## D122. Browser device key, pairing code and light confirmation encodings

Amends D35 and D38. Context: AD-21 named the mechanisms of E22 but not their encodings, and E22 tested them on Chrome for Testing 155 and 154 and Firefox 158 and 157, headless, with certificate validation (story 1.3, `spikes/browser-device-key/`). Decision: the per-request byte string is `vilicus/v1/req`, the 16-byte session id, the counter as 8 bytes big-endian, the method and the path with its query each preceded by its length as 4 bytes big-endian, and SHA-256 of the raw body; the browser signs SHA-256 of it with ECDSA P-256 and SHA-256; the Core accepts a counter only above the last accepted one, a refused request does not advance it, and the client sends the signed requests of a session one at a time. Sessions live in the Core's memory and do not survive a Core restart; the browser then opens a new one with its device key. A device public key is registered only with a proof of possession, an ECDSA signature by that key over `vilicus/v1/device-pop`, a length-prefixed context and the key. A pairing code is `HHH-SSSS-SSSS`: a 3-digit handle that names the pending pairing and is not secret, and an 8-digit secret drawn by the issuer, which is the OPAQUE password; a paired device registers it through signed requests and finishes only an issuance it started, and `vilicus device pair` registers it on the host. The Core signs each registration response with an identity key the issuing device pinned when it was registered (at enrollment, trust on first use; when paired by code, authenticated by the OPAQUE session key), and the device refuses an unsigned or wrongly signed response. OPAQUE uses ristretto255, 3DH with SHA-512, and Argon2id at 64 MiB, 3 passes and 4 lanes on the client, with one credential identifier per pairing. Every login start gets an OPAQUE answer, the fake one for an unknown, used, expired or exhausted handle, and is charged to its source address, at most 10 per 60 seconds; a start on a live pairing spends one of its 3 attempts; each run is kept under its own login identifier; the code is used up once the Core verifies the third OPAQUE message. The new browser binds its public key with an HMAC-SHA-256 tag under a key derived by HKDF-SHA-256 from the OPAQUE session key (info `vilicus/v1/pair/bind`) over the label, the handle, the login identifier and the key, plus a proof of possession. A light confirmation signs the canonical bytes of a Core challenge naming the request, its canonical hash, the device, a single-use nonce and an expiry; the signer decodes them as canonical CBOR and signs only a `vilicus/v1/light-confirmation` approving the request the member is looking at, for its own device; the Core verifies against the bytes it issued, a nonce approves only its request, from its device, once, and a device gets no challenge for another device's request. Lifetimes are checked on a monotonic clock. Consequences: an online guess succeeds with probability 3 in 10^8 per code; the lock-out after 3 attempts is a denial-of-service lever, since anyone who reaches the API can spend a live code's attempts, bounded by the uniform answers and the per-source limit, and the member then issues another code; a relay that breaks the binding also uses up the code; a relay present at a browser's enrollment can substitute the pinned identity key; the Core never uses a signature as an identifier, because ECDSA signatures are malleable; the CSP browser test of AD-19 probes from the page's own scripts, because code evaluated through the DevTools protocol can run `eval` despite the CSP in Chrome; E22's desktop part passed and no fallback is taken there; Android is still to run, and E22 is not passed until it does.

## D123. OPAQUE libraries under a recorded exception to D28

Amends D28, in the manner of D61. Context: pairing codes use OPAQUE, an augmented PAKE, so the pairing code never reaches the Core or the Gateway (D122); balanced PAKEs are no better audited (RustCrypto PAKEs README), and CPace is still an IRTF draft. `opaque-ke` was audited by NCC Group in June 2021 at 0.5.0, with fixes in 1.2.0; 4.0 syncs with RFC 9807 with no change to the core protocol. The browser build `@serenity-kit/opaque` had a security review by 7ASecurity, published in March 2024, of a version that predates `opaque-ke` 4.x. D28 allows audited libraries only, and neither pinned version is the audited one. Decision: keep OPAQUE, with `opaque-ke` in the Core and `@serenity-kit/opaque` in the browser, under a recorded exception to D28. Before FR-16 code: `opaque-ke` is pinned at `=4.0.1`, and the `opaque-ke` version built into the WASM is recorded; the WASM is built from pinned source in CI and must match the npm artifact byte for byte, or Vilicus serves its own build; the RFC 9807 Appendix C test vectors run on both sides; a cross-test runs the WASM client against the Core's server, the fake-record path and negative cases included; the duplicate `argon2` 0.5 is removed by implementing `opaque-ke`'s key stretching function (`Ksf`) over the Core's `argon2` 0.6, so `deny.toml` needs no duplicate entry for it; an external review comes before V1. The documentation never calls these libraries audited at their pinned versions. Consequences: four CI checks and a build step before FR-16 code; if one of them fails, the D107 fallback of E22 applies to the PAKE (pairing codes issued only by `vilicus device pair`).

## D124. Step-up challenge derivation and its setting in `webauthn-rs`

Amends D71. Context: D71 binds every step-up assertion to the hash of one pending action, but `webauthn-rs` 0.5.5 chooses every challenge itself and has no API to set one (story 1.5, `spikes/passkey-stepup/`). Decision: the step-up challenge is SHA-256 of `vilicus/v1/step-up`, a session handle and the request hash (AD-13). The session handle is SHA-256 of `vilicus/v1/session-handle` and the session identifier, so the bearer secret never enters a challenge, a log or an audit record. The request carries a 128-bit identifier from the Core's CSPRNG, and the Core stores its canonical bytes and executes only those after approval. At approval the Core recomputes the challenge for the presenting session and compares it with the stored one; a request of another session reads as unknown. The pending request is single use, checked and set atomically, and the Core refuses a signature counter that does not exceed the last one it saw for the credential, because `webauthn-rs` compares it only with a copy taken when each authentication state starts. The browser's prompt timeout is a named constant, and every ceremony (registration, login, step-up) expires on the Core at that timeout plus a named slack. The Core sets the challenge in `webauthn-rs` through the state serialized under `danger-allow-state-serialisation`, in one function that refuses unless the state round-trips unchanged and differs from the original at the challenge only; the state never leaves the Core. A caller-supplied challenge is proposed upstream, and the workaround is removed when it lands. Consequences: an assertion verifies for one request in one session only; two identical actions never share a challenge; an audit check recomputes from the stored request and the session handle; a `webauthn-rs` upgrade is gated by the tests of that function; the E2 login half passed on desktop Chromium and Firefox with virtual authenticators, while Android, Safari and real authenticators are still to run, and no D117 fallback is taken.

## D125. Peer identity by cgroup membership and pidfd; default template profile

Amends D18. Context: D18 names `SO_PEERCRED` for plugin sockets, and spine AD-24 named the unit read from the cgroup of the peer's pidfd; E10 (story 1.6, `spikes/sandbox-profile/`) showed, first in a container on kernel 6.18 and then on a Debian 13 VM (kernel 6.12, systemd 257 as PID 1, AppArmor active), that the Core cannot read `/proc/<pid>/cgroup` under its own `ProtectProc=invisible`, that Debian 13's kernel cannot give a pidfd's cgroup and refuses a late pidfd for a reaped peer (`EINVAL`), that a connection can outlive the process the Core verified, and that the profile of `architecture.md` section 4 alone leaves the system bus, the journal stream socket, host abstract sockets and user namespaces reachable. Decision: on every accepted peer connection the Core takes the peer's pidfd (`SO_PEERPIDFD`) and pid at accept, checks that the pid is listed in `cgroup.procs` of the cgroup systemd reports for the unit the socket belongs to (its `ControlGroup` property, pinned once the unit is active), and then checks that the pidfd's process has not exited; it never compares the last component of a cgroup path alone. Every other Vilicus process that admits a peer by its unit, the audit writer for the Core and the egress proxy for its callers, applies the same method. A failed `SO_PEERPIDFD`, whatever the errno, refuses the connection, with no fallback to the pid alone, and the Core refuses to start on a kernel older than 6.5, which lacks `SO_PEERPIDFD`. The Core watches the pidfd for the life of the connection and closes the connection, revoking what is bound to it, when the process exits. Each peer's socket sits in its own directory under a Core directory of mode 0700, and only that unit bind-mounts it. Plugin and AI process templates use the default template profile, whose reference is the fixed profile block of `spikes/sandbox-profile/units/vilicus-plugin@.service` until the shipped template replaces it, plus `NoExecPaths=/` and `ExecPaths=/usr` (story 5.4 tests that the plugin still loads its libraries); units that cannot take it get their own tested profile. The explicit deny of `io_uring_setup`, `io_uring_enter` and `io_uring_register` applies to every Vilicus unit, the Core included, because `@system-service` includes them through `@aio`; the kernel's `io_uring_disabled` sysctl is a host-wide alternative, not required. No Vilicus unit sets `Delegate=`. The Core does not set `PrivateUsers=yes`. The IP filter startup check runs as root before the Core, outside any IP filter, with a loopback UDP control datagram that must arrive and a probe datagram from a transient unit under `IPAddressDeny=any` that must fail with `EPERM`. Later options, not adopted now: `PIDFD_GET_INFO` with the cgroup id (kernel 6.13 or later) and systemd's `GetUnitByPIDFD` over D-Bus. Consequences: the Core must know the unit of each socket, which the one-socket-per-peer rule already gives, and reads each unit's cgroup from systemd once; a peer process in a sub-cgroup of its own unit is refused; a descriptor passed to another process stops working when the verified process exits; the E10 fallback is not needed; stories 5.3 and 5.4 apply the method and the profile.

## D126. Extension loading off on every connection; authorizer setup order

Amends D21. Context: the bundled SQLCipher build enables the extension loading C API on every connection, and the SQLite authorizer cannot see that C call; SQLCipher pragmas go through the authorizer; `VACUUM` and `VACUUM INTO` attach a database internally (E11, story 1.7, `spikes/sqlite-authorizer/`). Decision: every connection the Core opens turns off `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` before use, and the build compiles extension loading out where the toolchain allows; the Core keys each connection and runs its setup pragmas before installing the authorizer; after that, no pragma outside a read-only introspection allowlist runs, SQL functions are allowlisted (so `load_extension` and `sqlcipher_export` are refused), and writes to SQLite's internal tables are refused outside migrations. A migration connection refuses every statement outside the runner, and the runner owns the transaction. Copies of a file are made by a Core maintenance path outside any authorizer connection, as a file copy or with SQLite's online backup API, never with `VACUUM INTO` or `ATTACH`. A function denied by the authorizer fails with `SQLITE_ERROR`, not `SQLITE_AUTH`, and the storage layer classifies it as a refusal. Consequences: one FFI call in the storage layer until extension loading is compiled out; the E11 fallback (a statement parser) is not needed.

## D127. FTS5 virtual tables allowed in module migrations, under `SQLITE_DBCONFIG_DEFENSIVE`

Amends D21 and D126. Context: the E11 migration policy refuses `CREATE VIRTUAL TABLE`, while D23 puts full-text search on encrypted SQLite, so no module could create its FTS5 index (story 1.7); FTS5 keeps its index in shadow tables that ordinary SQL could otherwise write. Decision: `CREATE VIRTUAL TABLE` and `DROP VIRTUAL TABLE` are allowed only under the migration policy and only when the module name is `fts5`, compared case-insensitively; `fts5vocab`, `fts3`, `fts4`, `rtree` and every other module are refused. Every connection enables `SQLITE_DBCONFIG_DEFENSIVE` in D126's setup order, before the authorizer, and reads it back; under it, shadow tables are read-only to ordinary SQL. Each FTS5 table's migration sets its `secure-delete` option to 1 (D132). The module registry checks FTS5 table arguments against an allowlist: the built-in tokenizers `unicode61`, `ascii`, `porter` and `trigram`, and `content=` empty or naming a table of the same module. The `fts5()` SQL function stays denied. Consequences: shadow tables are read-only to module SQL; FTS5 content is encrypted at rest by SQLCipher like any table; the E11 suite is rerun with `SQLITE_DBCONFIG_DEFENSIVE` on, and E15 tests that direct DML on each shadow table is refused and that `integrity-check` passes after a migration.

## D128. Argon2id parameters and unlock concurrency

Amends D113. Context: FR-11 needs Argon2id parameters above the published floor that unlock under 2 seconds on the reference host (D113), under a global concurrency limit; E12 measured them on an emulation of the reference host and on a Debian 13 VM, not on the reference host (story 1.8, `spikes/argon2id-params/`). Decision: a cost meets the floor when it is at least one RFC 9106 section 4 option in both memory and passes, and a header is refused above the ceiling of m 1 GiB, m times t 4 GiB, p 8, before it is queued. Version 1 passphrase wrappers use Argon2id version 0x13, t = 3, p = 4, m = 384 MiB (provisional, below), a 16-byte random salt and a 32-byte KEK, over the passphrase normalised to NFC and encoded as UTF-8, as named constants in `vilicus-types`. The RustCrypto `argon2` crate `=0.6.0` is used without its `parallel` feature (D129): the four lanes run in order on one blocking-pool thread, under the key-operation guard of D131; lanes enter the hash and threads do not, so turning `parallel` on later rewrites no wrapper. Every Argon2id derivation of the Core (passphrase, backup secret, admin recovery code) goes through one limiter: at most two derivations at once, through a FIFO tokio `Semaphore` acquired before the blocking-pool permit, so no async worker thread blocks; a request that cannot start within 4 seconds is refused as retryable, and the time it waited is never returned to the client; one request in flight per member; after a failed passphrase the member's next attempt is delayed with an exponential backoff. The Argon2id working memory, a buffer the Core owns and wipes after each derivation, never exceeds the limit times m, at most 1 GiB, and the Core unit's `MemoryMax=` covers the limit times m plus its baseline. The reference-host run of E12 picks m from {256, 384, 512} MiB with this serial, limit-2 model, under the limit times m at most 1 GiB, and its result replaces the provisional value. Consequences: two simultaneous unlocks run side by side and a third waits; the emulated numbers of story 1.8 came from a two-thread pool under a limit of one, so the reference-host run measures this model; a wrapper rewritten after a cost change costs two derivations at its next unlock; turning `parallel` on is its own decision, with E12 and E32 rerun; PRD FR-11 states the limiter (DC-80).

## D129. Exception to D28 for the `argon2` crate, without its `parallel` feature

Amends D28, in the manner of D61. Context: AD-18 takes primitives from audited libraries only, and the spine pins the RustCrypto `argon2` crate, for which no published third-party audit is known; its `parallel` feature would pull `rayon` into the Core, and its history counts: 0.5.0 removed a `parallel` feature found unsound, and 0.6.0 restored it (crate CHANGELOG). Decision: an exception to D28 covering `argon2` and the `blake2` crate it depends on, with the `parallel` feature off, so `rayon` does not enter the Core. Before the passphrase-wrapping code: an internal security review of both crates and of Vilicus's use of them, assisted by the most capable model available, with every finding closed or accepted and the review committed. In CI: the RFC 9106 Argon2id vectors, the reference implementation's Argon2id vectors without secret or associated data, a cross-test against the reference implementation (phc-winner-argon2), a dev-dependency only, that agrees on 10 000 random cases over p in {1, 2, 4, 8}, and OpenSSL 3.5's `EVP_KDF-ARGON2` as a second oracle. An external review before V1. A defect is fixed upstream and the fix pinned. The documentation never calls the crate audited. Consequences: the passphrase path rests on vectors, a cross-test, two oracles and reviews, like HPKE under D61; turning `parallel` on later is its own decision, with E12 and E32 rerun (D128).

## D130. Canonical CBOR profile and libraries

Amends D19 and D113. Context: AD-13 left the CBOR crate, the TypeScript decoder and the listed tags open, and E19 tested the canonical encoding across Rust and TypeScript (story 1.9, `spikes/canonical-cbor/`). Decision: the canonical form is dCBOR restricted by this profile. The Core encodes and decodes it with `dcbor` and the web client decodes it with `cbor2`, each behind a profile layer. On decode, the layer first walks the item heads without recursion and refuses more than 32 nested arrays, maps or tags, any tag outside the listed set, any float and any byte after the first item, then decodes with the library's deterministic checks, then refuses integers below -2^63, and finally refuses an input whose re-encoding differs from it. On encode, it refuses non-NFC text instead of normalizing it, and map construction refuses a key equal to an earlier one once canonicalized. The listed tag set is empty. Integers are within [-2^63, 2^64 - 1]; simple values are false, true and null. Text is in NFC under the Unicode version of the Core's normalization tables, which are pinned exactly. A change of that Unicode version is a change of the canonical format: it needs its own decision record, a new protocol version (AD-12) and regenerated vectors stating the new `unicode_version`; a stored hash is only ever checked against the stored canonical bytes it was computed from, never against a re-encoding of the stored value; requests pending at the change are expired, not re-hashed; and records hashed before the change keep their bytes. A signer on older tables than the Core accepts its bytes; a signer on newer tables may refuse text holding code points new to the Core's version, which fails closed; neither hashes other bytes than it received. The shared vectors of `crates/vilicus-proto/tests/data/canonical-cbor/`, generated by `crates/vilicus-proto/examples/gen_vectors.rs`, state the profile constants and the Unicode version, and every decoder replays them; `spikes/canonical-cbor/vectors/` keeps a byte-equal copy, checked by a `vilicus-proto` test, for the TypeScript replay until Story 10.6. Consequences: `dcbor` 0.25.2 accepts integral floats that dCBOR forbids, decodes without a nesting bound and collapses keys equal once normalized, so its profile layer is required, not optional; `dcbor` brings `chrono` and the unmaintained `paste` (RUSTSEC-2024-0436) into the Core's tree, listed as an advisory exception in `deny.toml`; closed types are mapped by hand in `vilicus-proto`; a light confirmation holding text with code points new in the Core's Unicode version may fail to render on a browser with newer tables; the Kotlin part of E19 runs before the native app milestone.

## D131. Key memory rules from E16

Context: FR-13 and key management section 10 rely on locked memory and zeroization, and E16 measured them in the Rust runtime, in Debian 13 containers on the Docker Desktop kernel (story 1.10, `spikes/locked-memory/`); this record makes spine AD-4 concrete. Decision: the Core runs under its own static user, which runs nothing else; its first action, before reading the instance key, is `PR_SET_DUMPABLE` 0 and `RLIMIT_CORE` 0; the unit also carries `LimitCORE=0`, and the Core never calls `execve` or changes credentials afterwards. It allocates one key pool, refuses a second one, frames it with `PROT_NONE` guard pages, locks it with `mlock` and advises it `MADV_DONTDUMP` and `MADV_WIPEONFORK`; the pool is sized by the planned slot count (per unlocked adult the DEK, the household key, the member private key, the open file keys and transient slots, plus the instance-level keys), cut into slots wiped on drop. If the lock is refused, the Core refuses to start with an error naming `LimitMEMLOCK` and never falls back to unlocked memory; the unit sets `LimitMEMLOCK` to the pool size with a margin, without `CAP_IPC_LOCK`. Every key operation runs in a non-inlined function under a guard that scrubs the stack below the caller and zeroes the AVX registers, on success and on error, on the thread that ran it; `vilicus-crypto` exposes slots only through a closure API that applies the guard. AEAD and HKDF objects are built from a slot for one operation and dropped; key bytes are never held in heap memory the Core does not wipe or lock. Argon2id runs on memory the Core owns and wipes. Release builds keep `panic = "unwind"` (AD-9); a module handler runs inside a boundary that marks the thread, and the panic hook wipes the pool and aborts only for a panic outside such a boundary. SIGTERM is taken on a `signalfd` thread that wipes the pool before shutdown. Consequences: no key material was found after drop in the tested paths; at E12 sizes the Argon2id memory is wiped but not locked, so swap must be disabled or encrypted; abort paths without user code (allocation failure, stack overflow, panic during unwinding, fatal signals) leave keys in memory until the process ends, without a dump; an opener of the Core's memory from before hardening keeps access; registers beyond ymm15, kernel buffers, freed physical pages, hibernation images and SQLCipher's internal key handling are outside the claim; FR-13's run on the reference host is still to do.

## D132. Deletion is `secure_delete` ON plus a TRUNCATE checkpoint

Amends D2 and D113. Context: D2 and D113 rely on `secure_delete` for deletions that must be real, and E17 tested it on SQLCipher files in WAL mode (story 1.11, `spikes/secure-delete-wal/`). Decision: every connection the Core opens sets `PRAGMA secure_delete = ON` (never FAST) and `journal_size_limit`, and reads them back, before its authorizer is installed; the journal retention purge and the destruction of wrapped record keys are each followed by a TRUNCATE checkpoint through `sqlite3_wal_checkpoint_v2`, which the connection authorizer does not see, retried until the WAL is empty; wrapped record keys are never journaled, or shredding also deletes the journal rows that hold the key (the journal story chooses; never journaling is recommended); temporary storage stays in memory (`SQLITE_TEMP_STORE=2`, `temp_store` not in the authorizer allowlist); VACUUM, which the authorizer refuses, is the fallback for content deleted while `secure_delete` was off and runs only on a dedicated Core maintenance connection. Consequences: deleted rows leave the live files at the checkpoint, not at the delete; copies in existing backups and migration cold copies keep them until those expire, which is the backup caveat; filesystem and SSD remanence of freed blocks holds only ciphertext under the file key and is not covered by the claim.

## D133. Egress proxy budgets in tunnels, ranged private destinations, allowlist before lookup

Amends D105. Context: E14 (story 1.12, `spikes/egress-filter/`) found that the egress proxy sees tunnels, not requests, so per-host request budgets cannot be counted inside a CONNECT tunnel; that a named private destination given by host and port alone lets a rebinding name redirect the Core's exception to another private host; and that the refused address set of spine AD-16 left out special-purpose ranges. Decision: per-host budgets count tunnels per sliding window, per hostname, shared by every caller; every host has a budget, its own or a default one; part of each is reserved for the Core and the backup caller; the budget is taken after the address check. Inside a tunnel, a plugin's request rate is not bounded by the proxy, only by the tunnel lifetime and idle timeout; the trusted fetcher and the Core egress mode open one tunnel per request, so their budgets count requests. A named private destination records a host, a port and the private range (RFC 1918 or unique local) that its resolved addresses must fall in, checked at connect time. The allowlist decision is taken on the canonical hostname before any lookup, and one refused address refuses the whole name; the proxy resolves absolute names through its configured DNS servers only. IPv6 is accepted only inside global unicast, and every IANA special-purpose range that is not globally reachable is refused, 6to4 and NAT64 forms judged on the embedded IPv4 address. Consequences: a plugin that reuses one tunnel for many requests counts once per tunnel; naming a private destination asks for its range; PRD FR-105 states budgets in tunnels (DC-76); a unit under `IPAddressDeny=any` has its packets dropped rather than rejected, so a direct connect times out; domain fronting is handled by D134.

## D134. Domain fronting: SNI check, IP-range fallback not adopted, Host-header fronting a named risk

Amends D105. Context: E14 found one bypass of the hostname allowlist: on a shared front end (a CDN or a multi-tenant provider), an allowlisted hostname carries requests to another tenant named in the TLS SNI or in the HTTP Host header (story 1.12). The E14 fallback, per-plugin IP ranges, does not close it, because the tenants of a front end share its addresses. Large front ends now refuse a Host that differs from SNI (CloudFront, Azure Front Door, Cloudflare with a 421), but not all (at the time of writing Fastly, and Akamai in part; arXiv 2310.17851). Decision: the fallback is not adopted. The proxy checks the first TLS ClientHello of each tunnel of a caller that reaches a shared front end: its SNI must equal the CONNECT host, and Encrypted Client Hello (RFC 9849) is refused; plugin HTTP clients must not enable ECH. An allowlist entry on a front end that does not refuse a Host differing from SNI needs a stated reason in the allowlist review. Checking the server certificate is impossible in TLS 1.3 without interception, since the certificate is encrypted, and is not adopted; IP pinning does not help on shared front ends. Fronting by the HTTP Host header stays a named risk (R54, T67), since closing it needs TLS interception (as with Squid's peek and splice), which the design excludes. Consequences: a client that cannot send SNI cannot use a checked caller's tunnels; allowlist entries prefer hostnames on dedicated infrastructure.

## D135. No acknowledgement token in the push payload; push server reachable off the household network

Amends D75 and D118. Context: the E13 tooling (story 1.13, `spikes/push-delivery/`) showed that an ntfy-type server stores and serves the alert body, and ntfy has no end-to-end encryption (ntfy issue 69), so a one-time acknowledgement token sent in the push payload is readable by the server's operator; the design said how the Core reaches a self-hosted push server but not how a member's phone reaches it away from the household network. Decision: the push payload carries no one-time token on any server: it is the generic text plus an opaque reference that redeems nothing, and the token is shown and redeemed when the member opens the alert in a signed-in Vilicus client on a device they control. Payload encryption (RFC 8291) comes only once a Vilicus app is the UnifiedPush receiver. The push server keeps alerts long enough for an offline phone (ntfy `cache-duration` not 0). By default a phone reaches a self-hosted push server off the household network through D60's WireGuard tunnel, routed to the push server only beside the instance; the alternative is a published endpoint with `auth-default-access` set to `deny-all` and a read-only token per phone. E13 measures both on mobile data, battery use and NAT keepalive included. Consequences: acknowledging an alert needs a signed-in Vilicus client; D60's endpoint ships with the home milestone (PRD FR-86), so in V0.1 the published endpoint is the available path; on Android the tunnel uses the single VPN slot D60 already takes; how the enrollment test notification of D105 proves receipt without a token in the payload is open (`research-notes.md` section 4); with a self-hosted server, iOS members need forwarding through an upstream server (ntfy `upstream-base-url`), which sees delivery timing; D118's wording is amended accordingly; PRD FR-56 states both rules (DC-81).

## D136. E32 result in emulation and execution model parameters

Context: D116's criterion, p99 under 100 ms for one action through the full pipeline under household load, was met in emulation by story 1.15 (`spikes/core-execution/`, Docker `--cpus=4 --memory=8g` on a larger desktop, storage shared with other workloads): member probe p99 28.01 ms, token probe p99 34.72 ms, with two unlocks, a backup, journal retention and a long reader running throughout. Decision: blocking pool permits are the host's cores minus one (3 on the reference host), valid only with Argon2id lanes computed on the pool thread, so one derivation holds one core; Argon2id holds at most two of these permits (D128). Backup pauses are per file, one file at a time, each writer paused only while its own file is checkpointed and copied, and only for files of at most 32 MiB (measured copy 32.3 ms plus 0.80 ms per MiB, checkpoint up to 2.01 ms per MiB of WAL), with SQLite's online backup API in bounded steps above that size; a pause's checkpoint uses a short busy timeout and is retried, so no writer waits on a reader; the audit acknowledgement counts in every action's latency; writer connections use `synchronous = FULL`, read back at open. Story 5.1 reuses these values. Consequences: the reference-host E32 run uses E12's final m and confirms or reopens these values; the tail on idle files (88 ms maximum in emulation) is not explained by backups and is to be watched in that run; the D116 fallbacks (rule thread priority, a lower pool concurrency, throttled backup copies) stay available as parameters of the spike.

## D137. Overlay network addresses: private only on a named overlay interface

Context: the private-network naming option of FR-65 usually gives addresses in 100.64.0.0/10, which is not in FR-6's list of private interfaces, so the bootstrap wizard refuses a peer on the overlay (FR-4) and listening on the overlay address needs `--acknowledge-public-exposure` (FR-6) (E24, story 1.4). That range is shared address space for carrier-grade NAT (RFC 6598): the IANA special-purpose registry marks it not globally reachable, and Python's `ipaddress` treats it as neither private nor global, so other customers of the same provider may reach a host that holds such an address. Decision: 100.64.0.0/10 is never private by default. The operator may name one overlay interface at the host CLI with `vilicus instance listen`; an address of that interface in 100.64.0.0/10 is then private for FR-6 and FR-4, the Gateway's socket for it is bound to that interface (systemd `BindToDevice=`), and a peer on that address is accepted only on that socket. The overlay's IPv6 unique local addresses (for example fd7a:115c:a1e0::/48) are already private under FR-6. D60's WireGuard endpoint remains the recommended remote access. Consequences: FR-4 and FR-6 state the named overlay interface (DC-78); a host behind carrier-grade NAT never treats its own address as private; naming the interface is a host-only, audited and alerted change like any exposure change; on Android the overlay client and D60's tunnel still compete for the single VPN slot.

## D138. Temporary certificate names IP addresses only; relying party checks the instance name

Amends D76. Context: E24 (story 1.4, desktop Chrome and Firefox, virtual authenticators) found that every browser refuses WebAuthn on an IP origin, that a credential made over a temporary certificate is unusable on the instance name only when the temporary name differs from it, that Chrome keeps refusing WebAuthn on a host for the rest of the browser session once a person passed its certificate warning there, and that on `localhost` both browsers run the ceremony; Chrome allows WebAuthn over certificate errors on `localhost` by design (Chromium change "Skip TLS check in localhost"), and browser checks have had flaws (CVE-2025-6433, Firefox before 140). Decision: the wizard's temporary certificate carries IP SANs only. The Core's WebAuthn relying party accepts only the instance name as RP ID and `https://<instance name>` as origin (WebAuthn Level 3), so a credential or an assertion made on `localhost` or an IP address is refused server side, whatever the browser did. No ceremony route is served before the instance name and its real certificate exist (D76). The temporary certificate and its listener are destroyed once the real certificate is installed. The bootstrap token (D32) and the printed fingerprint gate the wizard. Consequences: the guarantee no longer rests on browser behaviour; PRD FR-4 states it (DC-79); the negative test of spine AD-33 also asserts the server-side refusal of a `localhost` origin.

## D139. External content sanitized with `ammonia`, then rendered on the port-based separate origin

Amends D26. Context: E26 (story 1.14, `spikes/separate-origin/`) showed that the sandboxed separate origin by port isolates external content on desktop Chromium and Firefox with every FR-65 naming option, directly and behind Caddy and nginx, but that Firefox 157 and 158 resolve the host of a `<link rel=preconnect>` in that content despite a CSP that forbids every fetch, which tells the sender that the content was opened; that the client's `frame-src` keeps the iframe from navigating anywhere; and that CSP reports miss some blocked attempts. Decision: keep the port-based origin (the E26 fallback is not taken). Before serving external HTML, the Gateway sanitizes it with `ammonia`, a new dependency of the Gateway approved by the owner on 2026-10-17 (pinned exactly, 4.2.4 when E26 ran; MIT OR Apache-2.0; reviewed under D28 like any dependency), with an allowlist: inert presentational elements only (text structure, lists, tables, inline emphasis, `a`), the attributes `lang`, `dir`, `colspan`, `rowspan` and `scope` only, no URL scheme, so no `href` on `a`, no `xlink:href`, `src`, `srcset`, `poster`, `background`, `style` or event-handler attribute; `script`, `style`, `template` and `noscript` dropped with their content; `link`, `meta`, `base`, forms, frames, `object`, `embed`, media, images and SVG dropped; comments stripped. The sanitized fragment is placed in the Gateway's own document shell; the sandbox and the content CSP remain the enforcement layers. The client's `frame-src` lists the content origin only, and the client shows the links of external content outside the iframe with their full destination. The content origin is the instance name on port 8443; the externally visible ports are exactly 443 and 8443 on every access path. The content origin never emits `Set-Cookie` and never relays an upstream response header. The production content CSP carries no `report-uri`; if one is added later, its endpoint is rate limited and truncates reports. Consequences: mail bodies render without images, styles or in-place links; a reverse proxy must expose 8443 and forward the Host header with its port; the Gateway's plain listeners behind a proxy bind to loopback or accept only the configured proxy; Android and Safari are still to run, so E26 is not passed until Android does.

## D140. Crate graph read by reachability; `unsafe` confined to four named crates

Amends AD-3 and the spine's unsafe-code convention. Context: building the workspace (story 2.1) raised two readings. AD-3 says dependencies follow the graph "and nothing else", which, read literally, forbids `vilicus-core` from naming `vilicus-types` directly although it already reaches it through `vilicus-proto`, and would force re-exports everywhere. The spine confines `unsafe` in the Core to `vilicus-crypto` memory locking, but accepted records need system or SQLite calls that no approved dependency wraps safely: the extension-loading switch of D126 and the TRUNCATE checkpoint of D136 (`sqlite3_db_config`, `sqlite3_wal_checkpoint_v2`) in `vilicus-storage`, the pidfd peer identity of D125 (`SO_PEERPIDFD`, pidfd polling) and the process hardening of D131 in `vilicus-core`, and taking the socket-activated listener in `vilicus-gateway`. Moving these calls into `vilicus-crypto` would make the key crate the home of unrelated code. Decision: a direct dependency is allowed when the AD-3 graph already reaches the target transitively, except that `vilicus-crypto` and `vilicus-storage` accept `vilicus-core` only and crates under `testing/` stay dev-only; reachability lets no crate link code it could not already link. `unsafe` is allowed only in `vilicus-crypto`, `vilicus-storage`, `vilicus-core` and `vilicus-gateway`. In each, `unsafe_code` is denied at crate level, every block is allowed locally, kept in one module of FFI wrappers that expose safe functions, and carries a `// SAFETY:` comment enforced by clippy's `undocumented_unsafe_blocks`. Every other crate, modules, adapters, plugins, AI processes, `vilicus-types` and `vilicus-proto` included, forbids `unsafe_code`. The CI check of story 2.1 holds the list, and adding a crate to it needs a decision record. Consequences: the memory-safety surface sits in four crates whose FFI modules are reviewed per block; the Gateway, which faces the network, keeps its `unsafe` to the listener handover; a dependency that wraps one of these calls safely may replace a block, under the dependency approval rule.

## D141. The testbed starts the test doubles instead of linking them

Amends D102 and AD-3. Context: D102 and AD-3 say the never-packaged `vilicus-testbed` binary links the reference module and the test doubles, while PRD FR-109 makes each double a separate executable; Cargo links no package that builds only a binary, so the two readings cannot both hold (story 2.6). Decision: `vilicus-testbed` links `vilicus-mod-reference` as a library and starts the test doubles (plugin, AI process, channel, model connector) as separate processes; the doubles ship beside it in the testbed artefact, never in a release artefact, and the packaging check of story 2.6 refuses them there. A double that later needs a workspace crate (`vilicus-plugin-sdk`, `vilicus-ai`) gets that edge in AD-3 when its story needs it. Consequences: gates that need a double exercise the real process boundary, socket and peer identity included, as FR-109 intends; the testbed artefact is a directory of executables, not one binary.

## D142. A fuzz crate outside the crate graph, on a dated nightly in its own job

Amends AD-3 and AD-33. Context: the decoders of `vilicus-proto` will read frames from sockets whose peers are untrusted (plugins, AI processes, channels, the Gateway), and story 2.5 tested them on a fixed vector set only; its review found a memory amplification by reasoning, not by test. Coverage-guided fuzzing needs `libfuzzer-sys` (which bundles LLVM's libFuzzer, under the NCSA licence) and a nightly toolchain for its sanitizer flags, while AD-3 says dependencies follow the graph and nothing else and the workspace builds on a pinned stable toolchain. Decision: `vilicus-fuzz` (`fuzz/`) is a workspace member outside the AD-3 graph. It depends on `vilicus-proto`; the CI check of story 2.1 refuses any dependency on it, of any kind, and refuses `libfuzzer-sys` and `arbitrary` in any other crate. `libfuzzer-sys` sits behind a feature that only the fuzz job enables, so the stable jobs never compile libFuzzer, and its NCSA licence is allowed for that crate alone. The fuzz job runs every target on a nightly pinned by date, used by that job only, under memory limits derived from the frame maximum and the item bound of each socket kind; a short budget runs on every change and a longer one weekly. Every input a run finds failing is committed to a regression set that `build-and-test` replays on stable. A new public decoder of `vilicus-proto` without a target fails CI. Consequences: one nightly toolchain and a C++ build exist in CI, confined to one job; a defect in a decoder can be found by a machine before a socket exposes it; the fuzz crate's dependencies pass the same supply-chain gates as every other crate.

## D143. SQLCipher 4.19.0, self-built from a vendored amalgamation

Resolves the spine's Deferred item "SQLCipher version" and amends D140 and AD-5. Context: `rusqlite` 0.40.2 bundles SQLCipher 4.14.0, and no `rusqlite` release bundles a later one. SQLCipher 4.15.0 fixed CVE-2026-51936 (CVSS 4.0 2.1), a defensive-mode bypass through the source name passed to `sqlcipher_export`; 4.19.0 is the latest 4.x (2026-09-08). The connection authorizer already refuses `sqlcipher_export` (D126), so Vilicus was not exposed, but the owner chose not to let one layer carry the defence alone (story 3.1). Decision: V0.1 compiles the SQLCipher 4.19.0 community amalgamation, generated from tag `v4.19.0` (commit `c4b275a47932888216bade83aff2bbc73df0ff85`) and vendored under `crates/vilicus-storage/sqlcipher/` with its licences and SHA-256 sums. The build script of `vilicus-storage` compiles it with the defines of `libsqlite3-sys`'s `bundled-sqlcipher` build except that extension loading is compiled out (D126), `SQLITE_USE_URI` is dropped, and the stack protector, stack clash protection and `_FORTIFY_SOURCE` are added; it keeps `SQLITE_TEMP_STORE=2` (D132) and links against the system OpenSSL; `rusqlite` uses its `sqlcipher` link feature. A CI job regenerates the amalgamation from the pinned tag of the official repository and refuses any byte that differs, on every change to the vendored directory and weekly; a second check refuses a file that differs from its sum. Moving to another release is a new decision record, a regeneration and a reading of its changelog. Consequences: every build compiles a C source that `cargo vet` and `cargo deny` do not see, held by the hash check instead; the binary package reproduces SQLCipher's BSD-3-Clause notice (story 5.7); extension loading is absent from the library, not only switched off. Amends D140: `vilicus-storage` also keys each file through `sqlite3_key_v2`, from a buffer zeroized on drop, as a third FFI call beside `sqlite3_db_config` and `sqlite3_wal_checkpoint_v2`, so no `PRAGMA key` text holds the key. Module SQL cannot reach `_meta`, migrations included; the Core writes it under a policy of its own, and an epoch change goes through a pending sidecar `<file>.epoch.next` that blocks every open until the Core resolves it (AD-5).

## D144. A module file is registered only if its stored schema is exactly the one its declaration implies

Amends AD-6, AD-9, AD-26, D126 and D127. Context: story 3.2 builds the module registry. Its review showed that comparing column types alone lets migration SQL write or delete rows outside the typed API: a foreign key with `ON DELETE CASCADE`, a primary key or `UNIQUE` with `ON CONFLICT REPLACE` (which replaced a `user` row by a `plugin` row), a `DEFAULT` that turned a NULL taint into `clean`, a `COLLATE NOCASE` on `taint`; and that SQLite flags a table as an FTS5 shadow by its name alone. Decision: each module declares its tables as `const` data in `vilicus-module-api`, whose rules are `const fn`s a module checks in its own build and the registry checks again; the binary's registry is a `const` item. Every module table carries the envelope columns, in this order and with no other clause: `id BLOB NOT NULL PRIMARY KEY`; `source`, `taint` and `data_types` `TEXT NOT NULL`; `author BLOB`, which may be NULL; `created_at`, `updated_at` and `rev` `INTEGER NOT NULL`. No field takes an envelope name or a rowid name (`rowid`, `oid`, `_rowid_`). The registry compares a file only at the module's latest schema version (otherwise the file is `migrating` or `newer than code`, AD-54), and compares each table's stored `CREATE TABLE` statement token by token, under SQLite's lexical rules, with the one statement the declaration implies: the envelope, then the fields in declared order, `NOT NULL` unless optional, no other clause, and `STRICT` as the only table option. It refuses foreign keys, triggers, views and undeclared tables or columns, and allows only the primary key's index and plain `CREATE INDEX` indexes over declared columns (not `UNIQUE`, not partial, no expression, BINARY collation). Declarations model no defaults, so a field added by a later migration is optional and declared last. An FTS5 table takes `content=''` or `content=` a declared table of the same module, a bare built-in `tokenize`, no other option, and no column named `rank`, `rowid` or the table's own name; its shadow tables are exactly `_data`, `_idx`, `_docsize` and `_config`, each with FTS5's own statement. `_meta` holds `core_schema_version` and `module_schema_version` (no row means 0), written only by the migration runner, under the Core policy, in the migration's own `BEGIN IMMEDIATE` transaction, one version after the other; an unversioned runner exists in tests only. `table_list`, `index_list`, `index_xinfo` and `foreign_key_list` are in the introspection pragma allowlist; none returns a file path. Consequences: a module's schema can carry no behaviour the Core did not declare, so every row change goes through the typed API, the envelope and the journal; adding a required field costs a table rebuild; story 3.7 must still prove FTS5 creation through a real migration, where FTS5 runs `PRAGMA data_version`, which the migration policy refuses today.

## D145. Tool declarations and the capability matrix check

Amends AD-9 and AD-48. Context: story 3.3 builds the tool declarations and the capability matrix check; its review found that a tool could omit its exception class, which the matrix held only in its Notes, and that "network effect" was read as any traffic leaving the instance, which would have forced reads to be mislabelled. Decision: a tool declares, as `const` data in `vilicus-module-api`, its name, its schema (arguments under the field rules of FR-58), its tier, a mandatory `network_effect`, at most one exception class, its confirmation (none or light), whether it crosses partitions, the name of its undo handler and its matrix row, named by section number and Action text; a module claims the matrix sections it implements, one section belongs to one module, and no module claims section 1, the Core's. A network effect is a change of state outside the instance's own files, in a third-party system, an account or a device; a read that only fetches is not one, its egress being the egress proxy's and the sandbox's (I4). The build refuses a tier H tool, a tier 2 tool and a tool crossing partitions before the native app, a network effect below tier 2 without an exception class, an exception class outside tier 1, without a network effect or without an undo handler, and a `reversible_external_state` or `own_account_delivery` tool without light confirmation; light confirmation is tier 1 only. `doc/capability-matrix.md` carries an Exception class column: `none`, a member of the closed set (tier 1 only, the two classes above with light confirmation), or `unsettled` for a row whose class the design has not settled. The capability matrix check is a Rust test over the registry's tool table and the matrix, read fail-closed: it fails on a tool without its row, on a tool naming a row of tier H, `n/a`, tier 2, no single tier or an unsettled class, on a tier, confirmation, class or network effect different from the row's, on a claimed section with no table of actions, and on a row of a claimed section at tier 0 or 1 without a tool, of no single tier or of an unsettled class. Consequences: a matrix section shared by several modules (10c), a row of mixed tier and an unsettled row are settled before their module ships; tier 1 device commands without a class (apply a scene, a safe-direction command, a mode change on no safety-relevant device) cannot register until the home milestone settles them between D56, AD-39 and I13, which as written makes them tier 2.

## D146. Field validation on write, reviewed-vocabulary labels and the envelope's stored form

Amends AD-6, AD-9, AD-26, D98 and D104. Context: story 3.4 builds the field validation of D98 and the reviewed vocabularies of D104; D104 names a restricted alphabet and I40 a character set without defining them, the documents do not say where confirmed labels are kept, and its review found that a migration back-fill could forge a record's envelope (a `trusted` taint, a made-up source). Decision: a field value is checked by `vilicus-module-api` against its declaration (storage class, then closed type, or character set and maximum length for free text) and refused, never converted or cleaned; the Core runs that check on every write, in the write transaction, then checks a reviewed-vocabulary label against the labels confirmed in the file, and holds every envelope column to its stored form: `id` a 16-byte UUIDv7, `author` NULL or one, `source` the conventions' notation (`system`, `<kind>(<id>)`, `module(<name>)`), `taint` `trusted` or `external`, `data_types` a non-empty subset of the record kind's declared types in the order of the closed set, joined by commas, times within years 0000 to 9999, `rev` 1 or more; the same checks read every stored row back after a migration. A date is an RFC 3339 `full-date`. Free text counts Unicode scalar values, declares at most 2^20 of them, and refuses NUL and the other C0 controls but tab and line feed (carriage return included), DEL and the C1 controls, U+202A to U+202E, U+2066 to U+2069, U+200B, U+2060 and U+FEFF; the joiners U+200C and U+200D and the marks U+200E, U+200F and U+061C are allowed. A reviewed-vocabulary label is 1 to 32 characters from ASCII letters and digits and the precomposed letters of Latin-1 Supplement (without `×` and `÷`) and Latin Extended-A that NFKC leaves unchanged, without the confusables U+0131 and U+0138, and the separators space, hyphen and apostrophe U+0027, never at an end nor two in a row; every other punctuation (`& . ° ( /` included) is refused; clients map the typographic apostrophe U+2019 to U+0027 before sending a label; labels compare exactly. Confirmed labels live in a Core table `_vocabulary` of each module file (vocabulary, label, confirming member, time), written by the Core only, which refuses a malformed label; a label is confirmed per vocabulary and per file. In V0.1 no surface confirms a label (FR-50). The fuzz test of D98 is a seeded generator over every write path of a registry, fields and envelope, compiled only with the `testing` feature of `vilicus-core`, which the packaging check refuses in a release artefact; libFuzzer stays confined to `vilicus-proto` (D142). Consequences: labels in other scripts need a decision; a label used in several partitions is confirmed in each; story 3.5 stamps the envelope in these forms.
