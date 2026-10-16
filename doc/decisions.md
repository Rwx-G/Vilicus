# Decision log

Status: design phase, no code yet. Revision 2. Short records in an ADR style: context, decision, consequences. Status values: **Accepted** (settled for v1 design), **Proposed** (leaning, to confirm with a prototype), **Open** (not decided), **Rejected**, **Superseded** (replaced by the record named). "Amended by" names a later record that changes part of an accepted one. Detail lives in the documents each record points to; this file explains why. Records D34 to D118 come from the product requirements ([`prd.md`](prd.md), section 8.1, design changes DC-1 to DC-73) and the [architecture spine](architecture-spine.md); the design documents they amend are updated in the same change or listed as pending in [`prd.md`](prd.md) section 6.1.

| ID | Title | Status |
|----|-------|--------|
| D1 | Rust, single binary, no container requirement | Accepted |
| D2 | SQLite with SQLCipher; PostgreSQL rejected | Accepted |
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
| D18 | Plugins and AI in separate processes; systemd in v1, WASM in v2 | Accepted, amended by D92 and D95; peer identity per spine AD-24 |
| D19 | Internal wire protocols: CBOR with closed types, MCP for AI processes | Accepted |
| D20 | Event bus with stamped emitters and the outbox pattern | Accepted |
| D21 | Migrations: declarative SQL with authorizer, forward only | Accepted, amended by D84 |
| D22 | Audit log: separate process, HMAC chain, off-machine anchors | Accepted, amended by D40 and D114 |
| D23 | Assistant memory behind `MemoryStore`; native backend by default | Accepted |
| D24 | Mail and calendar: IMAP/SMTP and CalDAV first; OAuth only bring-your-own-client | Accepted |
| D25 | Groceries: list first, cart prepared by an unofficial plugin, human validation | Accepted, cart tier settled by D44 |
| D26 | Front-end framework: Lit web components built with Vite | Accepted |
| D27 | Transport: hybrid key exchange, no post-quantum claim | Accepted |
| D28 | Supply chain controls | Accepted, one exception in D61 |
| D29 | License: Apache-2.0 | Accepted |
| D30 | Messaging plugins are outbound only, for notifications | Superseded by D42 |
| D31 | Kill switch not available to tainted sessions | Accepted, amended by D86 |
| D32 | Bootstrap token and pairing protocol | Accepted, pairing amended by D35, order amended by D76 |
| D33 | Second factor: passkeys by default, TOTP as fallback only | Accepted, amended by D71 and D117 |
| D34 | Adding an adult from the CLI with a delay and a veto | Accepted, amended by D74, D77 and D88 |
| D35 | Browser pairing in an enrollment or by a PAKE-bound code | Accepted |
| D36 | Unlock window chosen by the member; no delegation sub-key in V0.1 | Accepted, amended by D62 and D113 |
| D37 | Fields declared structured or free text; member taint as quoted data | Accepted, amended by D70, D98 and D104 |
| D38 | Elevated tier 1 calls go to a queue in the primary channel | Accepted, amended by D68 and D104 |
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
| D61 | HPKE from an unaudited crate, with an internal review | Accepted, amended by D74 and D107 |
| D62 | Delegation sub-keys for scheduled tasks after V0.1 | Accepted, amended by D94 and D111 |
| D63 | The researcher, a fourth AI role, contained | Accepted, amended by D73 |
| D64 | Disclosure grants between adults | Accepted, amended by D104 |
| D65 | Playbooks run by the Core without a model | Accepted, amended by D89 and D109 |
| D66 | Activatable modules and a per-member tool policy | Accepted |
| D67 | Own-account delivery as a named I13 exception class | Accepted, amended by D81 |
| D68 | A spoken confirmation approves elevated tier 1 only | Accepted, amended by D100 |
| D69 | Letting someone in or cutting infrastructure power: not before the native app | Accepted |
| D70 | Writes made or approved by a member are stored trusted | Accepted, amended by D99 and D104 |
| D71 | Step-up bound to the hash of one action | Accepted |
| D72 | Safety-relevant from discovery | Accepted, amended by D109 |
| D73 | Researcher requests by a trusted fetcher without a model | Accepted |
| D74 | Member key pairs generated by the Core and authenticated at member add | Accepted, amended by D107 and D117 |
| D75 | Out-of-browser acknowledgement by a one-time token | Accepted |
| D76 | Bootstrap order: name and certificate before any passkey | Accepted, amended by D101 and D105 |
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
| D98 | Structured fields validated against their declaration on write | Accepted, amended by D104 |
| D99 | An approval does not launder free text | Accepted |
| D100 | Spoken yes after a template read-back | Accepted |
| D101 | V0.1 action surfaces and host-only paths | Accepted |
| D102 | First-party plugins in the main package until V1; a testbed for the gates | Accepted |
| D103 | One data type taxonomy, carried by every record | Accepted |
| D104 | Structured means fixed at build time; assistant drafts readable as quoted data | Accepted |
| D105 | Out-of-browser channel required at enrollment; named private destinations for the Core | Accepted, amended by D118 |
| D106 | Backups to object storage, with passphrase wrappers sealed | Accepted |
| D107 | V0.1 events within one partition; crypto gates with done states and fallbacks | Accepted, amended by D117 |
| D108 | Secrets that open the house entered at the host CLI under a signed boot policy | Accepted |
| D109 | Relays fail closed; playbooks trigger only on trusted principals | Accepted |
| D110 | AI runtime isolation and an opt-in Claude subscription connector | Accepted |
| D111 | Delegated run descriptors; member-owned plugins only while unlocked | Accepted |
| D112 | Spoken provenance and per-item promotion of free text | Accepted |
| D113 | V0.1 values, named constants and new dependencies | Accepted |
| D114 | Audit and inbox files encrypted at rest | Accepted |
| D115 | No loopback address grants; per-port network isolation | Accepted |
| D116 | E32 pass criterion: one action through the pipeline under household load | Accepted |
| D117 | Fallbacks for the AD-36 construction and the passkey login half of E2 | Accepted |
| D118 | Out-of-browser channel defaults to a self-hosted UnifiedPush server | Accepted |

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

Decision: TLS 1.3 with X25519MLKEM768 through rustls with aws-lc-rs where the client supports it, tested by real handshake on each client; AES-256 at rest with Argon2id-derived keys; versioned algorithm identifiers. No post-quantum signatures in v1 (no public CA issues them, WebAuthn support is in drafts) and no extra application-layer encryption (young libraries, recent advisories). The documents never say "post-quantum" or "quantum-safe" as a property of the product.

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

Amends D47 and D105. Context: PRD open question 8 left open whether the household's push server for the out-of-browser channel is self-hosted or public, and E13 could not run without the answer. Decision: the out-of-browser channel defaults to a self-hosted UnifiedPush server of the ntfy type, which the Core reaches through a named private destination (D105). A public push server is allowed when the household chooses it. E13 is measured on both and passes when the default self-hosted server passes; a public server below the threshold is documented as not recommended. A public server sees only delivery timing metadata; the content stays encrypted. Consequences: the default setup needs a push server on the household's network and a named private destination before the first enrollment; E13 runs on two servers.
