# Decision log

Status: design phase, no code yet. Short records in an ADR style: context, decision, consequences. Status values: **Accepted** (settled for v1 design), **Proposed** (leaning, to confirm with a prototype), **Open** (not decided), **Rejected**. Detail lives in the documents each record points to; this file explains why.

| ID | Title | Status |
|----|-------|--------|
| D1 | Rust, single binary, no container requirement | Accepted |
| D2 | SQLite with SQLCipher; PostgreSQL rejected | Accepted |
| D3 | One database per module and per partition | Accepted |
| D4 | Key model: member DEK wrapped by several independent KEKs | Accepted |
| D5 | Instance admin separated from data keys | Accepted |
| D6 | Recovery by printed secret, waiting period and alerts | Accepted |
| D7 | Household key: versioned, rotation, threshold recovery | Accepted, threshold part Open |
| D8 | Background tasks: unlocked members, delegation sub-keys, or wait | Accepted |
| D9 | Instance key protects Core metadata only | Accepted |
| D10 | Tier 2 only from a paired native app, with signature over a displayed hash | Accepted |
| D11 | The web client never does tier 2 | Accepted |
| D12 | Protected Confirmation as reinforcement, Secure Payment Confirmation as bonus, transaction-authorization extensions dropped | Accepted |
| D13 | The model is untrusted; reader, planner and drafter roles | Accepted |
| D14 | Taint is mandatory metadata on every record | Accepted |
| D15 | "Reversible" means without effect on a third party | Accepted |
| D16 | Local alignment controller as third layer | Accepted, realization Proposed |
| D17 | No dependency on Jev (TypeSafe AI) | Accepted |
| D18 | Plugins and AI in separate processes; systemd in v1, WASM in v2 | Accepted |
| D19 | Plugin wire protocol: JSON-RPC or CBOR | Open |
| D20 | Event bus with stamped emitters and the outbox pattern | Accepted |
| D21 | Migrations: declarative SQL with authorizer, forward only | Accepted |
| D22 | Audit log: separate process, HMAC chain, off-machine anchors | Accepted |
| D23 | Assistant memory behind `MemoryStore`; native backend by default | Accepted |
| D24 | Mail and calendar: IMAP/SMTP and CalDAV first; OAuth only bring-your-own-client | Accepted |
| D25 | Groceries: list first, cart prepared by an unofficial plugin, human validation | Accepted, cart tier Open |
| D26 | Front-end framework | Open |
| D27 | Transport: hybrid key exchange, no post-quantum claim | Accepted |
| D28 | Supply chain controls | Accepted |
| D29 | License | Open |
| D30 | Messaging plugins are outbound only, for notifications | Accepted |
| D31 | Kill switch not available to tainted sessions | Accepted |
| D32 | Bootstrap token and pairing protocol | Accepted |
| D33 | Second factor: passkeys by default, TOTP as fallback only | Accepted |

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

Decision: the model is a component that proposes; the Core decides. The reader returns only closed enums, bounded numbers and opaque identifiers resolved by the Core; notifications are static templates. A drafter handles reply writing with local, human-only output. Consequences: some usefulness is lost on purpose; external MCP assistants get typed reader output by default.

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

## D19. Plugin wire protocol: JSON-RPC or CBOR

Status: open. Requirements: closed types with `deny_unknown_fields`, bounded frames, timeouts, mandatory taint. CBOR is already needed for canonical parameter hashing (deterministic encoding), which argues for one codec; JSON-RPC eases third-party plugin authoring. Decide with a prototype.

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

Decision: generated shopping list; cart prepared by an unofficial plugin acting in the user's own session; human validation before any order; no shared catalog or prices between households; no anti-bot circumvention; first step semi-manual; use an official API whenever one exists. Open: cart preparation is tier 2 in the matrix (outbound effect on an external account); a per-plugin relaxation is possible once cart operations are proven reversible.

## D26. Front-end framework

Open. One responsive front end packaged three ways (web, Android shell, desktop with Tauri later). A framework is leaning but not decided; candidates are compared on bundle size, strict CSP and Trusted Types compatibility, and drag-and-drop and calendar tooling.

## D27. Transport: hybrid key exchange, no post-quantum claim

Decision: TLS 1.3 with X25519MLKEM768 through rustls with aws-lc-rs where the client supports it, tested by real handshake on each client; AES-256 at rest with Argon2id-derived keys; versioned algorithm identifiers. No post-quantum signatures in v1 (no public CA issues them, WebAuthn support is in drafts) and no extra application-layer encryption (young libraries, recent advisories). The documents never say "post-quantum" or "quantum-safe" as a property of the product.

## D28. Supply chain controls

Decision: `cargo deny`, `cargo vet`, vendoring with `--locked`, allowlist for build scripts and proc macros, `forbid(unsafe_code)` in modules, minimal Core dependencies, SBOM, offline-signed releases with anti-rollback; reproducible builds by two builders as a goal.

## D29. License

Open. AGPL-3.0 is under consideration. No license is claimed and no LICENSE file exists until the owner decides.

## D30. Messaging plugins are outbound only

Decision: Telegram, Signal and WhatsApp plugins send notifications without sensitive content. Inbound messages are untrusted content that triggers no action. No tier 2 confirmation transits any plugin. Consequences: no chat-style control of the assistant over those channels in v1.

## D31. Kill switch not available to tainted sessions

Decision: only the human or a Core detector can trigger it; resuming needs a passkey. Reason: otherwise an injection can switch the system off at will.

## D32. Bootstrap token and pairing protocol

Decision: 128-bit one-time bootstrap token (15 minutes, loopback and LAN only, certificate fingerprint printed); device pairing with a 128-bit QR token (2 minutes, single use, bound to the initiator's session), a validation code typed on the already-paired device, 3 attempts, notifications to all devices, 24 hour delay before tier 2.

## D33. Second factor

Decision: passkeys by default; TOTP only as a login fallback, never for tier 2, pairing, recovery or step-up.
