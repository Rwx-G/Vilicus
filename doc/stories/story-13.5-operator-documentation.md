---
title: 'Operator documentation'
epic: 13
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-111, FR-2, FR-65, R14, D96, D27, NFR-7, E24, E16, E3, D131, D132, D134, D135, D137, D139]
---

# Story 13.5: Operator documentation

As an operator,
I want each release to ship the documentation I need to install, name, back up, restore, recover and upgrade the instance,
So that I can run Vilicus without reading its source and without being misled about what it protects.

**Acceptance Criteria:**

**AC1 (FR-111)**
**Given** a release candidate
**When** the documentation is built
**Then** it covers installation, the naming and certificate options, the TPM and no-TPM statement, the backup and restore runbook, the TPM unseal recovery runbook and the upgrade procedure
**And** a CI check fails if any of these sections is missing

**AC2 (FR-65, E24)**
**Given** the results of E24
**When** the naming section is written
**Then** it describes only the no-cost naming options that passed E24 (free dynamic DNS subdomain with a DNS-01 certificate, private-network name, local certificate authority), with placeholder names such as `vilicus.example.com`
**And** it states which options support passkeys and installation on each supported browser, naming the browsers actually run (desktop Chrome and Firefox with virtual authenticators at the end of Epic 1, installation measured on Chrome only) and the ones still to run
**And** it carries the conditions E24 found, as PRD FR-65 states them: the instance name is a DNS name, never an IP address; a public CA certificate is published in Certificate Transparency logs, so the instance name becomes public; with a dynamic DNS record holding the host's private address, router DNS rebinding protection may drop the answer, and it says how to add an exception; with a private-network name, every household device joins the overlay network, the operator names the overlay interface with `vilicus instance listen` so its 100.64.0.0/10 address counts as private (D137), and on Android the overlay client and the WireGuard tunnel compete for the single VPN slot

**AC3 (FR-65, D27, NFR-7)**
**Given** the reverse-proxy certificate option
**When** the operator reads it
**Then** the documentation states that the hybrid key exchange (X25519MLKEM768) ends at the proxy, and that the operator monitors certificate expiry in that mode
**And** it states that the proxy terminates TLS for the instance name on ports 443 and 8443, the only externally visible ports, and forwards the Host header with its port (nginx `proxy_set_header Host $http_host`; Caddy keeps it by default), because the external-content origin is the instance name on port 8443 (D139)
**And** the transport wording says the hybrid exchange is used when the client lists it first, names only the clients E3 ran, and says the others connect classically (E3, D27)
**And** no sentence claims more than D27 allows

**AC4 (FR-2, R14, D96, NFR-7)**
**Given** a host without a TPM
**When** the operator reads the host section
**Then** it states that the instance key is protected by file permissions only
**And** the TPM unseal recovery runbook describes restoring the instance key from a backup with the backup private key after an unseal failure

**AC5 (NFR-7, E16, D120, D123, D129, D131)**
**Given** the cryptography section
**When** it describes HPKE, Argon2id and the pairing code
**Then** it never calls the `hpke`, `argon2`, `opaque-ke` or `@serenity-kit/opaque` libraries audited at their pinned versions, and names their internal reviews, vectors and cross-tests instead
**And** E16 took no fallback (D131), so it states no shorter unlock window maximum; it states the key memory limits of D131 instead: abort paths without user code leave keys in memory until the process ends, without a dump, and the Argon2id working memory is wiped but not locked, so swap is disabled or encrypted and hibernation disabled

**AC6 (FR-111)**
**Given** the backup and restore runbook and the upgrade procedure
**When** they are followed step by step in the CI Debian 13 VM
**Then** the commands they list exist with the documented arguments (checked against the CLI help output)

**AC7 (D135, D118)**
**Given** the out-of-browser channel section
**When** the operator sets up a self-hosted push server
**Then** it states that the push server keeps alerts long enough for an offline phone (ntfy `cache-duration` not 0); that phones reach it off the household network through a published endpoint with `auth-default-access` set to `deny-all` and a read-only token per phone, the V0.1 path, or through D60's WireGuard tunnel once the home milestone ships it; that iOS members need forwarding through an upstream server (ntfy `upstream-base-url`), which sees delivery timing; and that any push server's operator sees the generic alert text and the delivery timing, never a token
**And** it states that acknowledging an alert needs a signed-in Vilicus client.

**AC8 (D132)**
**Given** the backup and restore runbook
**When** it describes deletion
**Then** it states the backup caveat: a record deleted on the host stays in existing backups and migration cold copies until they expire (7 daily and 4 weekly backups), and freed filesystem blocks may keep old ciphertext under the file key, which the deletion claim does not cover.

**AC9 (D134, R54)**
**Given** the plugin and egress section
**When** it describes the egress allowlist
**Then** it states that a hostname on a shared front end can carry requests to another tenant through the HTTP Host header, the accepted risk R54, that the proxy checks SNI and refuses Encrypted Client Hello, and that an allowlist entry on a front end that does not refuse a Host differing from SNI needs a stated reason.

**Dependencies:**
- Story 13.4 (upgrade check and procedure)
- Story 12.6 (restore drill that the runbook mirrors)

**References:**
- `doc/prd.md` FR-2, FR-65, FR-111, section 7 (honesty of claims)
- `doc/architecture-spine.md` AD-22
- `doc/architecture.md` sections 2, 15, 16, 17, 20 (R14)
- `doc/research-notes.md` E3, E16, E24
- `doc/decisions.md` D27, D61, D96, D118, D120, D123, D129, D131, D132, D134, D135, D137, D139
