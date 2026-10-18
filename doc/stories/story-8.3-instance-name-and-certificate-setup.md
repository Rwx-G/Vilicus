---
title: 'Instance name and certificate setup'
epic: 8
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-65, FR-4, D51, D76, E24, D113, D137, D138, DC-78, DC-79]
---

# Story 8.3: Instance name and certificate setup

As an operator holding the bootstrap token,
I want to set the instance name and a certificate trusted by the household's devices before any passkey exists,
So that every passkey is bound to the name members will keep using.

**Acceptance Criteria:**

**AC1 (FR-65, FR-4, D76)**
**Given** a redeemed bootstrap token
**When** the operator enters the instance name and chooses the certificate source
**Then** the choice is a certificate and key file delivered as a Gateway credential, or a reverse proxy that terminates TLS for the name

**AC2 (FR-65, D51)**
**Given** a configured name and certificate
**When** the wizard checks it from the wizard's browser
**Then** the certificate must validate there before any passkey enrollment page, for the instance admin or a member, is served
**And** a certificate that does not validate keeps the wizard on this step

**AC3 (FR-4, D76)**
**Given** the certificate validates
**When** the step completes
**Then** the wizard moves to the instance name and continues there

**AC4 (FR-65, D113)**
**Given** the certificate file option
**When** the certificate is within the alert lead time of its expiry (14 days, PRD assumption, operator-tunable in `vilicus.toml`)
**Then** an out-of-browser alert goes to the instance admin and every member

**AC5 (FR-65, E24)**
**Given** the reverse-proxy option
**When** it is chosen
**Then** the wizard states that the operator monitors certificate expiry and that the hybrid key exchange ends at the proxy
**And** the naming options it describes are those that passed E24: the three of FR-65 passed on desktop Chrome and Firefox with virtual authenticators (Story 1.4), and none is removed; Android, Safari, real authenticators and a real public CA are still to run (gate E24-1)

**AC6 (D138, D76, DC-79)**
**Given** the wizard before the instance name and its real certificate exist
**When** its routes are enumerated
**Then** no WebAuthn ceremony route is served, and the relying party of Story 7.6 AC9 accepts only the instance name, so a ceremony a browser runs on `localhost` or an IP address over the temporary certificate is refused server side
**And** once the real certificate is installed, the temporary IP-only certificate (Story 7.1 AC6) and its listener are destroyed: the listener's port refuses connections and the certificate is no longer stored; the bootstrap token (D32) and the printed fingerprint keep gating the wizard until then.

**AC7 (FR-65, E24)**
**Given** the instance name the operator enters
**When** the wizard checks it
**Then** it refuses an IP address as the instance name, even one with a valid certificate, because every browser refused WebAuthn on an IP origin and `webauthn-rs` refuses an IP address as RP ID (Story 1.4, settled task 3), and the RP ID is the full instance name.

**AC8 (D137, FR-4, DC-78)**
**Given** the private-network naming option with an overlay address in 100.64.0.0/10
**When** no overlay interface has been named at the host
**Then** a peer on that address is refused by the wizard like any non-private peer (FR-4, Story 7.1 AC7) until the operator names the overlay interface at the host with `vilicus instance listen` (Story 11.2 AC5); the overlay's IPv6 unique local addresses are private already
**And** the option's text states, as PRD FR-65 does, that every household device joins the overlay network, that on Android the overlay client and the WireGuard tunnel of FR-86 compete for the single VPN slot, and that the operator names the overlay interface so its addresses count as private.

**Dependencies:**
- Story 8.2 (bootstrap token)
- Story 8.1 (notification stage for expiry alerts)
- Story 7.1 (temporary certificate and private interfaces)
- Story 7.6 (relying party checks)

**References:**
- `doc/prd.md` FR-4, FR-65, DC-78, DC-79
- `doc/architecture-spine.md` AD-52, AD-22
- `doc/architecture.md` sections 7.1, 15
- `doc/decisions.md` D27, D51, D76, D113, D137, D138
- `doc/research-notes.md` E24
- `doc/stories/story-1.4-e24-passkeys-and-pwa-with-each-naming-option.md` (matrix, findings 1 to 6, open decision tasks settled)
- `doc/qa/gates/1.4-e24-passkeys-and-pwa-with-each-naming-option.yml` (E24-1, E24-3)
