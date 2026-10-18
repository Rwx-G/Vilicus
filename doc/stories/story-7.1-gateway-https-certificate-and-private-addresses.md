---
title: 'Gateway HTTPS, certificate and private addresses'
epic: 7
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-4, FR-6, FR-65, AD-14, AD-22, AD-55, D27, D51, E3, D137, D138, DC-78, DC-79]
---

# Story 7.1: Gateway HTTPS, certificate and private addresses

As an operator,
I want a socket-activated Gateway that terminates TLS with the instance certificate and listens only on private interfaces by default,
So that members reach the Core over HTTPS without the Gateway ever deciding anything, and nothing is exposed beyond the household network unless I choose it.

**Acceptance Criteria:**

**AC1 (AD-55, AD-22, D27)**
**Given** the package is installed and the Gateway unit is socket activated
**When** a browser connects over HTTPS
**Then** TLS 1.3 only is served by rustls with the aws-lc-rs provider, whose key exchange groups list X25519MLKEM768 first, then X25519, secp256r1 and secp384r1; rustls as a TLS 1.3 server takes the first group of the client's list that it supports, so the hybrid exchange is used when the client lists it first, and a client without it connects classically (E3, D27 clarified; the server does not force the hybrid group, which would need custom TLS code)
**And** a test, in the shape of `spikes/hybrid-kex/tests/handshake.rs`, shows a default rustls client getting X25519MLKEM768, X25519-only and P-256-only clients connecting, the server following the client's group order, and a TLS 1.2-only client refused
**And** the Gateway holds no address family of its own beyond the socket passed by systemd

**AC2 (FR-65, AD-22, D51)**
**Given** the certificate file option is configured
**When** the certificate and key are delivered as a systemd credential of the Gateway unit and the renewal hook runs `systemctl reload-or-restart vilicus-gateway`
**Then** the Gateway serves the renewed certificate without any other configuration change
**And** in reverse-proxy mode the Gateway accepts only the proxy's connection on its private listener and serves no certificate of its own to browsers

**AC3 (FR-6)**
**Given** a fresh installation with no exposure setting
**When** the Gateway socket unit is generated
**Then** it listens only on private interfaces: loopback, RFC 1918 addresses, IPv6 unique local addresses (fc00::/7) and link-local addresses

**AC4 (FR-4)**
**Given** bootstrap has not completed
**When** a peer whose address is not private connects
**Then** the Gateway refuses the connection
**And** private peers are served a temporary self-signed certificate whose fingerprint the Core prints with the bootstrap token

**AC5 (AD-14, AD-55)**
**Given** an HTTPS JSON request under the versioned API prefix
**When** the Gateway forwards it
**Then** it is translated into a typed CBOR request to the Core over the Gateway's peer socket, and the Core's response is returned
**And** no route of the Gateway serves MCP, verified by a route table test

**AC6 (D138, FR-4, DC-79)**
**Given** the temporary self-signed certificate of AC4
**When** it is generated
**Then** it carries IP SANs only, the host's IP addresses with loopback included, never a host name, because every browser refuses WebAuthn on an IP origin, and Chrome, once a person passed its warning for a host name, keeps refusing WebAuthn on that host for the rest of the browser session even after it serves a valid certificate (Story 1.4, finding 5)
**And** it and its listener are destroyed once the instance certificate is installed (Story 8.3 AC6).

**AC7 (D137, FR-6, FR-4, DC-78)**
**Given** the private interface list of AC3 and AC4
**When** an address in 100.64.0.0/10 is considered
**Then** it is never private by default, since that range is shared address space for carrier-grade NAT (RFC 6598) and other customers of the same provider may reach it
**And** when the operator has named one overlay interface (Story 11.2 AC5), an address of that interface in 100.64.0.0/10 is private for FR-6 and FR-4, the Gateway's socket for it is bound to that interface (`BindToDevice=`), and a peer on that address is accepted only on that socket; the overlay's IPv6 unique local addresses are already private under AC3.

**Dependencies:**
- Story 5.7 (package installs the Gateway unit, users and credentials)
- Story 6.2 (Gateway-originated authentication events are audited)

**References:**
- `doc/prd.md` FR-4, FR-6, FR-65
- `doc/architecture-spine.md` AD-14, AD-16, AD-22, AD-55
- `doc/architecture.md` section 15
- `doc/decisions.md` D27, D51, D137, D138
- `doc/research-notes.md` E3; `doc/stories/story-1.16-e3-hybrid-key-exchange-negotiation.md` (per-client table)
- `doc/qa/gates/1.16-e3-hybrid-key-exchange-negotiation.yml` (E3-2), `doc/qa/gates/1.4-e24-passkeys-and-pwa-with-each-naming-option.yml` (E24-3)
