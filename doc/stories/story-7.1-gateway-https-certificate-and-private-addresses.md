---
title: 'Gateway HTTPS, certificate and private addresses'
epic: 7
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-4, FR-6, FR-65, AD-14, AD-22, AD-55, D27, D51]
---

# Story 7.1: Gateway HTTPS, certificate and private addresses

As an operator,
I want a socket-activated Gateway that terminates TLS with the instance certificate and listens only on private interfaces by default,
So that members reach the Core over HTTPS without the Gateway ever deciding anything, and nothing is exposed beyond the household network unless I choose it.

**Acceptance Criteria:**

**AC1 (AD-55, AD-22, D27)**
**Given** the package is installed and the Gateway unit is socket activated
**When** a browser connects over HTTPS
**Then** TLS 1.3 is served by rustls with the aws-lc-rs provider, preferring the hybrid key exchange (X25519MLKEM768) when the client offers it, D27 wording
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

**Dependencies:**
- Story 5.7 (package installs the Gateway unit, users and credentials)
- Story 6.2 (Gateway-originated authentication events are audited)

**References:**
- `doc/prd.md` FR-4, FR-6, FR-65
- `doc/architecture-spine.md` AD-14, AD-16, AD-22, AD-55
- `doc/architecture.md` section 15
- `doc/decisions.md` D27, D51
