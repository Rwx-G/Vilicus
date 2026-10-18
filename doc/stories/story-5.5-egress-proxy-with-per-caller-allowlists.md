---
title: 'Egress proxy with per-caller allowlists'
epic: 5
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-55, AD-16, AD-55, E14, I4, D105, D125, D133, D134, T67]
---

# Story 5.5: Egress proxy with per-caller allowlists

As an operator,
I want all outbound traffic to go through one proxy that allows only listed hostnames per caller and refuses internal addresses,
So that no Vilicus process can reach the household network or an unlisted host on its own.

**Acceptance Criteria:**

**AC1 (AD-16, AD-55)**
**Given** the egress proxy unit
**When** it runs
**Then** it keeps no TCP listener and accepts callers only on one Unix data socket per caller (`egress/data/<caller>.sock`), identified by `SO_PEERPIDFD`, and takes allowlists from the Core only over `egress/control.sock`
**And** it accepts `CONNECT host:port` only, for a hostname on that caller's exact-hostname allowlist

**AC2 (AD-16, FR-55)**
**Given** an allowed hostname
**When** the proxy connects
**Then** it resolves the name itself, checks each resolved address at connect time and connects to that exact address
**And** it refuses loopback, RFC 1918, link-local and unique local addresses, 100.64.0.0/10, IPv4-mapped and NAT64 forms of all of these, multicast and unspecified addresses, and the host's own and the household's public addresses
**And** a test name that rebinds between two lookups to an internal address is refused
**And** the E14 test set of `spikes/egress-filter/run.sh` passes against the product proxy: the 34 `bypass.*` attempts, the `caller.*` checks, the `internal.*` matrix with its reachability controls (each refused address that has a host on the test network shown reachable from the proxy's own namespace, `0.0.0.0` included, which reaches the proxy host's own listeners), the `ac2.*` rebinding checks, the `sni.*` checks and the `limit.*` checks.

**AC3 (D105, I4, D133)**
**Given** a named private destination entry (host and port) set by the Core
**When** a caller requests it
**Then** the proxy allows it to the Core and backup callers only and refuses it to any other caller
**And** the entry also records the private range (RFC 1918 or unique local) its resolved addresses must fall in, and the proxy checks at connect time that each address lies in that range, in RFC 1918 or unique local space and outside the blocked list, so neither a rebinding name nor a configuration that bypassed the load check reaches loopback or another LAN host.

**AC4 (I4, FR-55, E14, D134)**
**Given** a sandboxed unit in the Debian 13 VM
**When** it opens a direct outbound connection
**Then** the connection fails, while the same request through its proxy socket to an allowlisted host succeeds; a connect that times out counts as enforcement, since `IPAddressDeny=any` drops rather than rejects
**And** the E14 direct-connection checks (`ac3.*` in `spikes/egress-filter/run.sh`, and the host matrix `host-e14-ac3.sh` that passed 22 of 22 under the guest's systemd, `doc/qa/epic-1-report.md` section 15) pass in the Debian 13 VM as a kept VM test (gate E14-2); E14 evaluated its fallback, per-caller IP ranges, and did not adopt it, because the tenants of a shared front end share its addresses (D134).

**AC5 (AD-16, D125)**
**Given** the Core
**When** it starts on a host that cannot enforce the IP filter
**Then** it refuses to start with a clear error, the check running as root before the Core and outside any IP filter: it owns a loopback UDP listener, sends a control datagram that must arrive, then has a transient unit with `IPAddressDeny=any` send one that must fail with `EPERM` and not arrive; anything else refuses startup, and TCP is not used because under the filter a connect times out instead of failing (Story 1.6, settled task 7)
**And** while running it checks the proxy's health every 30 seconds (assumption of `doc/architecture.md` section 17) and, after three failures, raises an alert in the Core alert queue

**AC6 (D134, T67, E14)**
**Given** a caller that reaches a shared front end
**When** it opens a tunnel
**Then** the first TLS ClientHello of the tunnel must be a single-record ClientHello whose SNI equals the CONNECT host and that offers no Encrypted Client Hello, and the proxy closes the tunnel before any byte reaches the upstream on a mismatching SNI, an ECH offer, a missing SNI or a non-TLS first record; plugin HTTP clients do not enable ECH
**And** an allowlist entry on a front end that does not refuse a Host differing from SNI carries a stated reason in the allowlist review; fronting by the HTTP Host header with a matching SNI stays the accepted risk R54 and T67, recorded by a test that shows it is not detected (`sni.host_header_fronting_not_detected`), and gate 1.12 stays FAIL against the spike's own criterion with that residual risk accepted.

**AC7 (D133, AD-16)**
**Given** a CONNECT request
**When** the proxy reads it
**Then** it accepts only one `CONNECT host:port` in HTTP/1.0 or 1.1 (HTTP/1.0 is in real use, `socat` sends it), with a request line in visible ASCII and a header of at most 8 KiB read within one header timeout, and a target that is a DNS hostname only: IP literals, a trailing dot, userinfo and any form the C library reads as an address are refused, and names compare in lowercase ASCII
**And** the allowlist decision is taken on the canonical hostname before any lookup, so a refused name never reaches the resolver, and the proxy logs an allowlisted target by name and any other target only as its length and a keyed hash
**And** the refused address set follows D133: IPv6 only inside global unicast (`2000::/3`), every IANA special-purpose range that is not globally reachable refused, 6to4 and NAT64 forms (network-specific NAT64 prefixes included) judged on the embedded IPv4 address, one refused address refusing the whole name, the household's whole delegated IPv6 prefix refused, and the host's own and the household's WAN addresses tracked at run time, not configured once.

**AC8 (D133, E14)**
**Given** the proxy's name resolution
**When** it resolves an allowlisted name
**Then** it uses an asynchronous resolver that queries only its configured DNS servers, with the absolute name and no search list, never the hosts file or other name service modules, and cancels a lookup in flight on timeout, because `getaddrinfo` consults both and keeps its blocking thread after a timeout (gate E14-3)
**And** it resolves the name once per tunnel and dials exactly the checked addresses, IPv6 and IPv4 interleaved, the next one started every 250 ms while earlier ones are pending, under one deadline.

**AC9 (D133, E14)**
**Given** a caller that holds many tunnels, or a host short of file descriptors
**When** the limits are reached
**Then** each caller socket has its own connection limit (the next connection gets 503 while other callers are served), a tunnel closes when idle and at its maximum lifetime, and the accept loop survives `EMFILE`, `ENFILE` and `ECONNABORTED`
**And** a test runs the proxy with `LimitNOFILE=64`, opens connections until `accept` fails with `EMFILE`, releases them, and checks that the same listener then answers a new connection (gate E14-4).

**AC10 (D125, AD-24)**
**Given** a caller socket
**When** a peer connects
**Then** the caller is identified by its unit with the method of Story 5.3 AC2, never by uid alone: every uid check of the spike becomes a unit identity check
**And** the spike's `documentation-ranges-public` switch, or any equivalent that unblocks documentation ranges for a test network, exists only behind a cargo feature absent from the release profile, and a release build refuses it at load.

**AC11 (E14)**
**Given** the proxy's network tests
**When** they read service logs
**Then** every read goes through one helper that strips the erase-line escape (`ESC [2K`) Debian's Compose 2.26 writes at the start of every `logs` line, because anchored log checks otherwise fail or pass vacuously (gate E14-5).

**Dependencies:**
- Story 5.4 (units and profile)
- Story 5.3 (unit identity of a peer)
- Story 1.12 (E14 result; D133, D134)

**References:**
- `doc/prd.md` FR-55, FR-56
- `doc/architecture-spine.md` AD-16, AD-55
- `doc/architecture.md` sections 4, 17 and 20 (R54)
- `doc/threat-model.md` T67
- `doc/ai-safety.md` I4
- `doc/decisions.md` D105, D125, D133, D134
- `doc/research-notes.md` E14
- `spikes/egress-filter/` (`src/address.rs`, `src/target.rs`, `src/sni.rs`, `src/proxy.rs`, `run.sh`)
- `doc/qa/gates/1.12-e14-egress-proxy-domain-filtering.yml` (E14-1 to E14-5)
