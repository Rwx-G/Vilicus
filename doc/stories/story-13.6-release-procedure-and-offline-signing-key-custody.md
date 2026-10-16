---
title: 'Release procedure and offline signing key custody'
epic: 13
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-112, AD-34, D28, FR-60, NFR-6]
---

# Story 13.6: Release procedure and offline signing key custody

As the project maintainer,
I want a written release procedure with an offline signing key under a custody procedure,
So that every release is built, signed and published the same way and the signing key never sits on a networked machine.

**Acceptance Criteria:**

**AC1 (FR-112, D28)**
**Given** the release procedure document
**When** the project maintainer follows it
**Then** the project's OpenPGP signing key is generated offline and kept on removable media under the written custody procedure
**And** every use of the key is logged in the procedure's log

**AC2 (FR-112, AD-34, NFR-6)**
**Given** a release candidate that passed every merge and release gate
**When** the release is published
**Then** the project's GitHub releases page carries the signed `.deb`, its detached signature and its CycloneDX SBOM produced by `cargo-cyclonedx`
**And** `vilicus upgrade verify` accepts the published package

**AC3 (FR-112, AD-34)**
**Given** the release build
**When** the binary is built
**Then** the project public key that `vilicus upgrade verify` checks against is embedded at build, and a test asserts it equals the key named in the procedure

**AC4 (FR-60)**
**Given** the release notes of a V0.1 release
**When** they are generated
**Then** they list the actions removed by FR-60: moving data from a personal partition to the household partition, promotion through the web, purge

**AC5 (FR-112)**
**Given** the custody procedure
**When** the key is lost or suspected compromised
**Then** the procedure names the revocation certificate, where it is kept, and how the next release announces the new key

**Decision tasks:**
- [ ] Decide the release location. Recommended: the project's GitHub releases page, as FR-112 states, with the detached signature as the trust anchor rather than the hosting. Gives up: independence from one hosting provider.
- [ ] Decide the custody procedure. Recommended: primary key generated on an offline machine, stored on two encrypted removable media kept in separate places, a revocation certificate stored with them, signing done offline over the copied artefact hashes, every use logged in the procedure. Gives up: signing speed.

**Dependencies:**
- Story 13.5 (documentation shipped with the release)
- Story 13.1 (detached signature verification)

**References:**
- `doc/prd.md` FR-60, FR-112, section 7 (supply chain)
- `doc/architecture-spine.md` AD-34, Stack (cargo-cyclonedx)
- `doc/architecture.md` section 16
- `doc/decisions.md` D28
