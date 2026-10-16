---
title: 'Operator documentation'
epic: 13
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-111, FR-2, FR-65, R14, D96, D27, NFR-7, E24, E16]
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
**And** it states which options support passkeys and installation on each supported browser

**AC3 (FR-65, D27, NFR-7)**
**Given** the reverse-proxy certificate option
**When** the operator reads it
**Then** the documentation states that the hybrid key exchange (X25519MLKEM768) ends at the proxy, and that the operator monitors certificate expiry in that mode
**And** no sentence claims more than D27 allows

**AC4 (FR-2, R14, D96, NFR-7)**
**Given** a host without a TPM
**When** the operator reads the host section
**Then** it states that the instance key is protected by file permissions only
**And** the TPM unseal recovery runbook describes restoring the instance key from a backup with the backup private key after an unseal failure

**AC5 (NFR-7, E16)**
**Given** the cryptography section
**When** it describes HPKE
**Then** it never calls the `hpke` crate audited and names the internal review and cross-test instead
**And** if E16 took its fallback, the documentation states the shorter unlock window maximum

**AC6 (FR-111)**
**Given** the backup and restore runbook and the upgrade procedure
**When** they are followed step by step in the CI Debian 13 VM
**Then** the commands they list exist with the documented arguments (checked against the CLI help output)

**Dependencies:**
- Story 13.4 (upgrade check and procedure)
- Story 12.6 (restore drill that the runbook mirrors)

**References:**
- `doc/prd.md` FR-2, FR-65, FR-111, section 7 (honesty of claims)
- `doc/architecture-spine.md` AD-22
- `doc/architecture.md` sections 2, 15, 16, 17, 20 (R14)
- `doc/research-notes.md` E16, E24
- `doc/decisions.md` D27, D61, D96
