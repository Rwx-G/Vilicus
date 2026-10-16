---
title: 'Signed packages and upgrade verify'
epic: 13
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-54, FR-112, FR-109, AD-34, D28]
---

# Story 13.1: Signed packages and upgrade verify

As an operator,
I want to check a package's detached signature against the project key before I install it,
So that only a release signed by the project's offline key reaches my host.

**Acceptance Criteria:**

**AC1 (FR-54, AD-34, FR-112)**
**Given** a `.deb` and its detached OpenPGP signature made by the project key
**When** the operator runs `vilicus upgrade verify <package>` as root
**Then** the command checks the signature against the project key embedded at build in the installed version and reports success
**And** it needs no member passphrase and unlocks nothing

**AC2 (FR-54, AD-34)**
**Given** a package whose signature is missing, malformed, made by another key, or whose bytes were modified after signing
**When** the operator runs `vilicus upgrade verify <package>`
**Then** the command fails with a non-zero exit status and a stable error message naming the reason
**And** nothing on the host is changed

**AC3 (FR-109, D28)**
**Given** a package signed only by the CI test key
**When** it is verified by the shipped `vilicus` binary
**Then** verification fails, because the shipped binary accepts only the project key
**And** the same package verifies with `vilicus-testbed`, which also accepts the CI test key

**AC4 (FR-54, AD-34)**
**Given** the Core is running
**When** it starts or serves requests
**Then** it verifies no package signature at runtime; signature checking exists only in `vilicus upgrade verify`

**AC5 (FR-54)**
**Given** any run of `vilicus upgrade verify`, successful or not
**When** the command completes
**Then** an audit entry records the command, the package version and the outcome, without key material

**Dependencies:**
- Story 5.7 (the Debian package and the installed binary that embeds the project key)
- Story 6.2 (every CLI command is audited)

**References:**
- `doc/prd.md` FR-54, FR-109, FR-112
- `doc/architecture-spine.md` AD-34
- `doc/architecture.md` section 16
- `doc/decisions.md` D28
