---
title: 'Unattended backup assembly and upload'
epic: 12
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-53, FR-3, AD-31, AD-25, D85, D106, D95, D113]
---

# Story 12.2: Unattended backup assembly and upload

As an operator,
I want backups to be assembled and uploaded by a timer without any secret,
So that the household always has a recent complete off-host copy without anyone typing a secret.

**Acceptance Criteria:**

**AC1 (FR-53, AD-31, D85)**
**Given** a configured target and the default daily schedule in `vilicus.toml`
**When** the systemd timer fires
**Then** `vilicus backup` runs as root, asks the Core over its admin socket to checkpoint and pause writers and return the instance key sealed to the backup public key, and asks the audit writer over its admin socket to flush and return the audit key sealed the same way

**AC2 (FR-53, D95, AD-25)**
**Given** a running backup
**When** files are copied
**Then** the archive contains every encrypted module database, every plugin state store, `wrappers.db`, `core.db` and `audit.db`
**And** migration working copies and cold copies are excluded

**AC3 (FR-53, D106)**
**Given** the archive
**When** a test opens it without the backup secret
**Then** passphrase wrappers and file names are sealed to the backup public key, while recovery-secret and household-key wrappers are as on the host

**AC4 (FR-53, AD-31)**
**Given** the archive
**When** the manifest is written
**Then** it is CBOR and records each file's generation and SHA-256, a monotonic backup sequence number and a MAC under a key derived from the audit key

**AC5 (FR-53, AD-31)**
**Given** the assembled archive
**When** it is uploaded
**Then** it goes through the egress proxy's Unix socket under the backup caller identity
**And** retention of 7 daily and 4 weekly backups is applied and shown to every adult as a privacy setting in the member web

**AC6 (FR-53, FR-3)**
**Given** the last successful backup is older than 3 days (PRD assumption)
**When** the Core checks backup age
**Then** the instance admin receives an alert
**And** every backup run, successful or failed, writes an audit entry and appears in `vilicus status`

**Decision tasks:**
- [ ] Decide the S3-compatible client (approved by D106). Recommended: `rusty-s3` (request signing only, no bundled HTTP stack, so uploads reuse the workspace HTTP client through the egress proxy), pinned in the Stack. Gives up: a full SDK's retry and multipart helpers.
- [x] Settled by FR-50 and D113: the backup schedule is set in `vilicus.toml` (root); the `doc/capability-matrix.md` row is aligned.

**Dependencies:**
- Story 12.1 (backup target)
- Story 4.8 (backup key pair)
- Story 6.4 (audit writer admin socket)

**References:**
- `doc/prd.md` FR-53, FR-50, section 12
- `doc/architecture-spine.md` AD-25, AD-31
- `doc/architecture.md` section 18
- `doc/decisions.md` D85, D95, D106, D113
