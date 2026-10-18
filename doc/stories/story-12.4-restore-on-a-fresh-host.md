---
title: 'Restore on a fresh host'
epic: 12
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-53, FR-3, AD-31, AD-34, D52, D106, D120]
---

# Story 12.4: Restore on a fresh host

As an operator,
I want to restore a backup on a fresh host with the backup secret,
So that the household gets its data back after losing the host, without an old backup bringing back revoked access.

**Acceptance Criteria:**

**AC1 (FR-53, AD-31, D120)**
**Given** a fresh Debian 13 host with the package installed, services stopped and an empty data directory
**When** root runs `vilicus restore` and types the backup secret at the prompt
**Then** the manifest MAC, hashes and completeness are checked before anything is written
**And** no key unwrapped from the archive with the backup private key is used before the manifest is verified against the sequence number and hash held by the remote sink (AD-31), as HPKE usage rule U10 requires, since HPKE base mode authenticates no sender (D120, `spikes/hpke-review/REVIEW.md` section 7)

**AC2 (FR-53, D106)**
**Given** a manifest whose MAC fails, or whose sequence number is older than the latest one recorded by the remote sink
**When** the restore runs
**Then** it is refused unless the operator explicitly acknowledges it, and the acknowledgement is audited

**AC3 (FR-53, AD-31)**
**Given** a valid backup
**When** the restore completes
**Then** the instance and audit keys are written as new credentials sealed to the new host's TPM, or as file credentials without one
**And** the backup private key is discarded

**AC4 (FR-53, D52)**
**Given** the restored instance
**When** the Core first starts
**Then** every paired device, web session, enrollment token and channel binding is invalidated before anything is served

**AC5 (FR-53)**
**Given** the restored instance
**When** a member logs in with a passkey, pairs the browser with `vilicus device pair`, or re-enrolls with `vilicus member reenroll`, and unlocks
**Then** their data is intact

**AC6 (FR-53, AD-34)**
**Given** an existing installation
**When** root runs `vilicus restore` without `--replace`
**Then** it refuses because the data directory is not empty
**And** `vilicus restore --replace` moves the existing data directory aside before restoring, and the documentation calls restore an operation equivalent to root

**Dependencies:**
- Story 12.3 (verified backups)
- Story 9.12 (re-enrollment after a restore)

**References:**
- `doc/prd.md` FR-53, FR-54
- `doc/architecture-spine.md` AD-31, AD-34
- `doc/architecture.md` sections 17, 18
- `doc/decisions.md` D52, D106, D120
