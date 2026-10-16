---
title: 'Restore drill in CI'
epic: 12
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-53, AD-31, AD-33]
---

# Story 12.6: Restore drill in CI

As a project maintainer,
I want CI to run a full restore drill on fresh Debian 13 VMs for every release,
So that no release ships whose backups cannot be restored.

**Acceptance Criteria:**

**AC1 (FR-53, AD-33)**
**Given** a release candidate package
**When** the drill job runs
**Then** it installs the package on a fresh Debian 13 VM, bootstraps, enrolls a member, changes member state that lives in partition and Core files (unlock window choice, a second passkey, a paired browser removed), and backs up to a test object storage target through the egress proxy

**AC2 (FR-53, AD-31)**
**Given** that backup
**When** the job restores it on a second fresh Debian 13 VM with the backup secret
**Then** the member logs in, pairs, unlocks and reads back the same data

**AC3 (AD-33)**
**Given** a drill that fails at any step
**When** the release pipeline runs
**Then** the release is blocked and the failing step is reported

**Dependencies:**
- Story 12.5 (restore and acknowledgement)
- Story 2.3 (Debian 13 VM CI harness)

**References:**
- `doc/prd.md` FR-53, section 6.1 (exit criteria)
- `doc/architecture-spine.md` AD-31, AD-33
