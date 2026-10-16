---
title: 'Debian 13 VM CI harness'
epic: 2
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-33, FR-109]
---

# Story 2.3: Debian 13 VM CI harness

As a project maintainer,
I want CI to boot a Debian 13 virtual machine with systemd as PID 1,
So that tests needing systemd units, sockets and sandboxing run in the real production shape.

**Acceptance Criteria:**

**AC1 (AD-33)**
**Given** a CI runner
**When** the VM job starts
**Then** its first step checks that the runner supports nested virtualisation
**And** fails with a clear message naming the missing capability when it does not.

**AC2 (AD-33, FR-109)**
**Given** a runner with nested virtualisation
**When** the job boots a Debian 13 amd64 image
**Then** systemd runs as PID 1 in the guest
**And** the job copies the built artefacts into the guest and runs a test command there, returning its exit status and logs to CI.

**AC3 (AD-33)**
**Given** a smoke test unit file shipped with the harness
**When** the harness starts it with `systemctl` in the guest
**Then** the test asserts the unit reaches the active state and its journal output is collected as a CI artefact.

**AC4 (AD-33)**
**Given** a project that cannot use a hosted runner with nested virtualisation
**When** a maintainer reads `ci/`
**Then** the self-hosted runner fallback is documented with its required host capabilities and the steps to register it.

**Dependencies:**
- Story 2.1 (workspace builds the artefacts)

**References:**
- `doc/architecture-spine.md` AD-33 (including the CI on GitHub Actions spine assumption)
- `doc/prd.md` FR-109
