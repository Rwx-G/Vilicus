---
title: 'Debian 13 VM CI harness'
epic: 2
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-33, FR-109, E10, E16]
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

**AC5 (E10, E16, AD-33)**
**Given** a test in the guest that boots systemd as PID 1 in a privileged container (as the E10 and E14 spikes do)
**When** the job runs it
**Then** the container image masks `systemd-sysctl.service`, because a privileged container that boots systemd shares the guest's `/proc/sys` and Debian's `10-coredump-debian.conf` replaced the guest's `systemd-coredump` pipe with `core` (Story 1.6, "Debian 13 VM run"; gates E10-4 and E16-4)
**And** the job reads `kernel.core_pattern` before and after the test and fails when it changed, so a later phase never tests the file case on a pipe host (gate E16-4: the locked-memory phase prints `core_pattern` and the report checks it against the host value).

**Dependencies:**
- Story 2.1 (workspace builds the artefacts)

**References:**
- `doc/architecture-spine.md` AD-33 (including the CI on GitHub Actions spine assumption)
- `doc/prd.md` FR-109
- `e2e/vm/` and its README (the Epic 1 Debian 13 KVM harness, a working example of AC2: QEMU with KVM, image pinned in `e2e/vm/IMAGE.lock`); `doc/qa/epic-1-report.md` section 15
- `doc/qa/gates/1.6-e10-sandbox-profile-and-peer-identity.yml` (E10-4), `doc/qa/gates/1.10-e16-locked-memory-and-zeroization.yml` (E16-4)
