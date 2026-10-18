---
title: 'Automated user journeys in the VM'
epic: 14
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-109, UJ-1, UJ-2, UJ-3, SM-3, E24, D138]
---

# Story 14.3: Automated user journeys in the VM

As the project maintainer,
I want UJ-1, UJ-2 and UJ-3 to run automated against the shipped package,
So that every release proves the installable Core works end to end for a household.

**Acceptance Criteria:**

**AC1 (FR-109, UJ-1, SM-3)**
**Given** a clean Debian 13 VM and the shipped `.deb`
**When** the journey test installs the package and drives the wizard with a browser virtual authenticator (token, instance name and certificate, admin passkey, admin destination, backup secret, first member)
**Then** the first member lands unlocked on the empty home screen, the wizard routes return not found, and `vilicus status` shows one member and healthy services
**And** the journey completes in under 30 minutes

**AC2 (UJ-1)**
**Given** the wizard was interrupted after the instance admin was created and before any member enrolled
**When** the test runs `vilicus member enroll-first` with the admin recovery code and finishes enrollment in the browser
**Then** the first member is enrolled and the command is refused when run again

**AC3 (UJ-2)**
**Given** an enrolled first member
**When** the test runs `vilicus member add` with that member's passphrase, enrolls the second adult in a second browser, advances the 24-hour delay, and unlocks the first member
**Then** the household key is wrapped to the new member only after the public key check succeeds, the new member reads the household partition, the first member cannot read the new member's personal partition, and the audit log shows each step
**And** a run of `vilicus member add` without a passphrase fails and is audited

**AC4 (UJ-3, SM-3)**
**Given** an enrolled member and a restarted host
**When** the test logs in with the passkey, unlocks with the passphrase and chooses a window
**Then** the data is back, the remaining time is shown, the audit view shows the restart and the unlock, and the partition locks when the window ends
**And** the journey completes in under 30 minutes

**AC5 (FR-109)**
**Given** the release job
**When** any journey fails
**Then** the release is blocked

**AC6 (E24, D138, AD-33)**
**Given** the bootstrap order of D76, which the virtual-authenticator journey of AC1 cannot show, because Chrome's CDP virtual authenticator lets a ceremony run on a page with a certificate error that Chrome otherwise refuses (Story 1.4, finding 2)
**When** the negative test of the bootstrap order runs
**Then** it attempts the ceremony over the temporary certificate from a browser profile without a virtual authenticator and finds it refused, by IP address and by `localhost`
**And** it asserts the server-side refusal of a `localhost` origin and of an IP origin by the relying party (Story 7.6 AC9), whatever the browser did, since on `localhost` both Chrome and Firefox run the ceremony.

**Dependencies:**
- Story 14.2 (surface conformance)

**References:**
- `doc/prd.md` section 2.3 (UJ-1, UJ-2, UJ-3), FR-109, section 6.1, SM-3
- `doc/architecture-spine.md` AD-33
- `doc/decisions.md` D76, D102, D138
- `doc/stories/story-1.4-e24-passkeys-and-pwa-with-each-naming-option.md` (AC2 result, findings 2 and 5)
