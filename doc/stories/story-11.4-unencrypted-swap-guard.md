---
title: 'Unencrypted swap guard'
epic: 11
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [NFR-5, FR-3, D131]
---

# Story 11.4: Unencrypted swap guard

As an operator,
I want the Core to refuse to start on a host with unencrypted swap unless I acknowledge the risk,
So that unlocked keys are not written to disk in clear without a deliberate decision.

**Acceptance Criteria:**

**AC1 (NFR-5)**
**Given** a Debian 13 VM with an unencrypted swap device active and no acknowledgement recorded
**When** the Core starts
**Then** it refuses to start and logs the reason to the journal

**AC2 (NFR-5)**
**Given** a host with encrypted swap, or no swap
**When** the Core starts
**Then** it starts normally without any acknowledgement

**AC3 (NFR-5, FR-3)**
**Given** the host of AC1
**When** root runs `vilicus host acknowledge-swap`
**Then** the acknowledgement is recorded, the Core starts, and an audit entry records the command

**AC4 (NFR-5)**
**Given** an acknowledged unencrypted swap
**When** the instance admin goes through the bootstrap wizard, or root runs `vilicus status`
**Then** both show that unencrypted swap was acknowledged

**AC5 (D131, NFR-5)**
**Given** a host whose active swap is a swap file rather than a partition (as the E16 VM run used)
**When** the Core starts
**Then** the check covers every active swap area the kernel lists, swap files included, because the Argon2id working memory (up to the limit times m, 1 GiB at most) is wiped but not locked, and any key object that must outlive one operation sits in unlocked memory, so both reach swap in clear on an unencrypted swap area (D131; Story 1.10, `swap-control-unlocked-page-swapped`).

**Decision tasks:**
- [ ] Decide whether the guard also covers hibernation: `doc/architecture.md` section 4 requires swap disabled or encrypted and hibernation disabled (D131, Story 1.10 "Limits": hibernation images are outside the E16 claim), and no V0.1 story checks hibernation. Recommended: refuse to start, with the same acknowledgement path as AC3, when hibernation is enabled to an unencrypted swap area. Gives up: one more host check and acknowledgement to explain.

**Dependencies:**
- Story 11.1 (status output)
- Story 8.4 (bootstrap wizard admin steps)

**References:**
- `doc/prd.md` section 7 (host hygiene), FR-3
- `doc/architecture.md` section 4 (memory hygiene)
- `doc/decisions.md` D131
- `doc/stories/story-1.10-e16-locked-memory-and-zeroization.md` (settled tasks 5 and 6, Limits)
