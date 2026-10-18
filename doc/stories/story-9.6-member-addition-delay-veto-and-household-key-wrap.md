---
title: 'Member addition delay, veto and household key wrap'
epic: 9
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-8, D34, D88, AD-30, AD-36, FR-56, UJ-2, D119, D121]
---

# Story 9.6: Member addition delay, veto and household key wrap

As an adult,
I want a delay with a veto before a new adult receives the household key, and the key wrapped only to a verified public key,
So that nobody, including someone with shell access or a write to the data directory, can silently join the household partition.

**Acceptance Criteria:**

**AC1 (FR-8, AD-30)**
**Given** a pending addition recorded by Story 9.5
**When** the delay starts
**Then** it is a durable deadline of 24 hours (PRD assumption) that survives restarts and completes only when wall clock and accumulated uptime agree
**And** while an adult has had no working out-of-browser destination for 24 hours, the delay runs to its maximum (FR-56)

**AC2 (FR-8, D34)**
**Given** a pending addition during its delay
**When** another adult vetoes with a step-up bound to that veto in the member web, or with `vilicus member veto` and their own passphrase at the host
**Then** the new member is revoked, every adult is notified, and the veto is audited

**AC3 (D88, FR-50)**
**Given** the authorizing adult is the only adult
**When** the addition is pending
**Then** that adult is notified at each step and can cancel during the delay in the member web with a step-up bound to the cancellation, and nobody else can veto

**AC4 (FR-8, AD-36, UJ-2)**
**Given** the delay ended without a veto
**When** an existing adult next unlocks
**Then** the Core verifies the MAC written over the new public key at enrollment, under the member authentication key created by `vilicus member add`, and only then wraps the household key to it as the last background step of that unlock
**And** the new member is notified and from then on sees the household partition

**AC5 (FR-8, AD-36)**
**Given** a public key in `wrappers.db` was substituted by a write to the data directory
**When** the wrap is attempted
**Then** the key is refused, no household key wrapper is written, and every adult is alerted

**AC6 (D121, D119)**
**Given** the wrap of AC4
**When** the Core writes the household key wrapper
**Then** it writes next to it, after unwrapping the enrollment key with the household key, the confirmation tag `HMAC(K_conf, "vilicus/v1/hk/confirm/" || member_id || hk_version || C(HK))` that the new member's first unlock verifies (Story 4.7 AC7)
**And** an enrollment key wrap made under another household key version is refused as stale, not reported as tampering (D119).

**Decision tasks:**
- [x] Settled by FR-50: the only adult cancels a pending addition in the member web with a step-up bound to the cancellation (D88).

The FR-8 wrap code also waits on the owner's approval of `spikes/hpke-review/REVIEW.md` (Story 4.6, decision task; D120).

**Dependencies:**
- Story 9.5 (pending addition)
- Story 9.3 (unlock, which triggers the wrap)
- Story 4.7 (confirmation of the household key)

**References:**
- `doc/prd.md` FR-8, FR-50, FR-56, UJ-2
- `doc/key-management.md` section 5
- `doc/architecture-spine.md` AD-30, AD-36
- `doc/decisions.md` D34, D74, D88, D119, D120, D121
