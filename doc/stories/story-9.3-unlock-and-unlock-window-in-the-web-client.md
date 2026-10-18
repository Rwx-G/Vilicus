---
title: 'Unlock and unlock window in the web client'
epic: 9
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-11, FR-12, AD-30, AD-54, D36, D113, UX-DR4, UJ-3, NFR-4, UJ-1, D121, D128, DC-80]
---

# Story 9.3: Unlock and unlock window in the web client

As a member,
I want to unlock my partition with my passphrase after a passkey login and choose how long it stays unlocked,
So that my data is usable for a period I control and locks itself even if I never come back.

**Acceptance Criteria:**

**AC1 (FR-11, NFR-4, UJ-3)**
**Given** a member logged in with a passkey in a paired browser after a restart that left every member locked
**When** the member types the passphrase and chooses a window
**Then** Argon2id runs only because the first factor succeeded, under the global concurrency limit, and unlock completes in under 2 seconds on the reference host
**And** unlock completes when keys are derived and the session is usable; each module file then opens, migrates and delivers its outbox in the background (AD-54)

**AC2 (FR-12, D113, AD-30)**
**Given** the unlock screen
**When** the member chooses a duration
**Then** the window is at most 24 hours with a default of 12 hours (PRD assumption), starts at unlock and ends at the unlock time plus the duration as a durable deadline
**And** when the window ends, the member keys are dropped from memory

**AC3 (FR-12, D36)**
**Given** an unlocked member
**When** the member logs out, or the web session ends after 15 minutes without activity
**Then** the web session ends and the window does not; a later web session that outlives the window keeps working without partition access until the member unlocks again

**AC4 (FR-12, D113)**
**Given** an unlocked member
**When** the member extends the window
**Then** the passphrase is required and the new end is no later than now plus the maximum
**And** when the member locks on demand, the window ends immediately and the keys are dropped

**AC5 (FR-12, UX-DR4)**
**Given** an unlocked member
**When** any page of the member web is shown
**Then** it displays the remaining unlock time, refreshed through the change stream
**And** choosing, extending and ending a window each produce an audit entry

**AC6 (FR-11)**
**Given** the Core restarts
**When** it serves its first request
**Then** every member is locked and no key of any member partition or of the household partition is derivable without a passphrase

**AC7 (FR-12, UJ-1)**
**Given** a member who has just completed an enrollment
**When** they land on the home screen
**Then** their partition is unlocked with the default window of 12 hours (PRD assumption), stored as a durable deadline, which they can change like any other window

**AC8 (D128, FR-11, DC-80)**
**Given** the Argon2id limiter of Story 4.4 AC6 (two derivations at once, arrival order)
**When** a third member unlocks while two derivations run, or a request cannot start within 4 seconds, or a member retries after a wrong passphrase
**Then** the third request waits its turn; a request refused after 4 seconds is shown to the member as retryable, without the time it waited; a second request from the same member while one is in flight is refused; and after a failed passphrase the member's next attempt is delayed with an exponential backoff.

**AC9 (D121)**
**Given** a member's unlock that opens the household key wrap
**When** the Core unwraps the household key
**Then** it confirms the opened key before using it, against the confirmation tag at the member's first unlock and against the DEK-keyed commitment at every later one (Story 4.7 AC7)
**And** a mismatch refuses the opened key, so it is never used, and alerts every adult.

**Dependencies:**
- Story 9.1 (an enrolled member)
- Story 4.4 (passphrase KEK and Argon2id gate)
- Story 4.7 (confirmation of the household key)

**References:**
- `doc/prd.md` FR-11, FR-12, UJ-3, DC-80
- `doc/key-management.md` section 4
- `doc/architecture-spine.md` AD-30, AD-54
- `doc/decisions.md` D36, D90, D113, D121, D128
