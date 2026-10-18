---
title: 'Recovery secret format and recovery KEK'
epic: 4
story: 5
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-14, FR-7, FR-110, D6, D39, D128, D131]
---

# Story 4.5: Recovery secret format and recovery KEK

As a member,
I want a printed recovery secret that is easy to copy without errors in any language and that unwraps my data key,
So that I can regain my partition when I lose my passkeys and my passphrase.

**Acceptance Criteria:**

**AC1 (FR-110, FR-14)**
**Given** a new recovery secret
**When** the Core generates it
**Then** it is random, rendered as grouped characters from a language-neutral alphabet with a checksum
**And** the same rendering is used for French and English members

**AC2 (FR-14)**
**Given** a recovery secret typed with one wrong or swapped character
**When** it is checked
**Then** the checksum error is detected before any Argon2id work starts, and the error names no character position beyond the failing group

**AC3 (D6, FR-14)**
**Given** a valid recovery secret
**When** the recovery KEK is derived
**Then** it wraps the member DEK in `wrappers.db` with a versioned wrapper of Story 4.1
**And** unwrapping with that KEK yields the same DEK as the passphrase KEK (test)

**AC4 (FR-7)**
**Given** an enrollment that shows a new secret once
**When** the partial re-typing step asks for some groups
**Then** a helper selects which groups to ask from a random choice and checks only those groups
**And** the full secret is never stored outside the wrapper derivation

**AC5 (D39, FR-14)**
**Given** a member who receives a new recovery secret
**When** the new wrapper is written
**Then** the previous recovery wrapper is removed in the same transaction, so the old secret no longer unwraps anything

**AC6 (D128, D131)**
**Given** a recovery KEK derivation that passed the checksum of AC2
**When** Argon2id runs
**Then** it goes through the one Argon2id limiter of Story 4.4 AC6, since D128 puts every Argon2id derivation of the Core behind it, and runs on Core-owned memory wiped after use under the key-operation guard (Story 4.4 AC7)

**Dependencies:**
- Story 4.4 (Argon2id KEK derivation)

**References:**
- `doc/prd.md` FR-7, FR-14, FR-110
- `doc/key-management.md` sections 2, 3 and 6
- `doc/decisions.md` D6, D39, D128, D131
