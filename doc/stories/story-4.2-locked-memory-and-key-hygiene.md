---
title: 'Locked memory and key hygiene'
epic: 4
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-13, E16, AD-4, NFR-2]
---

# Story 4.2: Locked memory and key hygiene

As a member,
I want my keys held in locked memory, wiped on drop and kept out of logs and core dumps,
So that an unlocked partition exposes as little key material as the design allows.

**Acceptance Criteria:**

**AC1 (FR-13, AD-4)**
**Given** a key buffer allocated by `vilicus-crypto`
**When** it is created
**Then** it lives in locked memory (`mlock`) and the process has `PR_SET_DUMPABLE` turned off
**And** an allocation that cannot be locked fails closed with a typed error instead of falling back to swappable memory

**AC2 (FR-13, E16)**
**Given** a key that was dropped, on the normal path and on a crash path
**When** the regression test derived from E16 inspects the process memory
**Then** no copy of the key material is found
**And** core dumps are disabled for the process, so a crash writes no dump

**AC3 (AD-4)**
**Given** the source of `vilicus-crypto`
**When** the `unsafe` code is reviewed by a CI check
**Then** `unsafe` appears only in the memory-locking code of `vilicus-crypto`, each block with a comment stating why it is sound, and nowhere else in the workspace outside the documented list

**AC4 (FR-13, NFR-2)**
**Given** a test that seeds a key, a passphrase, a recovery secret and a capability token through the Core's code paths
**When** the `tracing` output of the run is captured
**Then** none of the seeded values appears in it, in clear or hex or base64 form

**AC5 (E16, FR-13)**
**Given** the E16 result recorded in `doc/research-notes.md`
**When** E16 took its fallback
**Then** the shorter unlock window maximum is the named constant in `vilicus-types`, and the E16 entry in `doc/research-notes.md` states that the documentation must say so

**Dependencies:**
- Story 4.1 (key types)
- Story 1.10 (E16 result and fallback)

**References:**
- `doc/prd.md` FR-13, FR-12
- `doc/architecture-spine.md` AD-4, Consistency Conventions (Unsafe code, Logging)
- `doc/key-management.md` section 10
- `doc/research-notes.md` E16
