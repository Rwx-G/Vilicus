---
title: 'Key hierarchy and derived file keys'
epic: 4
story: 3
status: draft
author: Rwx-G
created: 2026-10-16
implements: [D3, D4, D9, AD-5, AD-4]
---

# Story 4.3: Key hierarchy and derived file keys

As a member,
I want each encrypted file opened with its own key derived from my partition root,
So that one file key reveals no other file and partition isolation rests on keys, not on code paths.

**Acceptance Criteria:**

**AC1 (D3, AD-5)**
**Given** a partition root (member DEK, household key or, for Core metadata, the instance key)
**When** the Core opens a `<module>.<partition>.db` file
**Then** the file's raw SQLCipher key is derived with HKDF-SHA-256 and the versioned label `vilicus/v1/db/<module>/<partition>/<generation>` of `doc/key-management.md` section 2
**And** two files of the same partition, or the same module in two partitions, get different keys (property test)

**AC2 (AD-5)**
**Given** a derived file key
**When** the file is created or re-keyed
**Then** its key epoch (partition root version, generation) is written atomically in the clear sidecar `<file>.epoch` and repeated in the file's `_meta` table
**And** an epoch mismatch between the sidecar and `_meta` refuses the open with a typed error

**AC3 (D9)**
**Given** the instance key delivered to the Core
**When** keys for Core metadata and the audit database are derived
**Then** Core metadata keys derive from the instance key and the audit database key derives from the audit key with the label `vilicus/v1/audit/db`
**And** no derivation from the instance key opens a personal or household partition file (test over every V0.1 label)

**AC4 (D4, AD-4)**
**Given** the `wrappers.db` schema
**When** it is created
**Then** it holds every member DEK wrapper (one per KEK) and member public key with format version, generation and algorithm identifiers, in its own file separate from `core.db`
**And** losing `core.db` or the instance key does not prevent unwrapping a member DEK from `wrappers.db` (test)

**AC5 (AD-4)**
**Given** a module that needs its data
**When** the Core hands it access
**Then** it receives an opened, partition-scoped handle, never a key or a path to a key

**Decision tasks:**
- [ ] Decide how `wrappers.db` is authenticated as a whole (`doc/stories/deferred-work.md`, gate AD36-1): the AD-36 construction authenticates each record, not the set, so deleting a record raises no alert and restoring an older file can bring back a vetoed or suspended member's valid record (D119). Recommended (gate AD36-1, which assigns the design to the keys and storage epics): the candidate recorded with the deferred item, a monotonic counter and a MAC over the record set under an HK-derived key, cross-checked with `core.db`, decided here because this story creates the `wrappers.db` schema. Gives up: every wrapper write also rewrites the set MAC and the counter; deferring again keeps the limit of D119 stated instead.

**Dependencies:**
- Story 4.1 (crypto suite)
- Story 3.1 (storage layer and epoch sidecar)

**References:**
- `doc/key-management.md` sections 2 and 9
- `doc/architecture-spine.md` AD-4, AD-5
- `doc/decisions.md` D3, D4, D9, D119
- `doc/architecture.md` section 5.2
- `doc/stories/deferred-work.md`; `doc/qa/gates/1.1-key-prototype-ad36-public-key-authentication.yml` (AD36-1)
