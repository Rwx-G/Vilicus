---
title: 'Audit writer and HMAC chain'
epic: 6
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-31, AD-17, D22, D114, DC-69, D125]
---

# Story 6.1: Audit writer and HMAC chain

As an adult,
I want the audit log kept by its own process in an encrypted, hash-chained file,
So that no other component of Vilicus can rewrite what happened without the change being detectable.

**Acceptance Criteria:**

**AC1 (AD-17, D22)**
**Given** the audit writer unit
**When** it runs
**Then** it is a separate process under its own static user, listening on `audit/append.sock` for the Core only (the Core identified by its unit with the method of Story 5.3 AC2, D125: `SO_PEERPIDFD` at accept, pid listed in the Core unit's `cgroup.procs`, a failed `SO_PEERPIDFD` refused, the connection closed when the verified process exits) and on `audit/admin/admin.sock` for root only (uid 0 by `SO_PEERCRED`)
**And** a plugin, an AI process or the Gateway that connects to either socket is refused (test)

**AC2 (FR-31, D114, DC-69)**
**Given** the audit key delivered as the audit writer's systemd credential
**When** the writer opens `audit.db`
**Then** it is a SQLCipher file under a key derived from the audit key with the label `vilicus/v1/audit/db`, opened by the audit writer only, in the subdirectory owned by its user

**AC3 (AD-17, D22)**
**Given** an entry appended through the append socket
**When** the writer stores it
**Then** the entry carries an HMAC under the audit key covering the previous entry's hash, forming one chain
**And** the writer only appends: no socket message updates or deletes an entry

**AC4 (FR-31, AD-17)**
**Given** the entry type in `vilicus-proto`
**When** an entry is built
**Then** it has the fixed shape of `doc/architecture.md` section 14: time, principal, task, capability token id, action, tier, opaque identifiers, canonical parameter hash, taint and outcome
**And** the type has no field for a parameter value in clear

**Dependencies:**
- Story 5.7 (audit writer unit, user, data subdirectory and audit key credential)
- Story 4.3 (audit database key label)

**References:**
- `doc/prd.md` FR-31
- `doc/architecture-spine.md` AD-17, AD-55
- `doc/architecture.md` section 14
- `doc/decisions.md` D22, D114
- `doc/key-management.md` section 2 (audit key)
