---
title: 'Capability tokens'
epic: 10
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-27, AD-11, D113, I5, I18, FR-107, FR-108, FR-14]
---

# Story 10.2: Capability tokens

As a member,
I want every plugin and AI task acting for me to hold a short-lived token whose scope only the Core knows,
So that a component can never exceed the task, partitions and actions it was given, and revocation takes effect at once.

**Acceptance Criteria:**

**AC1 (FR-27, AD-11)**
**Given** a task for one member
**When** the Core issues a capability token
**Then** the token is an opaque random identifier, and its scope (task, member, modules, partitions, actions, budget, expiry, provider) lives only in Core state
**And** the token carries no claim a peer could read or validate offline

**AC2 (FR-27, D113)**
**Given** an issued token
**When** 10 minutes pass, or its budget of 50 tool calls is spent
**Then** every further call with it is refused and audited
**And** both values come from the named constants of `vilicus-types`

**AC3 (FR-27, AD-11)**
**Given** a token issued to the plugin double's unit
**When** the same token is presented on another peer's socket, or by the AI double
**Then** the Core refuses it, because a token is accepted only from the peer unit it was issued to
**And** the token travels on every request, every MCP request included, and a request without it is refused

**AC4 (AD-11, I5)**
**Given** an outstanding token
**When** the Core revokes it
**Then** its state is deleted and the next call with it fails immediately, without waiting for its expiry

**AC5 (I18)**
**Given** the tool registry
**When** the static check runs
**Then** no tool creates or revokes a token, and issuance and revocation are reachable only from Core code paths

**AC6 (FR-107, FR-108, FR-14)**
**Given** a member with outstanding capability tokens
**When** the member is suspended, completes a re-enrollment or completes a recovery
**Then** every outstanding token acting for that member is revoked at once, and a new token for a suspended member is refused

**Dependencies:**
- Story 10.1 (peer handshake and doubles)
- Story 9.1 (a member to act for)
- Story 9.10 (suspension)
- Story 9.12 (re-enrollment)
- Story 9.14 (recovery completion)

**References:**
- `doc/prd.md` FR-27
- `doc/architecture-spine.md` AD-11
- `doc/decisions.md` D113
- `doc/ai-safety.md` P3, I5, I18
- `doc/capability-matrix.md` section 1 (create or revoke a capability token), section 11
