---
title: 'Channel model against a channel test double'
epic: 10
story: 12
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-37, D42, D82, D103, I15, AD-50, FR-56, FR-107, FR-108, FR-14, FR-68]
---

# Story 10.12: Channel model against a channel test double

As a member,
I want secondary channels to be bound to me by a challenge and limited to a ceiling of data types,
So that a messaging account, even taken over, can reach only low-risk actions and low-risk data.

**Acceptance Criteria:**

**AC1 (FR-37, D42)**
**Given** a channel test double reporting a sender identity
**When** a binding is requested through the Core API
**Then** a binding exists only after a code sent to the sender on the channel is typed in the primary channel
**And** the sender identity declared by the plugin alone never creates a binding; the binding screens ship after V0.1

**AC2 (FR-37, I15)**
**Given** inbound messages from the channel double
**When** a message comes from an unbound sender or from a group conversation
**Then** it is dropped, never processed, and counted in the audit log

**AC3 (FR-37, I15)**
**Given** a message from a bound sender
**When** it is processed
**Then** the sender acts as the member and the content taints the AI session
**And** only tier 0 and tier 1 actions are reachable; tier 2, H actions, pairing, recovery and binding changes are refused

**AC4 (FR-37, AD-50, D82, D103)**
**Given** a channel ceiling stored in `core.db`
**When** it is created
**Then** it is an allowlist of data types that never contains `budget`, `mail_raw` or `health`, and excludes `presence`, `home_state`, `alarm_state`, `calendar` and `child` unless an adult adds one through an H action with a warning
**And** a new channel starts with the default ceiling `meals`, `meal_plan`, `shopping_list` and confirmations of the member's own journal entries (PRD assumption)

**AC5 (AD-50, I15)**
**Given** a session whose output may reach the channel
**When** a token is requested for it naming a data type outside the ceiling
**Then** issuance is refused (input gating)
**And** every outbound message is checked against the ceiling, a type absent from it is never sent, tested per data type with the default allowlist and after an adult adds a type

**AC6 (FR-56, D42)**
**Given** a sender identity bound, or a data type added to a channel ceiling, through the Core API
**When** it takes effect
**Then** every adult concerned receives the FR-56 out-of-browser alert and the change is audited

**AC7 (FR-107, FR-108, FR-14)**
**Given** a member with channel bindings
**When** the member is suspended, or completes a re-enrollment or a recovery without keeping a binding on the completion screen
**Then** the binding is revoked at once and messages from that sender are dropped as unbound

**AC8 (FR-37, FR-68)**
**Given** a bound member who sends their own data through the channel double
**When** it is processed
**Then** the write is accepted as that member and the call is routed under the provider policy of FR-68

**AC9 (FR-37, D42)**
**Given** a reply to a bound sender
**When** it is sent
**Then** it comes from a template or stays within the ceiling, passes the outbound content check, and points to the app for details

**Dependencies:**
- Story 10.10 (data type routing at token issuance)
- Story 9.10 (suspension)
- Story 9.12 (re-enrollment)
- Story 9.14 (recovery completion)

**References:**
- `doc/prd.md` FR-37
- `doc/architecture-spine.md` AD-50
- `doc/ai-safety.md` P7, I15
- `doc/capability-matrix.md` legend (secondary channels)
- `doc/decisions.md` D42, D82, D103
