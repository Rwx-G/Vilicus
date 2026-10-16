---
title: 'Remote audit sink'
epic: 11
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-32, FR-50, FR-56, AD-17, D40, D106, DC-7, DC-61]
---

# Story 11.6: Remote audit sink

As an instance admin,
I want to configure a remote sink that receives the audit head hash on a fixed timer,
So that tampering by root on the host is detected for every entry older than the last head hash sent.

**Acceptance Criteria:**

**AC1 (FR-32, FR-50, FR-56)**
**Given** the instance admin web
**When** the instance admin sets a sink URL such as `https://sink.example.com/vilicus` and approves with a step-up bound to that configuration
**Then** the sink is stored as Core metadata and every adult is notified on the out-of-browser notification channel
**And** an audit entry records the change

**AC2 (FR-32, AD-17, D106)**
**Given** a configured sink
**When** 15 minutes pass (spine assumption) or the Core shuts down
**Then** the Core sends through the egress proxy an HTTPS POST of a CBOR record carrying the head hash, its sequence number, the latest backup sequence number and the latest manifest hash
**And** it sends on schedule whether or not anything was audited, never per audited event

**AC3 (FR-32, D40)**
**Given** a configured sink and root rewriting an audit entry older than the last head hash sent
**When** `vilicus audit verify` runs against the head hashes recorded by the test sink
**Then** the tampering is detected

**AC4 (FR-32)**
**Given** an unreachable sink
**When** deliveries fail
**Then** head hashes are queued and retried
**And** past the retry limit every adult is alerted

**AC5 (FR-32)**
**Given** a configured sink
**When** a member opens the audit view
**Then** the current head hash is shown for information only

**Decision tasks:**
- [ ] Decide the confirmation level for configuring or changing the remote sink. Recommended: a step-up bound to the configuration with every adult notified, as FR-50 states, since a wrong sink silently weakens the root-tamper claim. Gives up: nothing material.

**Dependencies:**
- Story 6.4 (audit verify)
- Story 8.1 (out-of-browser notification stage)
- Story 7.6 (action-bound step-up)

**References:**
- `doc/prd.md` FR-32, FR-50
- `doc/architecture-spine.md` AD-17, AD-31
- `doc/architecture.md` sections 14, 17
- `doc/decisions.md` D40, D106
