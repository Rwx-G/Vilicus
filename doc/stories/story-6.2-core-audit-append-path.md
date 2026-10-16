---
title: 'Core audit append path'
epic: 6
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-31, FR-3, AD-17, AD-8, AD-13, NFR-2]
---

# Story 6.2: Core audit append path

As an adult,
I want every action, refusal, CLI command and authentication event recorded by the Core without sensitive parameters,
So that the household can review what happened without the log itself becoming a leak.

**Acceptance Criteria:**

**AC1 (AD-17)**
**Given** the Core and every other component
**When** an audit entry must be written
**Then** only the Core appends, through the append socket; no other component holds a path to the audit writer

**AC2 (FR-31, AD-8)**
**Given** an action, a refusal or an authentication event handled by the Core
**When** it completes or is refused
**Then** an entry is appended with the principal from the closed enum of AD-8 and the outcome
**And** a test drives each event kind implemented so far and finds one entry per event

**AC3 (FR-3)**
**Given** the CLI framework of Story 5.6
**When** any CLI command runs, including one that fails on a wrong passphrase or a refused authorization
**Then** an entry is appended with principal `Cli`, the command and the outcome

**AC4 (AD-13, NFR-2)**
**Given** an entry whose action has parameters
**When** it is built
**Then** the parameters appear only as the SHA-256 of their canonical CBOR encoding (AD-13), never in clear
**And** a seeded-secret test (passphrases, recovery secrets, tokens, record content) inspects every entry and every log line produced and finds none of the seeded values

**Dependencies:**
- Story 6.1 (audit writer)
- Story 5.6 (CLI framework)

**References:**
- `doc/prd.md` FR-3, FR-31, section 7 (Privacy)
- `doc/architecture-spine.md` AD-8, AD-13, AD-17
- `doc/architecture.md` section 14
- `doc/ai-safety.md` P9
