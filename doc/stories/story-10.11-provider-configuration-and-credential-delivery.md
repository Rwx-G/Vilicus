---
title: 'Provider configuration and credential delivery'
epic: 10
story: 11
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-68, FR-55, FR-56, AD-25, AD-24, I4, D101]
---

# Story 10.11: Provider configuration and credential delivery

As an adult,
I want configuring a model provider to be a human-only action with a delay and a veto, and its API key to reach only the one process that uses it,
So that no single account, and no other process, decides where household data goes or reads the provider's credential.

**Acceptance Criteria:**

**AC1 (FR-68, D101)**
**Given** V0.1
**When** an adult configures a provider
**Then** it is reachable only through the Core API, exercised against the test double connector, never through a web screen
**And** it is an H action: a step-up by an adult, then a delay with a veto by each adult, never available to the instance admin role alone

**AC2 (FR-56)**
**Given** a provider configuration
**When** it is requested and when it takes effect
**Then** every adult receives the out-of-browser alert "a provider configured"
**And** the configuration is audited

**AC3 (FR-55, AD-25)**
**Given** a configured provider API key
**When** it is stored and used
**Then** it is stored encrypted in Core metadata and sent over the peer-verified socket only to the AI instance bound to that provider, which keeps it in memory only
**And** no module and no other process can read it

**AC4 (AD-24)**
**Given** an AI instance `vilicus-ai@<role>-<member>-<provider>`
**When** the Core binds its connection
**Then** its egress allowlist derives from its provider alone, and a token whose member or bound provider differs from the unit's triple is refused

**AC5 (I4)**
**Given** the AI double and the plugin double
**When** they open a direct outbound connection, request a host outside their allowlist, or request a named private destination
**Then** every attempt fails, and only allowlisted hosts through the egress proxy succeed

**Dependencies:**
- Story 10.10 (provider policy)
- Story 5.5 (egress proxy)

**References:**
- `doc/prd.md` FR-55, FR-56, FR-68
- `doc/architecture-spine.md` AD-16, AD-24, AD-25
- `doc/ai-safety.md` P7, I4
- `doc/capability-matrix.md` section 1 (configure a model provider)
- `doc/decisions.md` D101
