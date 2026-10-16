---
title: 'Model connector interface and provider policy'
epic: 10
story: 10
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-68, AD-11, AD-15, D48, D80, D103, I22, I36, I43]
---

# Story 10.10: Model connector interface and provider policy

As an adult,
I want the Core to decide, per data type, which model provider may receive household data,
So that health, journal and budget data never leave the instance and no call silently falls back to another provider.

**Acceptance Criteria:**

**AC1 (FR-68, AD-15)**
**Given** the model connector interface
**When** the test double connector is built
**Then** it implements both connector kinds, completion and agent, and the AI double uses it through the interface only

**AC2 (FR-68, D48, D103)**
**Given** the closed data type set of `vilicus-types`
**When** the provider policy is evaluated per data type
**Then** a remote provider configured by an adult is allowed by default for `meals`, `meal_plan`, `stock` and `shopping_list`; `health`, `journal` and `budget` go to the local model only and no configuration widens them; every other type follows the strictest rule that applies

**AC3 (FR-68, AD-11, D80, I22)**
**Given** a token request whose readable record kinds carry a local-only data type
**When** the Core issues the token
**Then** the session's provider is bound at issuance to one allowed for every readable data type
**And** a tool result whose data type set the bound provider may not receive is refused, never downgraded or filtered silently

**AC4 (FR-68, I22)**
**Given** a call the policy routes to a provider that is not configured
**When** it is made
**Then** it fails closed with a notification, and the call graph has no fallback path to another provider

**AC5 (FR-68, I36)**
**Given** a record kind of the reference module
**When** its data is routed
**Then** the routing reads the stored `data_types` set of each record, declared by the record kind in the registry

**AC6 (FR-68, AD-15)**
**Given** the test double connector
**When** a request is sent
**Then** the body is built from an allowlisted set of parameters and the test asserts the exact body
**And** no connector enables a provider-side capability (server-executed tools, remote MCP or account connectors, response or file storage on the provider)

**AC7 (I22, I43)**
**Given** a derived record whose `data_types` set includes a local-only type
**When** it is returned to a session bound to a remote provider
**Then** it is refused

**Dependencies:**
- Story 10.5 (session taint and token issuance path)

**References:**
- `doc/prd.md` FR-68
- `doc/architecture-spine.md` AD-11, AD-15
- `doc/ai-safety.md` P10, I22, I36
- `doc/capability-matrix.md` section 1 (call a remote AI provider)
- `doc/decisions.md` D48, D80, D103
