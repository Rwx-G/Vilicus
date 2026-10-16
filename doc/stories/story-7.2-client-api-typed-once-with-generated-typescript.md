---
title: 'Client API typed once with generated TypeScript'
epic: 7
story: 2
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-14, FR-50]
---

# Story 7.2: Client API typed once with generated TypeScript

As a project maintainer,
I want every client request, response and error type defined once in Rust and generated for the web client,
So that the front end and the Core can never drift on request shapes.

**Acceptance Criteria:**

**AC1 (AD-14)**
**Given** the client API under its versioned prefix
**When** a request, response or error type is added
**Then** it is defined only in `vilicus-proto`
**And** the TypeScript types are generated from it, never written by hand

**AC2 (AD-14)**
**Given** a change to a `vilicus-proto` client type
**When** CI runs without regenerating the TypeScript types
**Then** the check that the generated types are current fails the merge

**AC3 (AD-14, FR-50)**
**Given** any request the Core refuses
**When** the client receives the error
**Then** it carries a stable error code, a message key and a retry class (`retryable`, `not_retryable`, `unknown_outcome`)
**And** never an internal message or a stack trace

**AC4 (AD-14)**
**Given** the route table of the client API
**When** a test enumerates every GET endpoint and calls it
**Then** no GET endpoint changes any state

**Dependencies:**
- Story 7.1 (Gateway translating HTTPS JSON into CBOR)
- Story 2.5 (`vilicus-proto` types and framing)

**References:**
- `doc/architecture-spine.md` AD-14, AD-19, Consistency Conventions (Errors)
- `doc/prd.md` FR-50
