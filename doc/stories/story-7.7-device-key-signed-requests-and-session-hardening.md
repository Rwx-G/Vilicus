---
title: 'Device key signed requests and session hardening'
epic: 7
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-15, FR-17, AD-21, D35, D90, E22]
---

# Story 7.7: Device key signed requests and session hardening

As a member,
I want every request from my browser signed by a key that cannot leave it,
So that a stolen session cookie alone is useless.

**Acceptance Criteria:**

**AC1 (FR-15, AD-21, D35)**
**Given** a browser completing pairing
**When** it registers with the Core
**Then** it holds a non-extractable ECDSA P-256 key created with WebCrypto, whose public key the Core registers and alone verifies

**AC2 (AD-21)**
**Given** a paired browser with a web session
**When** it sends a request
**Then** it signs SHA-256 of `vilicus/v1/req` concatenated with the session id, a counter that strictly increases per session, the method, the path and SHA-256 of the raw body
**And** the Core verifies the signature and the counter and checks that the CBOR request equals its own decoding of the raw body, refusing any mismatch or replayed counter

**AC3 (FR-17, D90)**
**Given** a web session
**When** its cookie is issued
**Then** it is `__Host-`, `HttpOnly`, `Secure` and `SameSite=Strict`
**And** the session ends after 15 minutes without activity and after 12 hours at most, with revocation checked by the Core on every request

**AC4 (FR-15, FR-17)**
**Given** a valid session cookie copied to another client without the device key
**When** that client sends requests
**Then** every request is rejected

**AC5 (FR-15)**
**Given** a browser whose data was cleared
**When** it returns to the instance
**Then** it is treated as unpaired

**AC6 (E22)**
**Given** E22 took its first fallback
**When** a session stays active
**Then** it is re-proven by a passkey assertion every 15 minutes of activity, and the member is told so

**AC7 (FR-17, D90)**
**Given** a web session that ended after 15 minutes without activity or after 12 hours
**When** the member returns on the same paired browser
**Then** a new session starts only after a passkey assertion
**And** the device key alone never re-opens a session

**Dependencies:**
- Story 7.6 (passkey login)
- Story 1.3 (E22 result)

**References:**
- `doc/prd.md` FR-15, FR-17
- `doc/architecture-spine.md` AD-21
- `doc/architecture.md` section 6
- `doc/decisions.md` D35, D90, D107
- `doc/research-notes.md` E22
