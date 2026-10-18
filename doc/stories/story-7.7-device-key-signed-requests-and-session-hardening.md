---
title: 'Device key signed requests and session hardening'
epic: 7
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-15, FR-17, AD-21, D35, D90, E22, D122]
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

**AC2 (AD-21, D122)**
**Given** a paired browser with a web session
**When** it sends a request
**Then** it signs, with ECDSA P-256 and SHA-256 (WebCrypto `sign`, a 64-byte `r || s` signature), SHA-256 of the byte string fixed by D122: `vilicus/v1/req` (14 bytes), the 16-byte session id, the counter as 8 bytes big-endian, the length of the method as 4 bytes big-endian and the method, the length of the path with its query as 4 bytes big-endian and the path with its query, and SHA-256 of the raw body; the public key is the 65-byte uncompressed point of `exportKey('raw')`
**And** the Core verifies the signature (`ECDSA_P256_SHA256_FIXED`) and accepts a counter only above the last accepted one, a refused request not advancing it, and checks that the CBOR request equals its own decoding of the raw body, refusing any mismatch or replayed counter
**And** the client sends the signed requests of a session one at a time, in counter order, because two requests in flight can arrive out of order and the later counter then refuses the earlier one (tests as `ac1.concurrent_signed_requests_serialized` and its out-of-order control in `spikes/browser-device-key/`)

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
**Given** E22 took its first fallback (its desktop part passed without one, D122; Android is still to run, gate E22-1)
**When** a session stays active
**Then** it is re-proven by a passkey assertion every 15 minutes of activity, and the member is told so

**AC7 (FR-17, D90)**
**Given** a web session that ended after 15 minutes without activity or after 12 hours
**When** the member returns on the same paired browser
**Then** a new session starts only after a passkey assertion
**And** the device key alone never re-opens a session

**AC8 (D122, AD-21)**
**Given** a device public key to register, at enrollment or at pairing
**When** the Core registers it
**Then** it requires a proof of possession, an ECDSA signature by that key over `vilicus/v1/device-pop`, a length-prefixed context (the enrollment token or the pairing binding message) and the key, and refuses a registration whose proof is missing, zero or made by another key
**And** a session opened by the passkey login of AC7 is bound to the device key by a signature over `vilicus/v1/session`, the device id and a single-use Core nonce valid 60 seconds, refused when expired or presented for another device.

**AC9 (D122)**
**Given** the Core's session state
**When** the Core restarts
**Then** sessions, which live in the Core's memory, do not survive it, and the browser opens a new one as AC7 and AC8 state
**And** every lifetime (session challenges, nonces) is checked on a monotonic clock, and the Core never uses a signature as an identifier or a deduplication key, because ECDSA signatures are malleable (WebCrypto does not normalize `s` and aws-lc-rs accepts both forms); replay protection rests on the counter and single-use nonces.

**Dependencies:**
- Story 7.6 (passkey login)
- Story 1.3 (E22 result; D122)

**References:**
- `doc/prd.md` FR-15, FR-17
- `doc/architecture-spine.md` AD-21
- `doc/architecture.md` section 6
- `doc/decisions.md` D35, D90, D107, D122
- `doc/research-notes.md` E22
- `spikes/browser-device-key/` (`src/device.rs`, `src/core.rs`, `web/static/common.js`, `tests/core_flows.rs`)
- `doc/qa/gates/1.3-e22-browser-device-key-pake-and-signed-confirmations.yml` (E22-1)
