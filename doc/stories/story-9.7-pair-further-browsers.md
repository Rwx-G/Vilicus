---
title: 'Pair further browsers'
epic: 9
story: 7
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-16, AD-21, D35, D77, E22, FR-56]
---

# Story 9.7: Pair further browsers

As a member,
I want to pair another browser with a short-lived code from a paired device or from the host,
So that I can use Vilicus on a second device without a QR scan and without the code being usable by someone watching the network.

**Acceptance Criteria:**

**AC1 (FR-16, D35)**
**Given** a paired browser older than 24 hours
**When** the member asks it for a pairing code
**Then** the Core issues a code that is single use, expires after 2 minutes and allows 3 attempts
**And** a browser paired less than 24 hours ago is refused when it asks for a code

**AC2 (FR-16, D77, FR-56)**
**Given** root at the host
**When** `vilicus device pair <member>` runs with that member's own passphrase at the prompt
**Then** it prints a pairing code with the same limits, the passphrase of another adult is refused, and the member is notified on every paired device and on the out-of-browser notification channel

**AC3 (FR-16, AD-21)**
**Given** a valid code typed in the new browser
**When** pairing runs
**Then** OPAQUE (`opaque-ke` in the Core, its WASM build in the browser) binds the code to the new browser device key registration, so a party that observes or relays the traffic cannot use it
**And** the pairing page is a separate document whose CSP alone adds `'wasm-unsafe-eval'`

**AC4 (FR-56)**
**Given** a successful pairing from any source
**When** it completes
**Then** the member receives an out-of-browser alert stating how many passkeys and paired devices they now have, and the pairing is audited

**AC5 (E22)**
**Given** Story 1.3 recorded the PAKE fallback
**When** a paired device asks for a code
**Then** pairing codes are issued only by `vilicus device pair`, and the member web says so

**Dependencies:**
- Story 9.1 (a paired browser)
- Story 8.1 (out-of-browser alerts)

**References:**
- `doc/prd.md` FR-16, FR-56
- `doc/architecture-spine.md` AD-19, AD-21
- `doc/architecture.md` sections 6 and 7.3
- `doc/research-notes.md` E22
- `doc/decisions.md` D35, D77, D107
