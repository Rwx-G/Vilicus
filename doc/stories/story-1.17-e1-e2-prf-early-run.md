---
title: 'E1 and E2 PRF half: early run'
epic: 1
story: 17
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E1, E2]
---

# Story 1.17: E1 and E2 PRF half: early run

As the owner,
I want the WebAuthn PRF extension tried early on the household's real phones,
So that the later decision on PRF unlock is informed, without gating anything in V0.1.

**Acceptance Criteria:**

**AC1 (E1)**
**Given** a prototype app under `spikes/e1-e2-prf/` using the Android credential API (Credential Manager) with a platform and a roaming authenticator
**When** PRF is evaluated with the same salt across several sessions on each household phone
**Then** the record states whether the output is a stable 32-byte value per credential, without any phone model in the record

**AC2 (E2)**
**Given** a minimal server on `webauthn-rs` and a page on the supported browsers
**When** the PRF extension is requested at registration and assertion
**Then** the record states whether the library exposes PRF and whether each browser returns a reproducible output per credential

**AC3 (E1, E2)**
**Given** either result
**When** it is recorded
**Then** it gates nothing in V0.1, because PRF unlock comes after V0.1 and passphrase unlock is the V0.1 path

**Spike plan:**
- Question: does PRF work through the Android credential API (E1), and do `webauthn-rs` and the target browsers expose a reproducible PRF output (E2, PRF half)?
- Method: prototype app and minimal server and page, run on the household's real phones and the supported browsers.
- Pass criterion: stable 32-byte output per credential and salt across sessions.
- Timebox: 3 working days.
- Fallback on failure: passphrase unlock stays the only unlock path, which is already the V0.1 design.
- Result record: E1 and E2 PRF half status in `doc/research-notes.md`. Non-gating for V0.1.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E1, E2), section 1 (WebAuthn PRF), section 1.1 (WebAuthn library)
- `doc/prd.md` section 4.4, section 9
- `doc/key-management.md` section 3 (passkey wrapping details)
