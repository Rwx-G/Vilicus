---
title: 'E24: passkeys and PWA with each naming option'
epic: 1
story: 4
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E24, FR-65, FR-4, D51, D76, D107, NFR-9]
---

# Story 1.4: E24: passkeys and PWA with each naming option

As the owner,
I want passkeys and PWA installation tested on every supported browser with each documented naming option,
So that the documentation only offers naming and certificate options that work, and the bootstrap order is confirmed.

**Acceptance Criteria:**

**AC1 (E24, FR-65, D51, NFR-9)**
**Given** three test instances under placeholder names: a free dynamic DNS subdomain with a DNS-01 certificate, a private-network name with its certificate, and a local certificate authority installed on each device
**When** passkey registration, passkey login and PWA installation run on current and previous Chrome and Firefox, desktop and Android (Safari best effort)
**Then** a result is recorded for every browser and naming option pair, with no real hostname, address or device model in the record

**AC2 (E24, FR-4, D76)**
**Given** a page served over a temporary self-signed certificate on a private address
**When** a WebAuthn registration ceremony is attempted from each supported browser
**Then** the record states whether the browser refuses it or binds the credential to a host that becomes unusable once the instance name exists
**And** either outcome confirms that the D76 order (no WebAuthn before the instance name) is required, and the order does not depend on it

**AC3 (E24, FR-65)**
**Given** a naming option fails on a supported browser
**When** the result is recorded
**Then** that option is marked for removal from the documentation in `doc/research-notes.md`, and the bootstrap order of D76 is unchanged

**Spike plan:**
- Question: which naming options support passkeys and PWA installation on each supported browser, and is WebAuthn over the temporary self-signed certificate refused or unusable (E24)?
- Method: three test instances under placeholder names, a browser matrix, a self-signed ceremony attempt.
- Pass criterion: a complete matrix; every naming option kept in the documentation works on every supported browser.
- Timebox: 5 working days.
- Fallback on failure: a naming option that fails is removed from the documentation; the bootstrap order of D76 does not change.
- Result record: matrix in `doc/research-notes.md` (E24 status moved per its section 5); a decision record for each option removed.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3.1 (E24)
- `doc/prd.md` FR-4, FR-65, section 9
- `doc/decisions.md` D51, D76, D107
- `doc/architecture-spine.md` AD-52, AD-19
- `doc/architecture.md` section 15
