---
title: 'E13: push delivery reliability'
epic: 1
story: 13
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E13, FR-56, D105, D118, AD-32]
---

# Story 1.13: E13: push delivery reliability

As the owner,
I want content-free push alerts measured on each household phone for a week,
So that the veto window and the recovery alerts rest on a channel that actually delivers.

**Acceptance Criteria:**

**AC1 (E13, FR-56, AD-32, D118)**
**Given** a sender under `spikes/e13-push/` posting content-free alerts (one generic text, no title, sender or detail) through the push webhook to two UnifiedPush servers of the ntfy type: the default self-hosted server, reached through a named private destination (D105), and a public server, each with a topic protected by an access token or a random name of at least 128 bits
**When** it sends alerts at random times, idle nights included, to each household phone for 7 days on each server, and each phone records the reception time
**Then** the delivery delay of every alert is recorded per phone and per server, labelled only as self-hosted or public, without any phone model or server name in the record

**AC2 (E13, D105)**
**Given** the recorded delays
**When** they are evaluated per phone
**Then** a server passes only if 99 % of alerts were delivered within 10 minutes over the 7 days on every phone, and the result is recorded for each server; E13 as a whole passes when the default self-hosted server passes, and a public server below the threshold is documented as not recommended without failing E13

**AC3 (E13, D105)**
**Given** a phone falls below the threshold
**When** the result is recorded
**Then** the fallback is recorded in `doc/decisions.md`: a second push distributor within the same webhook transport, plus the maximum waits of FR-56; polling is never the only path

**Spike plan:**
- Question: is a persistent connection or UnifiedPush reliable enough for content-free notifications on Android (E13)?
- Method: content-free alerts through the push webhook to each household phone for 7 days, idle nights included, on the default self-hosted UnifiedPush server and on a public server (D118).
- Pass criterion: 99 % of alerts delivered within 10 minutes over 7 days per phone (D105).
- Timebox: 2 working days of setup plus 7 days of observation.
- Fallback on failure: a second push distributor within the same webhook transport, plus the maximum waits of FR-56; never polling as the only path.
- Result record: E13 status in `doc/research-notes.md` with per-phone delivery rates under anonymous labels.
- Push server: settled by D118 (PRD open question 8, resolved): a self-hosted server by default, a public one when the household chooses it; a public server sees only delivery timing metadata. No phone model or server name is written in the results.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E13)
- `doc/prd.md` FR-56, section 9, section 11 (open question 8, resolved)
- `doc/decisions.md` D105, D118
- `doc/architecture-spine.md` AD-32
