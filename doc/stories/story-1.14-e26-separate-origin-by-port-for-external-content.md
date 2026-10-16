---
title: 'E26: separate origin by port for external content'
epic: 1
story: 14
status: draft
author: Rwx-G
created: 2026-10-16
implements: [E26, AD-19, FR-17, FR-52, NFR-9]
---

# Story 1.14: E26: separate origin by port for external content

As the owner,
I want the port-based separate origin for sandboxed external content tested with each naming option and with reverse proxies,
So that external content is rendered in isolation, or shown only as sanitized plain text.

**Acceptance Criteria:**

**AC1 (E26, AD-19, FR-17, NFR-9)**
**Given** a prototype under `spikes/e26-origin/` serving the client on the instance name and external content from the same name on a separate port, in a script-less sandboxed iframe
**When** it runs with each FR-65 naming option (placeholder names) on current and previous Chrome and Firefox, desktop and Android (Safari best effort)
**Then** the iframe renders, cannot run script, and cannot reach the client's origin

**AC2 (E26, AD-19, FR-52)**
**Given** the content origin's CSP forbids every subresource and every form
**When** a hostile test page tries images, styles, fonts, frames, forms and links that auto-load
**Then** every attempt is blocked and reported

**AC3 (E26, AD-19)**
**Given** the same setup behind a reverse proxy terminating TLS for both ports
**When** the tests of AC1 and AC2 run again
**Then** results are recorded per proxy configuration
**And** if a port-based origin is not workable, the fallback (sanitized plain text, never HTML) is recorded in `doc/decisions.md`

**Spike plan:**
- Question: does a separate origin by port work for sandboxed external content with each naming option and with reverse proxies (E26)?
- Method: prototype client and content origin; browser and naming option matrix; hostile page; reverse proxy runs.
- Pass criterion: isolation and CSP blocking hold on every supported browser with every naming option kept in the documentation.
- Timebox: 3 working days.
- Fallback on failure: external content shown as sanitized plain text, never as HTML.
- Result record: E26 status in `doc/research-notes.md`; a decision record if the fallback is taken.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3.1 (E26)
- `doc/architecture-spine.md` AD-19
- `doc/architecture.md` section 6 (content security policy)
- `doc/prd.md` FR-17, FR-52, FR-65, section 9
