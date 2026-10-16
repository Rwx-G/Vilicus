---
title: 'Admin socket and CLI framework'
epic: 5
story: 6
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-3, AD-55, AD-8, FR-110]
---

# Story 5.6: Admin socket and CLI framework

As an operator,
I want a root-only CLI that reads every secret from an interactive prompt and lets the Core check passphrases,
So that host administration never leaks a secret through arguments, environment or files and never bypasses the Core.

**Acceptance Criteria:**

**AC1 (FR-3, AD-55)**
**Given** the `vilicus` CLI
**When** an operator runs `vilicus <noun> <verb>`
**Then** the command is sent to the Core over the root-only administration socket and its result printed in English
**And** run by a non-root user, the command fails because the socket cannot be opened

**AC2 (FR-3)**
**Given** a command that needs a passphrase, a recovery secret or the admin recovery code
**When** the secret is supplied
**Then** it is read only from an interactive prompt with echo off
**And** a test per input path shows that a secret given as an argument, an environment variable or a file is refused

**AC3 (FR-3, AD-8)**
**Given** a command that acts for a member
**When** the passphrase is typed
**Then** the CLI sends it to the Core, which verifies it; the CLI process never derives keys or decides authorization

**AC4 (FR-3, AD-55)**
**Given** the Gateway, AI, plugin and egress proxy units in the Debian 13 VM
**When** each tries to open the administration socket
**Then** every attempt fails (test)

**AC5 (FR-110)**
**Given** any CLI output or prompt
**When** it is shown
**Then** it is in English only, whatever the member's language setting

**Dependencies:**
- Story 5.3 (administration socket)

**References:**
- `doc/prd.md` FR-3, FR-110
- `doc/architecture-spine.md` AD-8, AD-55, Consistency Conventions (CLI)
