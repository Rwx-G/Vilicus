---
title: 'Core process and execution model'
epic: 5
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [AD-9, AD-2, AD-22, E32, D1]
---

# Story 5.1: Core process and execution model

As an operator,
I want one `vilicus` executable whose subcommands run the Core and each first-party process, with the Core's threading model fixed,
So that the services start the same way everywhere and module work never stalls the kernel.

**Acceptance Criteria:**

**AC1 (AD-2, D1)**
**Given** the `vilicus` binary
**When** it is started with the subcommand of the Core, the Gateway, the audit writer or the egress proxy
**Then** it runs that process role only, in its own process
**And** an unknown subcommand exits with a non-zero status and a usage message in English

**AC2 (AD-9, E32)**
**Given** the Core process
**When** it starts
**Then** it runs an async runtime for I/O, one writer thread per open file, and a bounded blocking pool for CPU-heavy work (Argon2id, HPKE, copies, migrations), with the pool size and priorities set from the E32 result, its fallback applied if E32 took it
**And** module handlers run as synchronous functions on the file's writer thread, never on the async runtime (test: a handler that blocks does not delay an unrelated async request beyond a bound)

**AC3 (AD-9)**
**Given** the Core unit started by systemd
**When** the Core is ready to serve
**Then** it reports readiness through `sd-notify`
**And** it sends a `WatchdogSec=` keep-alive from its main loop, so a hung Core is restarted by systemd (test: block the loop, observe the restart)

**AC4 (AD-22)**
**Given** a host configuration
**When** the Core reads it
**Then** non-secret configuration comes from `/etc/vilicus/vilicus.toml`, where only the backup schedule, the certificate alert lead time and the audit spool size are tunable
**And** the Core never reads a secret from an environment variable or a command-line argument (test: a secret-shaped environment variable is ignored and a key option on the command line is rejected)

**Dependencies:**
- Story 3.9 (fault isolation on the writer thread)
- Story 1.15 (E32 result)

**References:**
- `doc/architecture-spine.md` AD-2, AD-9, AD-22
- `doc/decisions.md` D1, D113
- `doc/research-notes.md` E32
