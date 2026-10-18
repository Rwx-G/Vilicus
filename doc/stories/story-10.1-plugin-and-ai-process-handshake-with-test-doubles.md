---
title: 'Plugin and AI process handshake with test doubles'
epic: 10
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-25, FR-109, AD-12, AD-24, D19, D102, I24, D125]
---

# Story 10.1: Plugin and AI process handshake with test doubles

As a project maintainer,
I want a plugin test double and an AI process test double that connect to the Core over their own sockets with the decided protocols,
So that the internal app interfaces of V0.1 are proven by executables that run like real plugins and AI processes, without shipping a half-built connector.

**Acceptance Criteria:**

**AC1 (FR-109, D102)**
**Given** the `testing/` tree of the workspace
**When** CI builds the test doubles
**Then** a plugin double and an AI process double exist as separate executables under `testing/`, never linked into the shipped `vilicus` binary
**And** in the CI Debian 13 VM they are installed as a `vilicus-plugin@<name>.service` instance and a `vilicus-ai@<role>-<member>-<provider>.service` instance, started and stopped by the Core through systemd

**AC2 (FR-25, AD-12, D19)**
**Given** the plugin double started by `vilicus-testbed`
**When** it connects to its Core peer socket
**Then** its first frame is a CBOR `Hello` carrying protocol, versions, unit and build, and the Core answers with the chosen version
**And** a first frame that is not a valid `Hello`, or a frame larger than the declared maximum, closes the connection before any decoding of the payload

**AC3 (FR-25, AD-12)**
**Given** the AI process double started by `vilicus-testbed`
**When** it connects to its Core peer socket
**Then** it speaks MCP (JSON-RPC 2.0) through `rmcp`, behind a framing layer that rejects a message above its maximum size before any parsing
**And** tool arguments are validated as closed types, unknown fields rejected

**AC4 (AD-24, D125)**
**Given** a process running under a unit other than the one a peer socket expects
**When** it connects to that socket
**Then** the Core identifies it by the peer identity method of Story 5.3 AC2 (its pid listed in `cgroup.procs` of the expected unit's cgroup, then its pidfd still alive, D125) and refuses the connection
**And** the refusal is audited

**AC5 (I24)**
**Given** the Gateway route table and every Core socket
**When** the I24 test runs
**Then** no Gateway route serves MCP, and an MCP request from a non-AI peer on any socket is refused
**And** MCP is served only on the peer sockets of Vilicus's own AI process units

**Dependencies:**
- Story 5.7 (packaged units, sockets and templates)
- Story 3.10 (reference module that the doubles call)
- Story 2.6 (`vilicus-testbed` and the `testing/` tree)

**References:**
- `doc/prd.md` FR-25, FR-109
- `doc/architecture-spine.md` AD-12, AD-24, AD-55
- `doc/decisions.md` D19, D102, D125
- `doc/ai-safety.md` section 3, I24
