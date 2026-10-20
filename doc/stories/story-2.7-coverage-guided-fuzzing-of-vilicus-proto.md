---
title: 'Coverage-guided fuzzing of vilicus-proto'
epic: 2
story: 7
status: ready-for-dev
author: Rwx-G
created: 2026-10-20
implements: [AD-12, AD-13, D130, E19]
---

# Story 2.7: Coverage-guided fuzzing of vilicus-proto

As a project maintainer,
I want the frame reader, the profile decoder and every closed-type decoder of `vilicus-proto` fuzzed with coverage guidance in CI,
So that the first component reading untrusted frames (Gateway, plugin, AI process and channel sockets, Epic 5 onward) does not rely on a fixed vector set alone.

**Context:** Story 2.5 replays a fixed set of 2 507 fuzzed inputs (`tests/data/canonical-cbor/fuzz.json`) and 90 hand-written non-canonical inputs. That proves agreement with the E19 verdicts, not that no other input crashes, loops or over-allocates. Its review found one memory amplification (a 16 MiB data frame decoding to 1.3 GB) by reasoning, not by test; this story makes that class of defect findable by a machine before any socket decodes a frame.

**Acceptance Criteria:**

**AC1 (AD-12, AD-13)**
**Given** the public decoding entry points of `vilicus-proto`
**When** the fuzz targets are listed
**Then** there is one target for each of: the frame reader for a control socket and for a data socket (length prefix and message), the D130 profile decoder on raw bytes, the bare `Hello` and `HelloReply` decoders, and the closed-type decoders of `vilicus-types` values (`Source`, every closed set, `ClientError`)
**And** a test fails when a public `decode`-like function of `vilicus-proto` has no target, so a new decoder cannot ship unfuzzed.

**AC2 (AD-13, D130)**
**Given** any input a target accepts
**When** the decoded value is encoded again
**Then** the bytes are equal to the accepted input (canonical round trip), and a decode never panics, never overflows the stack and never runs past the profile bounds (depth 32, item bounds of the socket kind)
**And** each target runs under a memory limit derived from the frame maximum and the item bound of its socket kind, so an amplification like the one of Story 2.5 fails the run.

**AC3 (E19)**
**Given** the committed E19 vectors
**When** a fuzz run starts
**Then** its seed corpus is built from `tests/data/canonical-cbor/` (corpus, invalid and fuzz files), never committed as a second copy
**And** every input a run finds failing is minimized and committed to a regression set under `crates/vilicus-proto/tests/data/` that `build-and-test` replays on the stable toolchain, with no fuzzing dependency.

**AC4 (D28)**
**Given** the merge gates of Story 2.2
**When** a pull request runs CI
**Then** a fuzz job runs every target for a short fixed budget and fails on any finding, and the weekly `schedule` trigger runs a longer budget
**And** the job is pinned like every other job (actions by SHA, toolchain by date, `contents: read`), and a finding on the schedule is reported, not silently retried.

**AC5 (D28, D29)**
**Given** the fuzzing tool chain
**When** it is added
**Then** it is approved by the owner before any code (no dependency without approval), it lives outside the shipped crates (a crate the workspace graph check of Story 2.1 refuses as a dependency of any `crates/*` member), its dependencies are vendored and pass `cargo deny`, `cargo vet` and `cargo audit`, and its licences are Apache-2.0 compatible
**And** if it needs a nightly toolchain, that toolchain is pinned by date in the fuzz job only; `rust-toolchain.toml` stays on stable.

**Dependencies:**
- Story 2.1 (crate graph check)
- Story 2.2 (merge gates, supply chain)
- Story 2.5 (the decoders under test and the E19 vectors)

**Must precede:** the first Epic 5 story that decodes a frame from a socket.

**Open choice at story start:** the tool. Recommended: `cargo-fuzz` with `libfuzzer-sys`, because it is coverage-guided, the RustCrypto and `rustls` projects use it, and a minimized crash is a plain file the regression replay reads. Gives up: a nightly toolchain in the fuzz job and a C++ runtime (libFuzzer) in the build of that job only. `proptest` alone runs on stable but is not coverage-guided, so it does not meet the intent of this story.

**References:**
- `doc/architecture-spine.md` AD-12, AD-13
- `doc/decisions.md` D28, D130
- `doc/research-notes.md` E19
- `doc/stories/story-2.5-wire-framing-and-canonical-encoding-in-vilicus-proto.md` (Result, review findings)
