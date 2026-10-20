---
title: 'Coverage-guided fuzzing of vilicus-proto'
epic: 2
story: 7
status: review
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

## Implementation Notes

**What was built**
- `fuzz/`: `vilicus-fuzz`, a workspace member that no crate may depend on (below). It inherits the workspace lints, so unsafe code is forbidden in it too. `src/lib.rs` holds every target as a `Target` (name, socket kind, input shape, the public decoders it reaches, and a check over raw bytes that panics when an input breaks an invariant); each target is a binary of `src/bin/` named after it, declared by one macro call. With the optional `libfuzzer` feature the binary is a libFuzzer entry point (`libfuzzer_sys::fuzz_target!`); without it, on stable, it replays the files and directories it is given. `src/bin/fuzz-plan.rs` prints each target's plan (name, input shape, longest input, memory limits) as JSON lines, and with `seeds <dir>` writes every target's seed corpus.
- The targets and their checks:
  - `frame_control` and `frame_data`: a stream of frames read with `frame::read_message` as `Message<Body, Source>`, frame after frame. An accepted message frames back (`frame::write_message`) to exactly the bytes consumed, and its value stays within depth 32 and the item bound of the socket kind (`assert_within_bounds`, iterative). A `TooLarge` refusal consumed the four prefix bytes alone. `Body` is a stand-in request body with a reading and a writing request, so both `call_id` rules are fuzzed; the bodies of real protocols come with their stories.
  - `frame_control_repeated` and `frame_data_repeated`: the same check on one frame whose message `expand` builds from a count, a prefix and a unit: the prefix, then an array of the unit repeated up to the count, or as many times as fit the frame maximum. An array of many small items is how a frame amplifies in memory (Story 2.5's review). From a raw stream a fuzzer seldom reaches a large frame whose item count matches its head; here a few bytes describe one.
  - `profile`: `profile::decode_with_max_items` under the control item bound. An accepted input passes `scan_heads`, `check_value` and `require_round_trip`, encodes back to its bytes, decodes to the same value unbounded, and the bound holds exactly at its item count. A refusal other than `TooManyItems` is the same refusal unbounded; the unbounded decoder never runs on an input the bound refused.
  - `hello`: `message::first_frame` on both socket kinds and `wire::decode::<Hello>`; an accepted `Hello` round-trips and negotiates its own highest version, and a refusal is `not_hello`.
  - `hello_reply`: `wire::decode_with_max_items::<HelloReply>` under the control item bound.
  - `closed_types`: one profile decode, then `from_cbor` of every type with a `Wire` implementation in `vocabulary.rs` and `wire.rs` (`Source`, every closed set, `ClientError`, the dotted names, `Id`, `UtcMillis`, `HelloRefusal`, `bool`, the integers, `String`, `Vec`); an accepted value round-trips. The types and the calls come from one macro invocation, which also produces `CLOSED_TYPES`.
- Memory limits, derived per target from its socket kind (`Target::malloc_limit_mib`, `rss_limit_mib`):
  - one allocation of twice the frame maximum plus one MiB fails the run (3 MiB control, 33 MiB data). Every buffer a decode needs holds one message, with the slack of a growing buffer; a larger one is reserved from a declared length, or is a vector of items amplifying past the frame. libFuzzer checks this limit on each allocation, so it is deterministic and the input alone reproduces it;
  - peak resident memory fails the run above a runtime allowance plus three times the decode budget, which counts four copies of the largest message and 256 bytes per item at the item bound (Story 2.5 measured at most 215): 316 MiB control, 640 MiB data. libFuzzer checks it once a second; it catches an amplification made of many small allocations.
- Seeds and regressions: `fuzz-plan seeds` reads every `items[].hex` of `corpus.json`, `invalid.json` and `fuzz.json` in `crates/vilicus-proto/tests/data/canonical-cbor/` in place (2 619 distinct inputs), shapes each one for the target (the message, one frame holding it, or an array holding it once), and adds the target's committed failing inputs from `crates/vilicus-proto/tests/data/fuzz/<target>/`. `tests/regressions.rs` replays those inputs and every seed through their checks on stable; `tests/coverage.rs` is the AC1 check.
- `ci/fuzz.py`: reads the plan, builds every target with `cargo +<nightly> build --frozen --config ci/cargo-vendored.toml --features libfuzzer --release --target x86_64-unknown-linux-gnu` and the RUSTFLAGS cargo-fuzz 0.13.2 passes for its default build (sancov, trace-compares, `--cfg fuzzing`, AddressSanitizer, debug assertions, one codegen unit), writes the seeds into a scratch directory, and runs each target for the given time under its limits, with `-timeout=60`. A failing target is reported with its input printed as hex (the first 4 KiB, its size and SHA-256), a crash or a timeout minimized, and the path to commit it under. The script exits 1 after running every target and never retries.
- `.github/workflows/ci.yml`: the `fuzz` job, pinned like the others (checkout by SHA, `permissions: contents: read` at workflow level), installs `nightly-2026-10-01` (rustc 1.101.0-nightly 21b707e3f, 2026-09-30) with the minimal profile and runs `ci/fuzz.py` for 60 seconds per target on pull requests, pushes, the merge queue and manual runs, and 1 200 seconds per target on the weekly `schedule`. On failure only, `actions/upload-artifact` (the SHA the `vm-smoke` job already uses) keeps the failing inputs. `WorkflowAgreementTest` pins the job: its check name and commands, a dated nightly named by this job alone and not by `rust-toolchain.toml`, a scheduled budget longer than the other one, and the upload as its only conditional step.
- Crate graph (AC5): `ci/crate_graph.toml` gains `[isolated.fuzz]` (`vilicus-fuzz`, path `fuzz`, `depends_on = ["proto"]`). `ci/check_workspace.py` classifies isolated crates before the nodes (exact name, then directory), refuses any edge to one, from any crate and of any kind, refuses an edge from one beyond what its nodes reach or to a private node it does not list, and refuses a crate under its directory that it does not list. `fuzz` joins the directories whose manifests must be members and where no `.cargo` configuration may sit.
- Supply chain: `libfuzzer-sys =0.4.13` in `[workspace.dependencies]`, optional in `vilicus-fuzz`. `Cargo.lock` grows from 83 to 86 packages (`libfuzzer-sys`, `arbitrary` 1.5.0, `vilicus-fuzz`); `cc` 1.9.0 and `jobserver`, its build dependencies, were already in the tree. `vendor/` gains the two crates (941 KB). `deny.toml` allows `NCSA` for `libfuzzer-sys@0.4.13` alone, as a licence exception; `ci/build_time_code.toml` lists its build script; `supply-chain/config.toml` gives `vilicus-fuzz` a `safe-to-run` policy and exempts `libfuzzer-sys` 0.4.13 and `arbitrary` 1.5.0 at those exact versions, with notes like those of the other exemptions. There is no `[[trusted]]` entry.
- `vilicus-proto` (the finding, below): `read_frame` reads into a buffer that holds 64 KiB at first and doubles only once its bytes have arrived, never past the declared length, instead of `take(len).read_to_end`.

**Decisions and why**
- *A workspace member behind an optional feature, not a separate workspace.* As a member, `vilicus-fuzz` and its dependencies are in the one `Cargo.lock`, so `vendor/`, `cargo deny` (all features, all platforms), `cargo vet`, `cargo audit` and `ci/check_supply_chain.py` cover them with no second lockfile, vendor sync or second run of each gate. `libfuzzer-sys` is optional and only the fuzz job enables the feature, so the stable jobs never compile libFuzzer, and `build-and-test` builds and replays the fuzz crate without any fuzzing dependency. What it gives up: the stable jobs compile `vilicus-fuzz` itself (seconds), and the crate graph check needed the isolated table, since every member must match it.
- *libFuzzer driven by `ci/fuzz.py`, not by the cargo-fuzz CLI.* `cargo fuzz build` runs `cargo build` itself and accepts neither `--frozen` nor `--config`, and Cargo reads no source replacement from the environment (tried: `CARGO_SOURCE_*` variables are ignored), so it would build from crates.io instead of `vendor/`. The script passes the flags cargo-fuzz 0.13.2 passes for its default build, read from its `src/project.rs`, and runs the binaries with libFuzzer's own options. What it gives up: when the nightly date moves, the flags are checked by hand against cargo-fuzz. The owner approved cargo-fuzz; it is installed nowhere.
- *Two limits rather than one.* Peak resident memory alone did not separate a control-frame amplification from the noise of a long run. With AddressSanitizer's default allocation context of 30 frames, the process keeps every distinct allocation stack, and a 10-minute run of `profile` grew from 113 to 275 MiB with no input holding more than a few MiB; `malloc_context_size=2`, now in `ASAN_OPTIONS`, keeps it at 106 MiB. The repetition targets still reach about 220 MiB on control frames, freed memory staying mapped. The unbounded control amplification adds 182 MiB, too close to that; its first large allocation, a 4 MiB vector of items, fails the allocation limit at once.
- *Allocation limit at twice the frame maximum.* The largest allocation a valid data frame makes is 20 MiB (one 16 MiB byte string, measured, Result), so the frame maximum alone would fail valid inputs. The amplifications the limit is for reserve 4 MiB (control) and 64 MiB (data) and keep growing.
- *Repetition targets.* Coverage guidance does not reward size, and libFuzzer grows inputs slowly: in 60-second runs on a build without the item bound, the raw frame targets did not reach the amplification, the repetition targets did within seconds.
- *Nightly date.* `nightly-2026-10-01`, 19 days old, builds the workspace (edition 2024, rust-version 1.99.0) and ships the AddressSanitizer runtime for x86_64 Linux in its minimal profile. `rust-toolchain.toml` stays on 1.99.0.
- *Isolation outside the AD-3 nodes.* An isolated crate is not a node, so the flowchart and `SpineAgreementTest` are unchanged; AD-3 itself says nothing of fuzzing (Open points).

**Files**
- `fuzz/Cargo.toml`, `fuzz/src/lib.rs`, `fuzz/src/bin/` (8 targets and `fuzz-plan.rs`), `fuzz/tests/coverage.rs`, `fuzz/tests/regressions.rs`
- `crates/vilicus-proto/src/frame.rs`, `crates/vilicus-proto/tests/data/fuzz/` (2 inputs)
- `ci/fuzz.py`, `ci/test_fuzz.py` (new); `ci/check_workspace.py`, `ci/crate_graph.toml`, `ci/test_check_workspace.py`, `ci/test_check_supply_chain.py`, `ci/build_time_code.toml`, `.github/workflows/ci.yml`
- `Cargo.toml`, `Cargo.lock`, `deny.toml`, `supply-chain/config.toml`, `vendor/` (2 crates)
- `doc/stories/sprint-status.yaml` (2.7 to `review`)

**Finding**
- *`read_frame` reserved twice the frame.* `take(len).read_to_end` doubles its buffer to probe for the end of the stream: a 16 MiB data frame took a 32 MiB allocation, a 1-byte frame a 33-byte buffer. It showed while setting the allocation limit, when the worst-case data frames of Story 2.5 (one byte string or text of 16 MiB) failed the frame targets at `malloc(33554432)`. Bounded by the frame maximum, so not an amplification, but a peer sending maximum frames made the reader hold twice what it reads. Fixed in `vilicus-proto` (`fix(proto)` commit). `frame::tests::a_frame_is_read_into_a_buffer_no_larger_than_its_length` reads, for each socket kind, frames of 0, 1, 64 KiB, 64 KiB + 1, half the maximum + 1 and the maximum, at once and one byte at a time, into a buffer whose capacity is their length; it fails on the previous code (capacity 33 for 1 byte).
- No other finding: no panic, stack overflow, timeout or memory limit on the real code in any run (Result).

**Deviations**
- *AC3, "every input a run finds failing is minimized".* A crash or a timeout is minimized by libFuzzer (`-minimize_crash=1`). An out-of-memory input is kept as found: the resident limit is checked once a second, so a single run of the input may end before the check, and minimization cannot tell it from a passing input. The amplification inputs are a few bytes anyway.
- *AC3, the regression set.* No run on the real code found a failing input. The two committed inputs (`amplification-without-item-bound`, 10 and 11 bytes) are what the repetition targets found within seconds on a build of `vilicus-proto` without the item bound of Story 2.5. On the real code they are refused by that bound, and they seed every run, so removing the bound fails the fuzz job at its first second. The regression of the finding above is a unit test in `vilicus-proto`, since the inputs that showed it are 16 MiB frames.
- *AC2, memory under replay.* `build-and-test` replays the committed inputs for the round trip and the bounds; it measures no memory. The limits apply in the `fuzz` job, which seeds every run with those inputs.
- *AC1, what counts as a decoder.* `tests/coverage.rs` reads `vilicus-proto/src` outside its test modules: every public function with a `&[u8]`, `Vec<u8>` or `impl Read` parameter, as `module::function`, and every public type with a `Wire` implementation, those written by `macro_rules!` included. `NOT_DECODERS` lists the three that take bytes without decoding them, each with its reason: `frame::write_frame`, `CanonicalBytes::from_stored` and `CanonicalBytes::matches_hash`. A source scan this small can be fooled by unusual formatting; it also fails when a name a target declares is not found, so it cannot silently find nothing.
- *AC4, "fails on any finding".* The job fails on a finding; making it a required check is a branch-protection setting outside the repository.

**Open points**
- *AD-3 wording.* The spine's AD-3 says dependencies follow the graph "and nothing else" and does not mention the fuzz crate. Proposed addition, for the coordinator to apply in the authoring copy: "`vilicus-fuzz` (`fuzz/`, Story 2.7) is outside the graph: it depends on `vilicus-proto`, and the CI check refuses any dependency on it." Not applied here.
- *Stack table.* The spine's Stack table names neither `libfuzzer-sys` 0.4.13 nor the fuzz job's nightly; `WorkflowAgreementTest` checks only that the nightly is dated and used by the fuzz job alone.
- *Required check.* The owner adds `Coverage-guided fuzzing of vilicus-proto (D130)` to the required checks.
- *Owner review.* The `NCSA` exception and the two exemptions record that the crates were not reviewed here (`cargo vet` suggests a diff of 39 files from `libfuzzer-sys` 0.4.7 and of 12 files from `arbitrary` 1.4.2).
- *No corpus between runs.* Every run starts from the seeds; what a weekly run learns is discarded. A cached corpus would let runs build on each other, at the cost of cache content no gate reviews.
- *Bodies of later protocols.* The frame targets decode a stand-in `Body`. Each story that defines the request and response types of a socket adds them to a target, which `tests/coverage.rs` enforces for every public `Wire` type of `vilicus-proto`.
- *Not run on GitHub.* The job ran locally only, in the pinned image with the nightly added; the runner's C++ compiler and the nightly's AddressSanitizer runtime on `ubuntu-24.04` are untested until the first push.
- *Story 2.5 text.* Its notes describe `read_frame` with `take(len).read_to_end`; they are history and were not edited.

## Result

All commands ran on 2026-10-20 in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Docker Desktop on Windows, 24 cores), `rustc 1.99.0`, with `nightly-2026-10-01` (`rustc 1.101.0-nightly (21b707e3f 2026-09-30)`) for fuzzing, cargo-deny 0.20.2, cargo-vet 0.10.2 and cargo-audit 0.22.2. The gates ran on a fresh clone of the branch made inside the container; fuzzing and mutations ran on copies, never on the working tree.

Gates, as `.github/workflows/ci.yml` runs them:

- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings`: exit 0.
- `cargo build --workspace --frozen --config ci/cargo-vendored.toml`: exit 0; `libfuzzer-sys` is not compiled.
- `cargo test --workspace --frozen --config ci/cargo-vendored.toml`: 122 tests passed, none failed. In `vilicus-fuzz`, 5 unit tests, 4 coverage tests and 3 regression tests; in `vilicus-proto`, 48 unit tests (one new), 10 vector tests and 1 doctest.
- `python3 -m unittest discover -s ci`: `Ran 182 tests`, `OK` (162 before; new: 7 in `IsolatedTest`, 3 fuzz-job tests in `WorkflowAgreementTest`, 10 in `ci/test_fuzz.py`).
- `python3 ci/check_workspace.py`: `workspace checks passed: 19 crates`.
- `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 86 packages`. Before the allowlist entry it named `libfuzzer-sys 0.4.13 has a build script`.
- `python3 ci/check_supply_chain.py --vendor`: `vendor check passed`.
- `python3 ci/check_packaging.py`: `packaging check passed: 1 release artefacts, none built from or linking the 6 never-packaged crates`.
- `python3 ci/release_gates.py check`: `release gates declared: 2 package, 1 testbed`.
- `cargo deny --locked check`: `advisories ok, bans ok, licenses ok, sources ok`. Before the exception: `licenses FAILED` on `(MIT OR Apache-2.0) AND NCSA`.
- `cargo vet --locked`: `Vetting Succeeded (13 fully audited, 4 partially audited, 50 exempted)`. Before: `2 unvetted dependencies` (`arbitrary:1.5.0`, `libfuzzer-sys:0.4.13`).
- `cargo audit --json`, judged by `python3 ci/check_audit_report.py ci/audit-exceptions.toml`: `audit report passed: no vulnerability, 1 warning(s), each a listed exception`.

Fuzzing the real code, `python3 ci/fuzz.py --toolchain nightly-2026-10-01 --seconds 600 --target <name>`, one process per target, the eight at once, under the limits of the plan. Every run printed `no finding` and exited 0:

| Target | Executions | Coverage (edges) | Peak RSS | RSS limit | Allocation limit |
|---|---|---|---|---|---|
| `frame_control` | 11 162 757 | 1 540 | 112 MiB | 316 MiB | 3 MiB |
| `frame_data` | 11 943 356 | 1 546 | 110 MiB | 640 MiB | 33 MiB |
| `frame_control_repeated` | 319 801 | 1 436 | 220 MiB | 316 MiB | 3 MiB |
| `frame_data_repeated` | 131 735 | 1 400 | 332 MiB | 640 MiB | 33 MiB |
| `profile` | 6 424 836 | 1 477 | 104 MiB | 316 MiB | 3 MiB |
| `hello` | 5 279 175 | 1 483 | 105 MiB | 640 MiB | 33 MiB |
| `hello_reply` | 14 789 994 | 1 443 | 101 MiB | 316 MiB | 3 MiB |
| `closed_types` | 14 258 532 | 1 897 | 106 MiB | 316 MiB | 3 MiB |

Before that run: two 10-minute calibration runs of every target without a resident limit (the first with AddressSanitizer's default allocation context, the second with two frames), a 5-minute sequential run of the first targets, and short runs of all of them. No crash, no timeout, no stack overflow. The one out-of-memory report among them was the calibration problem of Decisions: `frame_control_repeated` at 190 MiB against a first limit of 188 MiB, on a 145-byte input whose own decode peaks at 58 MiB.

Worst-case frames at each bound (the shapes of Story 2.5), each run once through `frame_control` or `frame_data` with `ASAN_OPTIONS=quarantine_size_mb=16:malloc_context_size=2:detect_leaks=0`. Peak RSS, the process alone holding 33 MiB:

| Shape | Control | Data |
|---|---|---|
| array of zeros at the item bound | 50 MiB | 85 MiB |
| map at the item bound | 63 MiB | 130 MiB |
| byte strings filling the frame | 65 MiB | 191 MiB |
| texts filling the frame | 69 MiB | 194 MiB |
| one byte string of the frame | 41 MiB | 130 MiB |
| one text of the frame | 45 MiB | 149 MiB |
| zeros filling the frame (over the bound, refused) | 36 MiB | 100 MiB |

Each passes under the plan's limits. With the allocation limit at the frame maximum plus one MiB, the data frames of byte strings, of texts and of one byte string failed at `malloc(18087936)` and `malloc(20971520)`; before the `read_frame` fix, every frame at the maximum failed at twice its size.

Mutations, each on a copy:
- `read_message` decoding with `usize::MAX` instead of the item bound, as Story 2.5 did before its review. Zeros filling the frame then peak at 215 MiB (control) and 2 091 MiB (data), and fail the allocation limit at `malloc(4194304)` and `malloc(67108864)`. Without the committed regression inputs, `ci/fuzz.py --seconds 60` on the two repetition targets fails both: `frame_control_repeated` at execution 2 785, on the 9-byte input `001300000000000000` (allocation limit), and `frame_data_repeated` at execution 5 836, on a 16-byte input (`used: 891Mb; limit: 640Mb`); the raw frame targets found nothing in the same time. With the committed inputs, both targets fail on their seeds. The two committed inputs, `008000010000000081a0` and `250000010000000062d697`, come from an earlier 60-second run of the same mutation.
- A public `decode_header(bytes: &[u8])` added to `frame.rs` and a public `Extra` type with a `Wire` implementation added to `message.rs`: `tests/coverage.rs` fails with `public decoders without a fuzz target: ["frame::decode_header"]` and `Wire types without a fuzz target: ["Extra"]`.
- The new `read_frame` test on the previous code: `Control frame of 1 bytes`, capacity 33 instead of 1.

| Criterion | Result | Tests and observed outcome |
|---|---|---|
| AC1 (AD-12, AD-13) | **Pass** | One target per entry point: `frame_control` and `frame_data` (`read_frame`, `read_message`, `Message`, `Request`, `Response`: length prefix and message), with their repetition forms; `profile` (`decode`, `decode_with_max_items`, `scan_heads`, `require_round_trip`); `hello` (`first_frame`, `wire::decode`, `Hello`); `hello_reply` (`HelloReply`); `closed_types` (`Source`, every closed set, `ClientError`, and every other `Wire` type of `vocabulary.rs` and `wire.rs`). `tests/coverage.rs`: `every_public_function_reading_bytes_has_a_target_or_a_reason`, `every_public_wire_type_is_decoded_by_a_target`, `every_declared_decoder_and_reason_names_an_entry_point`, `every_target_has_its_binary_and_every_binary_a_target`; the mutation above turns the first two red. |
| AC2 (AD-13, D130) | **Pass** | Every check asserts the canonical round trip of an accepted input and the depth and item bounds of its value (`assert_within_bounds`, iterative); a panic, a stack overflow (AddressSanitizer), a 60-second timeout or a memory limit fails the run. Limits derived from `SocketKind::max_message_len` and `max_items` (`fuzz-plan`): 3 MiB per allocation and 316 MiB resident for the control targets, 33 MiB and 640 MiB for the data targets. The Story 2.5 amplification fails both socket kinds (mutation above); worst-case valid frames pass (table). One finding, fixed in `vilicus-proto`. |
| AC3 (E19) | **Pass** | Seeds read in place from `corpus.json`, `invalid.json` and `fuzz.json` (2 619 inputs per target) by `fuzz-plan seeds`, written to a scratch directory, never committed. Failing inputs committed under `crates/vilicus-proto/tests/data/fuzz/<target>/` and replayed by `tests/regressions.rs` (`every_committed_failing_input_passes_its_target`, `every_regression_directory_names_a_target_and_holds_only_inputs`, `every_seed_passes_its_target`) in `build-and-test`, on stable, without `libfuzzer-sys` (optional, off). Minimization and the origin of the two inputs: Deviations. |
| AC4 (D28) | **Pass** | The `fuzz` job: 60 s per target on pull requests and pushes, 1 200 s per target on the weekly schedule; exit 1 on any finding, never retried, inputs printed as hex and uploaded on failure. Checkout pinned by SHA, upload by the SHA already in use, `nightly-2026-10-01`, `contents: read`. `WorkflowAgreementTest`: `test_fuzz_job_runs_every_target_on_a_nightly_pinned_by_date`, `test_fuzz_job_budget_is_short_on_changes_and_longer_on_the_schedule`, `test_fuzz_job_runs_only_its_upload_after_a_failure`, and the existing pinning and permission tests. Not yet run on GitHub (Open points). |
| AC5 (D28, D29) | **Pass** | Owner approval of `cargo-fuzz`, `libfuzzer-sys` and a dated nightly before any code. `vilicus-fuzz` is `[isolated.fuzz]`: `IsolatedTest` refuses an edge to it from the crate of every node, of every kind, and `test_the_repository_isolates_the_fuzz_targets_from_every_crate` names the shipped binary, the Core, `vilicus-proto`, the Gateway and the testbed. Its dependencies are vendored and pass deny, vet and audit (above); their licences are `(MIT OR Apache-2.0) AND NCSA` and `MIT OR Apache-2.0`, NCSA being in the ASF's Category A. The nightly is in the fuzz job only; `rust-toolchain.toml` stays on 1.99.0. |
