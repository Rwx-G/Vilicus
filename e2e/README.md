---
title: 'Epic 1 end-to-end harness'
author: Rwx-G
---

# Epic 1 end-to-end harness

`e2e/run.sh` replays every Epic 1 spike in one campaign, from a single command, and records
enough context for anyone to rerun it on the same commit. Each phase is one spike: its own
`spikes/<name>/run.sh`, or, for story 1.1 which has none, the cargo gates (format, lint,
tests) inside the same pinned `rust:1-trixie` container the other spikes use. Every spike
prints `PASS <name>`, `FAIL <name>` and `INFO ...` lines and exits non-zero on failure; the
harness only orchestrates, counts and records. The verdict per story lives in the QA report
and gates under `doc/qa/`, written from a full run.

## Phases

`bash e2e/run.sh --list` prints the phases with their story, runner, CPU sensitivity,
timeout, and whether the runner exists. Phases run in story order, strictly one after the
other, never in parallel.

| Phase | Story | Notes |
|---|---|---|
| `ad36` | 1.1 | Built-in runner: `cargo fmt --check`, `clippy -D warnings`, `cargo test`. |
| `hpke` | 1.2 | |
| `device-key` | 1.3 | Compose project and headless browsers. |
| `naming` | 1.4 | Compose project and headless browsers. |
| `passkey` | 1.5 | Compose project and headless browsers. |
| `sandbox` | 1.6 | Privileged systemd container. |
| `authorizer` | 1.7 | |
| `argon2id` | 1.8 | CPU-sensitive: waits for an idle engine. |
| `cbor` | 1.9 | |
| `locked-memory` | 1.10 | |
| `secure-delete` | 1.11 | |
| `egress` | 1.12 | Compose project. |
| `push` | 1.13 | Simulation only. |
| `separate-origin` | 1.14 | Compose project and headless browsers. |
| `core-execution` | 1.15 | CPU- and fsync-sensitive: waits for an idle engine. 15 to 25 minutes. |
| `hybrid-kex` | 1.16 | Compose project. |
| `prf-probe` | 1.17 | Proves the probe pipeline only. |

A phase whose runner does not exist yet is reported `SKIP` with the reason, not failed.

## Usage

```bash
bash e2e/run.sh                       # full campaign
bash e2e/run.sh --list                # phases, runners, timeouts
bash e2e/run.sh --only cbor           # one phase (comma-separated or repeated for several)
bash e2e/run.sh --skip-core-execution # every phase but one (repeatable)
bash e2e/run.sh --keep-going          # do not skip the remaining phases after a failure
```

Without `--keep-going`, every phase after the first failure is skipped, as in Lorica.

Environment:

- `E2E_IDLE_WAIT` (default 300): seconds a CPU-sensitive phase waits for other containers to
  stop before failing with the list of running containers.
- `E2E_TIMEOUT_SCALE` (default 1): integer multiplier on every phase timeout, for a slower
  machine or a cold image cache.

Runs from Linux or from Git Bash on Windows. Needs Docker only.

## Outputs

Each run writes `e2e/results/<UTC timestamp>-<short sha>/` (ignored by git; the QA report
carries the numbers):

- `run-info.txt`: date UTC, full git HEAD and branch, count of uncommitted paths, Docker server
  version, engine CPUs and memory, host CPUs and memory, the exact command line.
- `<phase>.log`: the full output of the phase, as printed.
- `summary.tsv`: one row per phase: `phase`, `story`, `status` (PASS, FAIL, TIMEOUT, SKIP),
  `exit_code`, `pass`, `fail`, `info` line counts, `duration_s`, `skip_reason` (or a note).
- `summary.md`: the run context and the same table in Markdown.

A phase passes only when its runner exits zero, prints at least one `PASS` line and no `FAIL`
line. On failure the last 40 lines of its log are printed. The run ends with
`=== ALL E2E TESTS PASSED ===` or `=== E2E FAILED: <phases> ===`, and the exit code follows.

## Replaying a recorded run

1. Read the commit SHA and the command in the QA report (`doc/qa/`), or in `run-info.txt`.
2. `git checkout <sha>` (a clean tree: the report also records how many paths were dirty when it
   was produced; a non-zero count means the run is not exactly reproducible from the SHA).
3. Stop every other container, so the CPU-sensitive phases measure on an idle engine.
4. Run the recorded command from the repository root.

The spikes pin their base images by digest and their crates by `Cargo.lock`; npm and Playwright
packages are pinned by each spike. Measured values (Argon2id timings, core execution
latencies) still depend on the machine.

## Runtime expectations

A full campaign with warm caches takes roughly one to two hours, dominated by
`core-execution` (15 to 25 minutes) and the browser phases. The first run pulls the images and
fills the cargo, npm and Playwright caches (named Docker volumes), and can take much longer:
use `E2E_TIMEOUT_SCALE=2` for it.

## What this does not cover

- Real phones and real browsers on household devices. The browser phases drive headless
  Chromium and Firefox with virtual authenticators; the device runs follow each spike's
  `RUNBOOK.md` and are recorded separately.
- The real reference host. `argon2id` and `core-execution` emulate it with a CPU and memory
  quota on a larger machine, which is not the same as four physical cores; their numbers are
  indicative until rerun on the reference host.
- Real push services: `push` is a simulation.
- `cargo audit`, which needs the network for its advisory database: run it on the host.

## Limits of the harness

- A timeout stops the runner script, not necessarily the containers it started (the Docker
  client on Windows does not always forward the signal). The harness lists the containers still
  running after a timeout and leaves them; stop them before the next CPU-sensitive phase.
- The idle check counts every running container on the engine, including ones unrelated to
  Vilicus.
