#!/usr/bin/env python3
"""Runs the coverage-guided fuzz targets of fuzz/ (Story 2.7) for a fixed time each.

1. Reads the plan of every target from `fuzz-plan` (fuzz/src/bin/fuzz-plan.rs): its name, the
   shape of its input, its longest input and its memory limits, which vilicus-fuzz derives from
   the frame maximum and the item bound of the target's socket kind. `fuzz-plan seeds` then
   writes each target's seed corpus into a scratch directory: every input of the committed E19
   vectors (the corpus, invalid and fuzz files of crates/vilicus-proto/tests/data/canonical-cbor/,
   read in place, never copied into the repository) in the shape the target reads, and the
   target's committed failing inputs.
2. Builds every target with libFuzzer, coverage instrumentation and AddressSanitizer, on the
   dated nightly toolchain given, from the vendored sources (`--frozen --config
   ci/cargo-vendored.toml`), with the flags cargo-fuzz 0.13.2 passes for its default build.
3. Runs each target for the given number of seconds under its limits. A target that finds an
   input that panics, overflows the stack, times out or passes a memory limit fails: its input
   is minimized, both are printed as hex and kept under the output directory, and the script
   exits 1 after running every target. Nothing is retried.

A failing input is replayed on stable, without any fuzzing dependency, once committed under
`crates/vilicus-proto/tests/data/fuzz/<target>/` (fuzz/tests/regressions.rs).

Usage: fuzz.py --toolchain nightly-YYYY-MM-DD --seconds N --out DIR [--target NAME]...
Standard library only, Python 3.11 or later.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/fuzz.py needs Python 3.11 or later; this is {sys.version.split()[0]}")

import argparse
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import check_workspace as cw

REPO_ROOT = cw.REPO_ROOT
PACKAGE = "vilicus-fuzz"
PLAN_BINARY = "fuzz-plan"
FEATURE = "libfuzzer"
TRIPLE = "x86_64-unknown-linux-gnu"
DATED_NIGHTLY = re.compile(r"^nightly-\d{4}-\d{2}-\d{2}$")
# A decode of the largest data frame takes well under a second; an input that takes this long
# loops.
TIMEOUT_SECONDS = 60
# Minimization runs this many attempts at most, which stays within a minute per input.
MINIMIZE_RUNS = 20_000
# The files libFuzzer writes for a failing input; it also keeps slow inputs, which are not failures.
FINDING_PREFIXES = ("crash-", "oom-", "timeout-", "leak-")
MINIMIZED_PREFIXES = ("crash-", "timeout-")
# What is printed of an input in the log; the whole input is in the output directory.
PRINTED_BYTES = 4096
# cargo-fuzz 0.13.2 (src/project.rs), `cargo fuzz build` for x86_64 Linux with its defaults:
# release with debug assertions, AddressSanitizer, trace-compares, branch folding disabled, one
# codegen unit and line tables. `--target` keeps the flags off build scripts and macros.
RUSTFLAGS = (
    "-Cpasses=sancov-module",
    "-Cllvm-args=-sanitizer-coverage-level=4",
    "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
    "-Cllvm-args=-sanitizer-coverage-pc-table",
    "-Cllvm-args=-sanitizer-coverage-trace-compares",
    "--cfg fuzzing",
    "-Cllvm-args=-simplifycfg-branch-fold-threshold=0",
    "-Zsanitizer=address",
    "-Cllvm-args=-sanitizer-coverage-stack-depth",
    "-Cdebug-assertions",
    "-Ccodegen-units=1",
)
PROFILE_CONFIG = 'profile.release.debug="line-tables-only"'
# Keeps the resident memory about what the decoders hold, so that the limit measures them: a small
# quarantine of freed memory, and two frames of allocation context instead of 30, since
# AddressSanitizer keeps every distinct allocation stack for the life of the process and the
# recursive decoder reaches new ones throughout a run (Story 2.7: a 10-minute run of `profile`
# grew from 113 to 275 MiB with 30 frames, and stayed at 106 MiB with 2).
ASAN_OPTIONS = "quarantine_size_mb=16:malloc_context_size=2:detect_leaks=0"


@dataclass(frozen=True)
class Plan:
    name: str
    input: str
    max_len: int
    malloc_limit_mb: int
    rss_limit_mb: int


def parse_plan(output: str) -> list[Plan]:
    return [Plan(**json.loads(line)) for line in output.splitlines() if line.strip()]


def plan_command(toolchain: str, *arguments: str) -> list[str]:
    """`fuzz-plan`, built without the fuzzing feature, so on the toolchain alone."""
    return [
        "cargo",
        f"+{toolchain}",
        "run",
        "--quiet",
        "--frozen",
        "--config",
        str(cw.VENDORED_CONFIG_FILE),
        "--package",
        PACKAGE,
        "--bin",
        PLAN_BINARY,
        *(("--", *arguments) if arguments else ()),
    ]


def build_command(toolchain: str, targets: list[str]) -> list[str]:
    return [
        "cargo",
        f"+{toolchain}",
        "build",
        "--frozen",
        "--config",
        str(cw.VENDORED_CONFIG_FILE),
        "--config",
        PROFILE_CONFIG,
        "--package",
        PACKAGE,
        "--features",
        FEATURE,
        "--release",
        "--target",
        TRIPLE,
        *(argument for target in targets for argument in ("--bin", target)),
    ]


def binary(target: str) -> Path:
    return REPO_ROOT / "target" / TRIPLE / "release" / target


def fuzz_command(plan: Plan, seconds: int, corpus: Path, artifacts: Path) -> list[str]:
    return [
        str(binary(plan.name)),
        f"-max_total_time={seconds}",
        f"-max_len={plan.max_len}",
        f"-rss_limit_mb={plan.rss_limit_mb}",
        f"-malloc_limit_mb={plan.malloc_limit_mb}",
        f"-timeout={TIMEOUT_SECONDS}",
        f"-artifact_prefix={artifacts}/",
        "-print_final_stats=1",
        str(corpus),
    ]


def minimize_command(plan: Plan, artifact: Path, minimized: Path) -> list[str]:
    return [
        str(binary(plan.name)),
        "-minimize_crash=1",
        f"-runs={MINIMIZE_RUNS}",
        f"-max_len={plan.max_len}",
        f"-rss_limit_mb={plan.rss_limit_mb}",
        f"-malloc_limit_mb={plan.malloc_limit_mb}",
        f"-timeout={TIMEOUT_SECONDS}",
        f"-exact_artifact_path={minimized}",
        str(artifact),
    ]


def describe(label: str, data: bytes) -> str:
    shown = data[:PRINTED_BYTES].hex()
    more = f" (first {PRINTED_BYTES} of {len(data)} bytes)" if len(data) > PRINTED_BYTES else ""
    return f"{label}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}{more}\n{shown}"


def report_findings(plan: Plan, artifacts: Path, env: dict[str, str]) -> list[str]:
    """Describes each input the run kept, and minimizes a crash or a timeout. An out-of-memory
    input is kept as it is: libFuzzer checks the resident memory once a second, so a single run
    of the input may end before the check and minimization cannot tell it from a passing one."""
    lines = []
    for artifact in sorted(path for path in artifacts.iterdir() if path.name.startswith(FINDING_PREFIXES)):
        lines.append(describe(f"{plan.name}: failing input {artifact.name}", artifact.read_bytes()))
        keep = artifact
        if artifact.name.startswith(MINIMIZED_PREFIXES):
            minimized = artifacts / f"minimized-{artifact.name}"
            result = subprocess.run(minimize_command(plan, artifact, minimized), cwd=REPO_ROOT, env=env)
            if result.returncode == 0 and minimized.is_file():
                lines.append(describe(f"{plan.name}: minimized {minimized.name}", minimized.read_bytes()))
                keep = minimized
        lines.append(
            f"{plan.name}: commit {keep.name} as crates/vilicus-proto/tests/data/fuzz/{plan.name}/<name> "
            "with the fix, so that build-and-test replays it and the next runs seed from it"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--toolchain", required=True, help="the dated nightly, nightly-YYYY-MM-DD")
    parser.add_argument("--seconds", type=int, required=True, help="fuzzing time per target")
    parser.add_argument("--out", type=Path, required=True, help="where corpora and failing inputs go")
    parser.add_argument("--target", action="append", help="run only this target (repeatable)")
    args = parser.parse_args(argv)
    if not DATED_NIGHTLY.match(args.toolchain):
        parser.error(f"--toolchain {args.toolchain!r} is not a dated nightly (nightly-YYYY-MM-DD)")
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    out = args.out.resolve()

    plan_output = subprocess.run(
        plan_command(args.toolchain), cwd=REPO_ROOT, check=True, stdout=subprocess.PIPE, text=True
    ).stdout
    plans = parse_plan(plan_output)
    unknown = sorted(set(args.target or ()) - {plan.name for plan in plans})
    if unknown:
        parser.error(f"no fuzz target named {', '.join(unknown)}")
    plans = [plan for plan in plans if not args.target or plan.name in args.target]

    build_env = {**os.environ, "RUSTFLAGS": " ".join(RUSTFLAGS)}
    subprocess.run(build_command(args.toolchain, [plan.name for plan in plans]), cwd=REPO_ROOT, env=build_env, check=True)

    subprocess.run(plan_command(args.toolchain, "seeds", str(out / "corpus")), cwd=REPO_ROOT, check=True)
    run_env = {**os.environ, "ASAN_OPTIONS": ASAN_OPTIONS}
    failed = []
    for plan in plans:
        corpus = out / "corpus" / plan.name
        artifacts = out / "artifacts" / plan.name
        artifacts.mkdir(parents=True, exist_ok=True)
        inputs = sum(1 for path in corpus.iterdir() if path.is_file())
        print(
            f"== {plan.name}: {args.seconds} s, {inputs} corpus inputs, max_len {plan.max_len}, "
            f"rss_limit_mb {plan.rss_limit_mb}, malloc_limit_mb {plan.malloc_limit_mb}",
            flush=True,
        )
        result = subprocess.run(fuzz_command(plan, args.seconds, corpus, artifacts), cwd=REPO_ROOT, env=run_env)
        if result.returncode != 0:
            failed.append(plan.name)
            print(f"== {plan.name}: FAILED (exit {result.returncode})", flush=True)
            for line in report_findings(plan, artifacts, run_env):
                print(line, flush=True)
        else:
            print(f"== {plan.name}: no finding", flush=True)

    if failed:
        print(f"fuzzing failed: {', '.join(failed)}; failing inputs are under {out / 'artifacts'}")
        return 1
    print(f"fuzzing passed: {len(plans)} targets, {args.seconds} s each, no finding")
    return 0


if __name__ == "__main__":
    sys.exit(main())
