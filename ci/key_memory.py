#!/usr/bin/env python3
"""Key memory regression test (Story 4.2, AC2, AC6, AC7, AC9, AC10; D131; gates E16-1 to E16-5).

Builds the harness of crates/vilicus-crypto/examples/key_memory on the release profile, the
product build, and runs each of its groups in a container of the pinned Debian 13 Rust image,
given only the capabilities and limits the group's checks need:

  main       --cap-add SYS_PTRACE (the harness reads a non-dumpable subject's memory, as a root
             attacker would) and RLIMIT_MEMLOCK 8 MiB, the systemd default LimitMEMLOCK: the
             memory scans, the stack canary, the pool's state and capacity, panics, SIGTERM,
             SIGKILL and fork
  noptrace   no added capability, RLIMIT_CORE unlimited for the dumpable control: same-user
             reading and core dumps
  nomemlock  no added capability, RLIMIT_MEMLOCK 0: the refused lock fails closed
  ipclock    --cap-add IPC_LOCK: a process holding CAP_IPC_LOCK is refused its pool
  swap       --memory 256m --memory-swap 1g: the locked pool stays resident under pressure, or
             SKIP with the reason on a host without swap

No container gets CAP_IPC_LOCK but `ipclock`. Each group prints PASS, FAIL, SKIP and INFO lines;
the run fails on any FAIL line, on a container that exits non-zero without one, or when no PASS
line is printed. Under a systemd-coredump pipe `core_pattern` (a Debian 13 host), it also compares
the host's `coredumpctl` entries for the harness with the dumpable crashes the `noptrace` group
reports: a hardened subject must leave none (AC7, gate E16-2).

Needs Docker, and network access once: the crates are built offline from vendor/, but rustup in
the pinned image installs the toolchain rust-toolchain.toml names, which the image does not ship,
into a volume made for the run. The build output lives in another such volume; both are removed
at the end, and the repository is mounted read-only.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGE = "rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
MEMLOCK = 8 * 1024 * 1024
BINARY = "/target/release/examples/key_memory"
BUILD = (
    "cargo build --release --frozen --config ci/cargo-vendored.toml "
    "-p vilicus-crypto --features testing --example key_memory"
)
GROUPS: dict[str, list[str]] = {
    "main": ["--cap-add", "SYS_PTRACE", "--ulimit", f"memlock={MEMLOCK}:{MEMLOCK}"],
    "noptrace": ["--ulimit", f"memlock={MEMLOCK}:{MEMLOCK}", "--ulimit", "core=-1:-1"],
    "nomemlock": ["--ulimit", "memlock=0:0"],
    "ipclock": ["--cap-add", "IPC_LOCK", "--ulimit", f"memlock={MEMLOCK}:{MEMLOCK}"],
    "swap": ["--ulimit", f"memlock={MEMLOCK}:{MEMLOCK}", "--memory", "256m", "--memory-swap", "1g"],
}
HARNESS_EXE_SUFFIX = "/examples/key_memory"
# How long the coredumpctl check waits for systemd-coredump to store the control's crash, and
# for how many one-second polls in a row the count must hold before it is read.
COREDUMP_WAIT = 60.0
COREDUMP_SETTLE_POLLS = 3


def count(output: str, tag: str) -> int:
    return sum(1 for line in output.splitlines() if line.startswith(f"{tag} "))


def group_failed(status: int, output: str) -> bool:
    """A group fails on a FAIL line, or when its container exits non-zero."""
    return status != 0 or count(output, "FAIL") > 0


def info_value(output: str, name: str) -> str | None:
    prefix = f"INFO {name}: "
    return next((line[len(prefix) :].strip() for line in output.splitlines() if line.startswith(prefix)), None)


def harness_coredumps(listing: str, suffix: str = HARNESS_EXE_SUFFIX) -> list[dict]:
    """The entries of `coredumpctl --json=short list` whose executable is the harness."""
    entries = json.loads(listing) if listing.strip() else []
    return [entry for entry in entries if str(entry.get("exe", "")).endswith(suffix)]


def docker(volume: str, rustup: str, options: list[str], command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{REPO_ROOT}:/w:ro",
            "-v", f"{volume}:/target",
            "-v", f"{rustup}:/usr/local/rustup",
            "-e", "CARGO_TARGET_DIR=/target",
            "-e", "CARGO_TERM_COLOR=never",
            "-w", "/w",
            *options,
            IMAGE,
            *command,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def pipes_to_systemd_coredump(core_pattern: str) -> bool:
    """Whether a `core_pattern` hands core dumps to systemd-coredump, the case AC7 tests."""
    return core_pattern.startswith("|") and "systemd-coredump" in core_pattern.split()[0]


def settled_entries(
    listing: Callable[[], list[dict]],
    expected: int,
    timeout: float = COREDUMP_WAIT,
    settle: int = COREDUMP_SETTLE_POLLS,
    poll: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    """The harness's coredumpctl entries once `systemd-coredump` has stored the expected control
    crashes and the count has not changed for `settle` polls in a row, or when `timeout` seconds
    have passed: an entry for a hardened subject, which would come after the control's, is then
    in the listing too."""
    found = listing()
    stable = 0
    waited = 0.0
    while waited < timeout and (len(found) < expected or stable < settle):
        sleep(poll)
        waited += poll
        again = listing()
        stable = stable + 1 if len(again) == len(found) else 0
        found = again
    return found


def coredumpctl_check(since: float, expected: str | None, core_pattern: str | None = None) -> tuple[str, bool]:
    """The coredumpctl comparison as one report line and whether it failed; SKIP, with the reason,
    when the host does not pipe its core dumps to systemd-coredump, so that a run shows that AC7's
    pipe test did not happen."""
    if core_pattern is None:
        try:
            core_pattern = Path("/proc/sys/kernel/core_pattern").read_text(encoding="utf-8").strip()
        except OSError:
            core_pattern = ""
    if not (pipes_to_systemd_coredump(core_pattern) and shutil.which("coredumpctl")):
        return (
            f"SKIP coredumpctl-no-entry-for-hardened-subjects: the host does not pipe core dumps to "
            f"systemd-coredump (core_pattern {core_pattern!r}), so AC7's pipe test did not run here",
            False,
        )
    command = ["coredumpctl", "--no-pager", "--json=short", "list", f"--since=@{int(since)}"]
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        command = ["sudo", "-n", *command]
    failures: list[str] = []

    def listing() -> list[dict]:
        listed = subprocess.run(command, capture_output=True, text=True, check=False)
        if listed.returncode not in (0, 1):
            failures.append(f"{' '.join(command)} exited {listed.returncode}: {listed.stderr.strip()}")
            return []
        return harness_coredumps(listed.stdout if listed.returncode == 0 else "")

    wanted = int(expected) if expected is not None and expected.isdigit() else 0
    found = settled_entries(listing, wanted)
    if failures:
        return f"FAIL coredumpctl-check: {failures[-1]}", True
    ok = expected is not None and len(found) == wanted
    detail = ", ".join(f"pid {entry.get('pid')} signal {entry.get('sig')} corefile {entry.get('corefile')}" for entry in found)
    return (
        f"{'PASS' if ok else 'FAIL'} coredumpctl-no-entry-for-hardened-subjects: {len(found)} entr(ies) for the "
        f"harness ({detail or 'none'}), expected the {expected} dumpable control crash(es) only",
        not ok,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("groups", nargs="*", metavar="group", help=f"groups to run, of {', '.join(GROUPS)} (all by default)")
    args = parser.parse_args(argv)
    unknown = [group for group in args.groups if group not in GROUPS]
    if unknown:
        parser.error(f"unknown group(s) {', '.join(unknown)}; the groups are {', '.join(GROUPS)}")
    groups = args.groups or list(GROUPS)
    run_id = f"{os.getpid()}-{int(time.time())}"
    volume, rustup = f"vilicus-key-memory-target-{run_id}", f"vilicus-key-memory-rustup-{run_id}"
    failures = 0
    passes = 0
    try:
        built = docker(volume, rustup, [], ["bash", "-c", f"rustc --version && {BUILD}"])
        print(built.stdout + built.stderr if built.returncode else f"PASS build: {built.stdout.strip()}, {BUILD}")
        if built.returncode != 0:
            print(f"FAIL build: exit status {built.returncode}")
            return 1
        for group in groups:
            since = time.time()
            ran = docker(volume, rustup, GROUPS[group], [BINARY, "checks", group])
            output = ran.stdout + ran.stderr
            print(output, end="" if output.endswith("\n") else "\n")
            passes += count(output, "PASS")
            if group_failed(ran.returncode, output):
                failures += 1
                if count(output, "FAIL") == 0:
                    print(f"FAIL container-{group}: exit status {ran.returncode}")
            if group == "noptrace":
                line, failed = coredumpctl_check(since, info_value(output, "dumpable-crashes"))
                print(line)
                failures += int(failed)
                passes += int(line.startswith("PASS "))
    finally:
        for name in (volume, rustup):
            subprocess.run(["docker", "volume", "rm", "--force", name], capture_output=True, check=False)
    if failures or passes == 0:
        print(f"{failures} group(s) or check(s) failed" if failures else "no check passed")
        return 1
    print("all key memory checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
