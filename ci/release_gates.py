#!/usr/bin/env python3
"""Release-gate runner (doc/prd.md FR-109, D102; Story 2.6 AC4).

Release gates are declared in ci/release_gates.toml, each with a target tag: `testbed` for a gate
that needs a module or a test double, `package` for every other gate. This runner executes each
gate in the Debian 13 VM of ci/vm/README.md against the artefact its tag names:

  package   the shipped artefacts of ci/release_artefacts.toml
  testbed   every executable of the never-packaged crates: vilicus-testbed and the test doubles

  check                validate the declarations; an untagged gate, an unknown tag or an unknown
                       key fails, naming the gate
  build                build each artefact with its own cargo invocation, as a release builds the
                       shipped one, so the testbed crates never share a build with it
  run --out DIR        validate, then copy each artefact into its own guest directory and run its
                       gates there, package gates first, before the testbed artefact reaches the
                       guest; every gate runs under GNU timeout (its `timeout`, or
                       DEFAULT_GATE_TIMEOUT), between two reads of kernel.core_pattern, as
                       `vm_harness.py run` does, and its output goes to DIR/<gate>.log

The VM must be up (`vm_harness.py up`). Until the Debian package exists (Epic 5), the package
artefact is the set of executables cargo builds for it; Story 5.7 replaces it with the .deb.

Standard library only, Python 3.11 or later.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/release_gates.py needs Python 3.11 or later (tomllib); this is {sys.version.split()[0]}")

import argparse
import json
import re
import shlex
import subprocess
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import check_packaging as cp
import check_workspace as cw
import vm_harness

GATES_FILE = cw.CI_DIR / "release_gates.toml"
# Run order: package gates first, so that no testbed file is in the guest while they run.
TARGETS = ("package", "testbed")
GATE_KEYS = frozenset({"target", "checks", "command", "timeout"})
# Seconds a gate may run when it declares no `timeout`; GNU timeout then exits 124. A command that
# ignores SIGTERM gets SIGKILL after TIMEOUT_KILL_AFTER more seconds, and exits 137.
DEFAULT_GATE_TIMEOUT = 300
TIMEOUT_KILL_AFTER = 10
TIMED_OUT = 124
GATE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
# Relative to the guest test user's home; emptied at the start of every run.
GUEST_GATES_DIR = "release-gates"
DEFAULT_ARTEFACT_DIR = cw.REPO_ROOT / "target" / "debug"


@dataclass(frozen=True)
class Gate:
    name: str
    target: str
    checks: str
    command: str
    timeout: int = DEFAULT_GATE_TIMEOUT


def load_gates(config: dict) -> tuple[list[Gate], list[str]]:
    """The declared gates, and one violation per malformed declaration."""
    violations = [
        f"gates: unknown table {key!r} in {GATES_FILE.name}; gates are declared as [gate.<name>]"
        for key in sorted(set(config) - {"gate"})
    ]
    tables = config.get("gate")
    if not isinstance(tables, dict) or not tables:
        return [], [*violations, f"gates: {GATES_FILE.name} declares no [gate.<name>]"]
    gates = []
    for name, table in tables.items():
        problems = []
        if not GATE_NAME.fullmatch(name):
            problems.append("its name must be lower case letters and digits separated by hyphens")
        if not isinstance(table, dict):
            violations.append(f"gates: gate {name} is not a table")
            continue
        target = table.get("target")
        if target is None:
            problems.append(
                "it has no target tag; declare target = \"testbed\" if it needs a module or a test double, "
                "target = \"package\" otherwise"
            )
        elif target not in TARGETS:
            problems.append(f"its target is {target!r}, not one of {', '.join(TARGETS)}")
        problems.extend(f"unknown key {key!r}" for key in sorted(set(table) - GATE_KEYS))
        problems.extend(
            f"`{key}` must be a non-empty string"
            for key in ("checks", "command")
            if not isinstance(table.get(key), str) or not table[key].strip()
        )
        timeout = table.get("timeout", DEFAULT_GATE_TIMEOUT)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            problems.append(f"`timeout` must be a positive whole number of seconds, not {timeout!r}")
        if problems:
            violations.extend(f"gates: gate {name}: {problem}" for problem in problems)
        else:
            gates.append(Gate(name, target, table["checks"], table["command"], timeout))
    return gates, violations


def artefact_packages(metadata: dict, graph: cw.Graph, artefacts: dict) -> dict[str, list[str]]:
    """Target -> the workspace packages that build its artefact."""
    members = cp.workspace_members(metadata)
    return {
        "package": sorted({artefact.package for artefact in cp.load_artefacts(artefacts)}),
        "testbed": sorted(
            name for name in cp.never_packaged_crates(metadata, graph, artefacts) if cp.bin_targets(members[name])
        ),
    }


def artefact_binaries(metadata: dict, graph: cw.Graph, artefacts: dict) -> dict[str, list[str]]:
    """Target -> the executables its artefact is made of."""
    return {
        "package": sorted({artefact.binary for artefact in cp.load_artefacts(artefacts)}),
        "testbed": cp.testbed_binaries(metadata, graph, artefacts),
    }


def cargo_build_commands(packages: dict[str, list[str]]) -> list[list[str]]:
    """One vendored, frozen cargo build per target."""
    return [
        [
            "cargo",
            "build",
            "--frozen",
            "--config",
            str(cw.VENDORED_CONFIG_FILE),
            *(argument for package in packages[target] for argument in ("--package", package)),
        ]
        for target in TARGETS
        if packages[target]
    ]


def guest_command(directory: str, gate: Gate) -> str:
    """The gate's command, run by bash from its target directory under GNU timeout."""
    return (
        f"cd {shlex.quote(directory)} || exit 1; "
        f"timeout --kill-after={TIMEOUT_KILL_AFTER} {gate.timeout} bash -c {shlex.quote(gate.command)}"
    )


def run_gates(
    guest: vm_harness.Guest,
    gates: list[Gate],
    binaries: dict[str, list[str]],
    artefact_dir: Path,
    out: Path,
    report: Callable[[str], None] = print,
) -> int:
    checks = vm_harness.Checks(report)
    guest.output(f"rm -rf {GUEST_GATES_DIR}")
    for target in TARGETS:
        selected = [gate for gate in gates if gate.target == target]
        if not selected:
            continue
        directory = f"{GUEST_GATES_DIR}/{target}"
        names = binaries[target]
        if not checks.check(f"{target}_artefact_defined", bool(names), f"executables: {', '.join(names) or 'none'}"):
            continue
        copied = guest.copy([artefact_dir / name for name in names], directory)
        if not checks.check(f"{target}_artefact_copied", copied == 0, f"into ~/{directory}, status {copied}"):
            continue
        guest.output("chmod 0755 " + " ".join(shlex.quote(f"{directory}/{name}") for name in names))
        for gate in selected:
            log = out / f"{gate.name}.log"

            def test(gate: Gate = gate, log: Path = log) -> int:
                return guest.stream(guest_command(directory, gate), log)

            status = vm_harness.guarded(guest.core_pattern, test, report)
            outcome = f"timed out after {gate.timeout} s" if status == TIMED_OUT else f"exited {status}"
            checks.check(f"gate {gate.name}", status == 0, f"target {gate.target}, {outcome}: {gate.checks}")
    return checks.status


def _load(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gates", type=Path, default=GATES_FILE, help="the gate declarations (default: %(default)s)")
    parser.add_argument("--metadata", type=Path, help="read cargo metadata JSON from this file instead of running cargo")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    commands.add_parser("build")
    run = commands.add_parser("run")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--artefact-dir", type=Path, default=DEFAULT_ARTEFACT_DIR, help="where cargo wrote the executables")
    args = parser.parse_args(argv)

    gates, violations = load_gates(_load(args.gates))
    for violation in violations:
        print(violation)
    if violations:
        print("RESULT FAIL: no gate was run")
        return 1
    if args.command == "check":
        counts = ", ".join(f"{sum(gate.target == target for gate in gates)} {target}" for target in TARGETS)
        print(f"release gates declared: {counts}")
        return 0

    metadata = json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else cw.cargo_metadata(cw.REPO_ROOT)
    graph = cw.Graph.from_config(_load(cw.GRAPH_FILE))
    artefacts = _load(cp.ARTEFACTS_FILE)
    if args.command == "build":
        for command in cargo_build_commands(artefact_packages(metadata, graph, artefacts)):
            print(f"INFO {' '.join(command)}", flush=True)
            status = subprocess.run(command, cwd=cw.REPO_ROOT, check=False).returncode
            if status != 0:
                return status
        return 0

    packaging = cp.check_artefacts(metadata, graph, artefacts)
    for violation in packaging:
        print(violation)
    if packaging:
        print("RESULT FAIL: the package artefact fails the packaging check; no gate was run")
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    try:
        status = run_gates(vm_harness.Guest(), gates, artefact_binaries(metadata, graph, artefacts), args.artefact_dir, args.out)
    except vm_harness.HarnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"RESULT {'PASS' if status == 0 else 'FAIL'}")
    return status


if __name__ == "__main__":
    sys.exit(main())
