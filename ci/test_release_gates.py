"""Tests for ci/release_gates.py: the gate declarations, the artefact of each target tag, and the
runner on a fake guest.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import copy
import io
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import check_workspace as cw
import release_gates as rg
import test_check_packaging as tcp
import vm_harness

GATES = tomllib.loads(rg.GATES_FILE.read_text(encoding="utf-8"))
CORE_PATTERN = f"{vm_harness.GUEST_CORE_PATTERN_PREFIX} %P %u %g %s %t %c %h"


def gate(target: str | None, **extra: str) -> dict:
    table = {"checks": "what it checks", "command": "true", **extra}
    if target is not None:
        table["target"] = target
    return table


class FakeGuest:
    """Records what the runner does in the guest; a gate's command exits with `statuses`."""

    def __init__(self, statuses: dict[str, int] | None = None, pattern_after: str | None = None) -> None:
        self.events: list[tuple] = []
        self.statuses = statuses or {}
        self.pattern_after = pattern_after
        self.pattern_reads = 0

    def output(self, command: str) -> str:
        self.events.append(("output", command))
        return ""

    def copy(self, paths: list[Path], destination: str) -> int:
        self.events.append(("copy", destination, [path.name for path in paths]))
        return 0

    def stream(self, command: str, log: Path | None) -> int:
        self.events.append(("stream", command))
        return next((status for marker, status in self.statuses.items() if marker in command), 0)

    def core_pattern(self) -> str:
        self.pattern_reads += 1
        if self.pattern_after is not None and self.pattern_reads % 2 == 0:
            return self.pattern_after
        return CORE_PATTERN


class DeclarationTest(unittest.TestCase):
    def test_repository_gates_are_well_formed_and_cover_both_targets(self) -> None:
        gates, violations = rg.load_gates(GATES)
        self.assertEqual(violations, [])
        for target in rg.TARGETS:
            with self.subTest(target=target):
                self.assertTrue(any(declared.target == target for declared in gates))

    def test_untagged_gate_fails_naming_it(self) -> None:
        config = copy.deepcopy(GATES)
        config["gate"]["untagged-gate"] = gate(None)
        gates, violations = rg.load_gates(config)
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("gate untagged-gate: it has no target tag", violations[0])
        self.assertNotIn("untagged-gate", {declared.name for declared in gates})

    def test_malformed_gates_fail(self) -> None:
        cases = {
            "unknown target": ({"g": gate("vm")}, "its target is 'vm', not one of"),
            "tag under another key": ({"g": {**gate(None), "tag": "testbed"}}, "unknown key 'tag'"),
            "extra key": ({"g": gate("package", retries="5")}, "unknown key 'retries'"),
            "timeout as text": ({"g": {**gate("package"), "timeout": "60"}}, "`timeout` must be a positive whole number"),
            "zero timeout": ({"g": {**gate("package"), "timeout": 0}}, "`timeout` must be a positive whole number"),
            "boolean timeout": ({"g": {**gate("package"), "timeout": True}}, "`timeout` must be a positive whole number"),
            "empty command": ({"g": gate("package", command=" ")}, "`command` must be a non-empty string"),
            "no checks": ({"g": {"target": "package", "command": "true"}}, "`checks` must be a non-empty string"),
            "bad name": ({"Bad_Name": gate("package")}, "its name must be lower case"),
            "not a table": ({"g": "package"}, "gate g is not a table"),
        }
        for label, (tables, fragment) in cases.items():
            with self.subTest(case=label):
                gates, violations = rg.load_gates({"gate": tables})
                self.assertEqual(gates, [])
                self.assertTrue(any(fragment in violation for violation in violations), violations)

    def test_no_gate_or_another_table_fails(self) -> None:
        self.assertIn("declares no [gate.<name>]", rg.load_gates({})[1][0])
        self.assertIn("unknown table 'gates'", rg.load_gates({**GATES, "gates": {}})[1][0])

    def test_untagged_gate_fails_every_command_before_anything_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gates.toml"
            path.write_text(
                rg.GATES_FILE.read_text(encoding="utf-8") + '\n[gate.untagged-gate]\nchecks = "x"\ncommand = "true"\n',
                encoding="utf-8",
            )
            for command in (["check"], ["build"], ["run", "--out", temp]):
                with self.subTest(command=command[0]):
                    output = io.StringIO()
                    with (
                        mock.patch.object(rg.vm_harness, "Guest") as guest,
                        mock.patch.object(rg.cw, "cargo_metadata") as metadata,
                        mock.patch.object(rg.subprocess, "run") as run,
                        redirect_stdout(output),
                    ):
                        status = rg.main(["--gates", str(path), *command])
                    self.assertEqual(status, 1)
                    self.assertIn("gate untagged-gate: it has no target tag", output.getvalue())
                    self.assertIn("RESULT FAIL: no gate was run", output.getvalue())
                    guest.assert_not_called()
                    metadata.assert_not_called()
                    run.assert_not_called()


class ArtefactTest(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.metadata = tcp.Metadata(Path(temp.name)).document()

    def test_each_target_names_its_artefact(self) -> None:
        binaries = rg.artefact_binaries(self.metadata, tcp.GRAPH, tcp.CONFIG)
        self.assertEqual(binaries["package"], sorted({a.binary for a in tcp.cp.load_artefacts(tcp.CONFIG)}))
        self.assertEqual(binaries["testbed"], tcp.cp.testbed_binaries(self.metadata, tcp.GRAPH, tcp.CONFIG))
        self.assertIn(tcp.DOUBLE, binaries["testbed"])
        self.assertFalse(set(binaries["package"]) & set(binaries["testbed"]))

    def test_each_artefact_is_built_alone_from_vendored_sources(self) -> None:
        packages = rg.artefact_packages(self.metadata, tcp.GRAPH, tcp.CONFIG)
        commands = rg.cargo_build_commands(packages)
        self.assertEqual(len(commands), len(rg.TARGETS))
        never_packaged = set(tcp.cp.never_packaged_crates(self.metadata, tcp.GRAPH, tcp.CONFIG))
        for target, command in zip(rg.TARGETS, commands):
            with self.subTest(target=target):
                self.assertEqual(command[:5], ["cargo", "build", "--frozen", "--config", str(cw.VENDORED_CONFIG_FILE)])
                built = set(command[6::2])
                self.assertEqual(built, set(packages[target]))
                if target == "package":
                    self.assertFalse(built & never_packaged)
                else:
                    self.assertLessEqual(built, never_packaged)


class RunnerTest(unittest.TestCase):
    BINARIES = {"package": ["shipped"], "testbed": ["testbed", "double"]}

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name)
        self.lines: list[str] = []

    def run_gates(self, gates: list[rg.Gate], guest: FakeGuest, binaries: dict | None = None) -> int:
        return rg.run_gates(guest, gates, binaries or self.BINARIES, Path("artefacts"), self.out, self.lines.append)

    @staticmethod
    def gates(*targets: str) -> list[rg.Gate]:
        return [rg.Gate(f"{target}-{index}", target, "checks", f"gate-{target}-{index}") for index, target in enumerate(targets)]

    def test_package_gates_run_before_the_testbed_artefact_is_copied(self) -> None:
        guest = FakeGuest()
        self.assertEqual(self.run_gates(self.gates("testbed", "package", "testbed", "package"), guest), 0)
        kinds = [(event[0], event[1].split("/")[-1] if event[0] == "copy" else event[1]) for event in guest.events]
        testbed_copy = kinds.index(("copy", "testbed"))
        package_streams = [i for i, (kind, value) in enumerate(kinds) if kind == "stream" and "gate-package" in value]
        self.assertEqual(len(package_streams), 2)
        self.assertLess(max(package_streams), testbed_copy)
        self.assertEqual(guest.events[0], ("output", f"rm -rf {rg.GUEST_GATES_DIR}"))

    def test_each_gate_runs_in_its_target_directory_against_its_target_artefact(self) -> None:
        guest = FakeGuest()
        self.run_gates(self.gates("package", "testbed"), guest)
        copies = {event[1]: event[2] for event in guest.events if event[0] == "copy"}
        for target in rg.TARGETS:
            with self.subTest(target=target):
                directory = f"{rg.GUEST_GATES_DIR}/{target}"
                self.assertEqual(copies[directory], self.BINARIES[target])
                streams = [event[1] for event in guest.events if event[0] == "stream" and f"gate-{target}" in event[1]]
                self.assertEqual(len(streams), 1)
                self.assertTrue(streams[0].startswith(f"cd {directory} || exit 1; "))

    def test_target_without_gates_is_not_copied(self) -> None:
        guest = FakeGuest()
        self.run_gates(self.gates("package"), guest)
        self.assertEqual([event[1] for event in guest.events if event[0] == "copy"], [f"{rg.GUEST_GATES_DIR}/package"])

    def test_failing_gate_fails_the_run_and_the_others_still_run(self) -> None:
        guest = FakeGuest(statuses={"gate-package-0": 3})
        self.assertEqual(self.run_gates(self.gates("package", "package", "testbed"), guest), 1)
        self.assertEqual(sum(event[0] == "stream" for event in guest.events), 3)
        self.assertTrue(any(line.startswith("FAIL gate package-0: target package, exited 3") for line in self.lines))
        self.assertTrue(any(line.startswith("PASS gate testbed-2:") for line in self.lines))

    def test_target_with_gates_and_no_executable_fails_without_running_them(self) -> None:
        guest = FakeGuest()
        status = self.run_gates(self.gates("package", "testbed"), guest, {"package": ["shipped"], "testbed": []})
        self.assertEqual(status, 1)
        self.assertFalse(any(event[0] == "stream" and "gate-testbed" in event[1] for event in guest.events))
        self.assertTrue(any(line.startswith("FAIL testbed_artefact_defined") for line in self.lines))

    def test_every_gate_runs_under_its_timeout_or_the_default(self) -> None:
        self.assertEqual(rg.load_gates({"gate": {"g": gate("package")}})[0][0].timeout, rg.DEFAULT_GATE_TIMEOUT)
        self.assertEqual(rg.load_gates({"gate": {"g": {**gate("package"), "timeout": 30}}})[0][0].timeout, 30)
        guest = FakeGuest()
        gates = [rg.Gate("quick", "package", "checks", "true; echo 'quoted'", 30), *self.gates("testbed")]
        self.run_gates(gates, guest)
        streams = [event[1] for event in guest.events if event[0] == "stream"]
        self.assertEqual(
            streams[0],
            f"cd {rg.GUEST_GATES_DIR}/package || exit 1; "
            f"timeout --kill-after={rg.TIMEOUT_KILL_AFTER} 30 bash -c 'true; echo '\"'\"'quoted'\"'\"''",
        )
        self.assertIn(f"timeout --kill-after={rg.TIMEOUT_KILL_AFTER} {rg.DEFAULT_GATE_TIMEOUT} bash -c", streams[1])

    def test_timed_out_gate_fails_naming_the_timeout_and_the_next_gates_run(self) -> None:
        guest = FakeGuest(statuses={"gate-package-0": rg.TIMED_OUT})
        self.assertEqual(self.run_gates(self.gates("package", "package", "testbed"), guest), 1)
        self.assertEqual(sum(event[0] == "stream" for event in guest.events), 3)
        self.assertTrue(
            any(line.startswith(f"FAIL gate package-0: target package, timed out after {rg.DEFAULT_GATE_TIMEOUT} s") for line in self.lines),
            self.lines,
        )
        self.assertTrue(any(line.startswith("PASS gate package-1:") for line in self.lines))

    def test_gate_that_changes_kernel_core_pattern_fails(self) -> None:
        guest = FakeGuest(pattern_after="core")
        self.assertEqual(self.run_gates(self.gates("package"), guest), 1)
        self.assertTrue(any(line.startswith("FAIL core_pattern_unchanged") for line in self.lines))


if __name__ == "__main__":
    unittest.main()
