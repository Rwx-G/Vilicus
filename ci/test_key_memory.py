"""Tests of ci/key_memory.py: how it reads the harness's report and the host's coredumpctl
listing, and that it runs the harness's groups in the image CI pins."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import key_memory as km

HARNESS_CHECKS = km.REPO_ROOT / "crates" / "vilicus-crypto" / "examples" / "key_memory" / "checks.rs"
WORKFLOW = km.REPO_ROOT / ".github" / "workflows" / "ci.yml"


class ReportTest(unittest.TestCase):
    OUTPUT = "PASS a: x\nFAIL b: y\nINFO dumpable-crashes: 1\nSKIP swap: no swap\nPASS c: z\n  PASS indented\n"

    def test_lines_are_counted_by_their_tag_at_the_start(self) -> None:
        self.assertEqual(km.count(self.OUTPUT, "PASS"), 2)
        self.assertEqual(km.count(self.OUTPUT, "FAIL"), 1)
        self.assertEqual(km.count(self.OUTPUT, "SKIP"), 1)

    def test_a_group_fails_on_a_fail_line_or_a_non_zero_exit(self) -> None:
        self.assertTrue(km.group_failed(0, self.OUTPUT))
        self.assertTrue(km.group_failed(101, "PASS a: x\n"))
        self.assertFalse(km.group_failed(0, "PASS a: x\nSKIP b: y\n"))

    def test_an_info_value_is_read_by_name(self) -> None:
        self.assertEqual(km.info_value(self.OUTPUT, "dumpable-crashes"), "1")
        self.assertIsNone(km.info_value(self.OUTPUT, "core-pattern"))


class CoredumpTest(unittest.TestCase):
    def test_only_the_harness_entries_are_counted(self) -> None:
        listing = json.dumps(
            [
                {"pid": 10, "exe": "/target/release/examples/key_memory", "sig": 6, "corefile": "none"},
                {"pid": 11, "exe": "/usr/bin/other", "sig": 11, "corefile": "present"},
                {"pid": 12, "exe": "/target/release/examples/key_memory_other", "sig": 6},
            ]
        )
        self.assertEqual([entry["pid"] for entry in km.harness_coredumps(listing)], [10])

    def test_an_empty_listing_has_no_entry(self) -> None:
        self.assertEqual(km.harness_coredumps(""), [])
        self.assertEqual(km.harness_coredumps("[]"), [])


class CoredumpWaitTest(unittest.TestCase):
    """Review finding 8: the check polls for the control's entry instead of sleeping."""

    @staticmethod
    def listing(*answers: list[dict]):
        queue = list(answers)
        return lambda: queue.pop(0) if len(queue) > 1 else queue[0]

    def test_it_waits_for_the_control_then_for_a_settled_count(self) -> None:
        control = {"pid": 1}
        slept = []
        found = km.settled_entries(self.listing([], [], [control]), 1, sleep=slept.append)
        self.assertEqual(found, [control])
        self.assertEqual(len(slept), 2 + km.COREDUMP_SETTLE_POLLS)

    def test_an_entry_after_the_control_is_still_counted(self) -> None:
        control, hardened = {"pid": 1}, {"pid": 2}
        found = km.settled_entries(self.listing([control], [control], [control, hardened]), 1, sleep=lambda _: None)
        self.assertEqual(found, [control, hardened])

    def test_the_wait_is_bounded(self) -> None:
        slept = []
        self.assertEqual(km.settled_entries(self.listing([]), 1, timeout=5, sleep=slept.append), [])
        self.assertEqual(len(slept), 5)

    def test_a_host_without_the_pipe_reports_skip(self) -> None:
        line, failed = km.coredumpctl_check(0, "1", core_pattern="|/usr/share/apport/apport -p%p")
        self.assertTrue(line.startswith("SKIP coredumpctl-no-entry-for-hardened-subjects: "), line)
        self.assertIn("did not run here", line)
        self.assertFalse(failed)

    def test_only_a_systemd_coredump_pipe_runs_the_check(self) -> None:
        self.assertTrue(km.pipes_to_systemd_coredump("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"))
        for pattern in ("core", "|/usr/share/apport/apport -p%p", "|/wsl-capture-crash %t %E %p %s", ""):
            self.assertFalse(km.pipes_to_systemd_coredump(pattern), pattern)


class AgreementTest(unittest.TestCase):
    def test_the_groups_are_the_harness_groups(self) -> None:
        match = re.search(r"pub const GROUPS: \[&str; \d+\] = \[([^\]]*)\];", HARNESS_CHECKS.read_text(encoding="utf-8"))
        self.assertIsNotNone(match)
        self.assertEqual(list(km.GROUPS), re.findall(r'"([^"]+)"', match.group(1)))

    def test_the_image_is_the_one_the_workflow_pins(self) -> None:
        self.assertIn(km.IMAGE, WORKFLOW.read_text(encoding="utf-8"))

    def test_the_harness_binary_is_the_example_the_build_makes(self) -> None:
        self.assertTrue(km.BINARY.endswith(km.HARNESS_EXE_SUFFIX))
        self.assertIn(f"--example {Path(km.BINARY).name}", km.BUILD)


if __name__ == "__main__":
    unittest.main()
