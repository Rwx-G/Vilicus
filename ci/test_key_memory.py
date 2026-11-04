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
