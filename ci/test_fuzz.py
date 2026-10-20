"""Tests for ci/fuzz.py: the commands it runs and how it reports a finding. The fuzzing itself runs
in the `fuzz` job, on the nightly toolchain that job pins.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_workspace as cw
import fuzz as fz

# Limits no real plan has, so that a test cannot pass by matching the real numbers by chance.
PLAN = fz.Plan(name="frame_data", input="frames", max_len=1111, malloc_limit_mb=7, rss_limit_mb=99)
NIGHTLY = "nightly-2026-10-01"


class CommandTest(unittest.TestCase):
    def test_plan_lines_are_read_into_plans(self) -> None:
        output = (
            '{"name": "frame_data", "input": "frames", "max_len": 1111, "malloc_limit_mb": 7, "rss_limit_mb": 99}\n'
            "\n"
            '{"name": "profile", "input": "message", "max_len": 2222, "malloc_limit_mb": 3, "rss_limit_mb": 44}\n'
        )
        plans = fz.parse_plan(output)
        self.assertEqual([plan.name for plan in plans], ["frame_data", "profile"])
        self.assertEqual(plans[0], PLAN)

    def test_every_cargo_command_is_frozen_vendored_and_on_the_given_toolchain(self) -> None:
        vendored = ["--frozen", "--config", str(cw.VENDORED_CONFIG_FILE)]
        for command in (fz.plan_command(NIGHTLY), fz.plan_command(NIGHTLY, "seeds", "/out"), fz.build_command(NIGHTLY, ["a"])):
            with self.subTest(command=command):
                self.assertEqual(command[:2], ["cargo", f"+{NIGHTLY}"])
                self.assertEqual(command[3:6] if command[2] == "build" else command[4:7], vendored)

    def test_the_plan_runs_without_the_fuzzing_feature_and_passes_its_arguments(self) -> None:
        command = fz.plan_command(NIGHTLY, "seeds", "/out/corpus")
        self.assertNotIn("--features", command)
        self.assertEqual(command[-4:], ["fuzz-plan", "--", "seeds", "/out/corpus"])
        self.assertNotIn("--", fz.plan_command(NIGHTLY))

    def test_the_build_links_libfuzzer_for_the_target_triple_only(self) -> None:
        command = fz.build_command(NIGHTLY, ["frame_control", "profile"])
        self.assertIn("--release", command)
        self.assertEqual(command[command.index("--features") + 1], fz.FEATURE)
        self.assertEqual(command[command.index("--target") + 1], fz.TRIPLE)
        self.assertEqual(command[command.index("--package") + 1], fz.PACKAGE)
        bins = [command[i + 1] for i, argument in enumerate(command) if argument == "--bin"]
        self.assertEqual(bins, ["frame_control", "profile"])

    def test_the_build_flags_instrument_coverage_and_address_sanitizer(self) -> None:
        flags = " ".join(fz.RUSTFLAGS)
        for flag in ("-Cpasses=sancov-module", "-Zsanitizer=address", "--cfg fuzzing", "-Cdebug-assertions"):
            with self.subTest(flag=flag):
                self.assertIn(flag, flags)

    def test_a_run_applies_the_plan_limits(self) -> None:
        command = fz.fuzz_command(PLAN, 60, Path("/out/corpus/frame_data"), Path("/out/artifacts/frame_data"))
        self.assertEqual(command[0], str(fz.binary("frame_data")))
        for argument in (
            "-max_total_time=60",
            "-max_len=1111",
            "-rss_limit_mb=99",
            "-malloc_limit_mb=7",
            f"-timeout={fz.TIMEOUT_SECONDS}",
            "-detect_leaks=1",
            "-artifact_prefix=/out/artifacts/frame_data/",
        ):
            with self.subTest(argument=argument):
                self.assertIn(argument, command)
        self.assertEqual(command[-1], "/out/corpus/frame_data")

    def test_only_a_dated_nightly_is_accepted(self) -> None:
        for toolchain in ("nightly", "stable", "1.99.0", "nightly-2026-10", "beta-2026-10-01"):
            with self.subTest(toolchain=toolchain):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    fz.main(["--toolchain", toolchain, "--seconds", "1", "--out", "/tmp/out"])
        self.assertRegex(NIGHTLY, fz.DATED_NIGHTLY)


class ReportTest(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.artifacts = Path(temp.name)

    def test_a_long_input_is_printed_in_part_with_its_size_and_hash(self) -> None:
        text = fz.describe("x", bytes(fz.PRINTED_BYTES + 10))
        self.assertIn(f"{fz.PRINTED_BYTES + 10} bytes", text)
        self.assertIn(f"first {fz.PRINTED_BYTES} of", text)
        self.assertEqual(len(text.splitlines()[1]), 2 * fz.PRINTED_BYTES)
        self.assertEqual(fz.describe("y", b"\x81\xa0").splitlines()[1], "81a0")

    def test_a_crash_is_minimized_and_an_out_of_memory_input_is_kept_as_it_is(self) -> None:
        (self.artifacts / "crash-1").write_bytes(b"\x01\x02")
        (self.artifacts / "oom-2").write_bytes(b"\x03")
        (self.artifacts / "slow-unit-3").write_bytes(b"\x04")

        def minimize(command: list[str], **_: object) -> mock.Mock:
            target = Path(next(a for a in command if a.startswith("-exact_artifact_path=")).split("=", 1)[1])
            target.write_bytes(b"\x01")
            return mock.Mock(returncode=0)

        with mock.patch.object(fz.subprocess, "run", side_effect=minimize) as run:
            lines = "\n".join(fz.report_findings(PLAN, self.artifacts, {}))
        self.assertEqual(run.call_count, 1)
        minimize = run.call_args.args[0]
        for argument in ("-minimize_crash=1", f"-max_total_time={fz.MINIMIZE_SECONDS}", "-detect_leaks=1", "-malloc_limit_mb=7"):
            with self.subTest(argument=argument):
                self.assertIn(argument, minimize)
        self.assertIn("failing input crash-1", lines)
        self.assertIn("minimized minimized-crash-1: 1 bytes", lines)
        self.assertIn("commit minimized-crash-1 as crates/vilicus-proto/tests/data/fuzz/frame_data/", lines)
        self.assertIn("failing input oom-2", lines)
        self.assertIn("commit oom-2 as", lines)
        self.assertNotIn("slow-unit", lines)

    def test_a_failed_minimization_keeps_the_original_input(self) -> None:
        (self.artifacts / "timeout-1").write_bytes(b"\x01")
        with mock.patch.object(fz.subprocess, "run", return_value=mock.Mock(returncode=1)):
            lines = "\n".join(fz.report_findings(PLAN, self.artifacts, {}))
        self.assertIn("commit timeout-1 as", lines)
        self.assertNotIn("minimized", lines)


if __name__ == "__main__":
    unittest.main()
