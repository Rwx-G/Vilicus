"""Tests for ci/must_run.py, replaying the events of the `hpke-review` job on a real git repository.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import must_run as mr

WATCHED = ["spikes/hpke-review", ".github/workflows/ci.yml"]
ZERO_SHA = "0" * 40


@unittest.skipUnless(shutil.which("git"), "git is needed to replay the events")
class MustRunTest(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.git("init", "-q")
        self.commit("base", {"spikes/hpke-review/run.sh": "a", "crates/a/lib.rs": "a", ".github/workflows/ci.yml": "a"})
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args: str) -> str:
        command = ["git", "-C", str(self.repo), "-c", "user.name=test", "-c", "user.email=test@example.com", *args]
        return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, message: str, files: dict[str, str]) -> None:
        for relative, content in files.items():
            (self.repo / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / relative).write_text(content, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def run_for(self, event: str, base: str) -> bool:
        return mr.must_run(event, base, WATCHED, self.repo)

    def test_change_outside_the_watched_paths_skips_for_each_diff_event(self) -> None:
        self.commit("crates only", {"crates/a/lib.rs": "b"})
        for event in sorted(mr.DIFF_EVENTS):
            with self.subTest(event=event):
                self.assertFalse(self.run_for(event, self.base))

    def test_change_under_each_watched_path_runs_for_each_diff_event(self) -> None:
        for path in ("spikes/hpke-review/run.sh", ".github/workflows/ci.yml"):
            self.commit(path, {path: path})
            for event in sorted(mr.DIFF_EVENTS):
                with self.subTest(path=path, event=event):
                    self.assertTrue(self.run_for(event, self.base))
            self.git("reset", "-q", "--hard", self.base)

    def test_events_that_compare_nothing_run(self) -> None:
        self.commit("crates only", {"crates/a/lib.rs": "b"})
        for event in ("workflow_dispatch", "schedule", "repository_dispatch"):
            with self.subTest(event=event):
                self.assertTrue(self.run_for(event, self.base))

    def test_unknown_or_missing_base_runs(self) -> None:
        self.commit("crates only", {"crates/a/lib.rs": "b"})
        for base in ("", ZERO_SHA, "1" * 40, "not-a-sha"):
            with self.subTest(base=base):
                self.assertTrue(self.run_for("pull_request", base))

    def test_command_line_prints_the_decision(self) -> None:
        self.commit("crates only", {"crates/a/lib.rs": "b"})
        script = Path(mr.__file__).resolve()
        for event, expected in (("merge_group", "false"), ("schedule", "true")):
            with self.subTest(event=event):
                output = subprocess.run(
                    ["python3", str(script), "--event", event, "--base", self.base, "--repo", str(self.repo), *WATCHED],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
                self.assertEqual(output.strip(), expected)


if __name__ == "__main__":
    unittest.main()
