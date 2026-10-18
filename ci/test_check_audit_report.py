"""Tests for ci/check_audit_report.py over reports shaped like `cargo audit --json` output.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import check_audit_report as car

SPIKE_EXCEPTIONS = Path(car.__file__).resolve().parent.parent / "spikes" / "hpke-review" / "audit-exceptions.toml"


def package(name: str, version: str) -> dict:
    return {"name": name, "version": version}


def advisory_warning(kind: str, advisory_id: str, name: str = "old", version: str = "1.0.0") -> dict:
    return {"kind": kind, "package": package(name, version), "advisory": {"id": advisory_id, "title": "t"}}


def yanked_warning(name: str, version: str) -> dict:
    return {"kind": "yanked", "package": package(name, version), "advisory": None}


def report(vulnerabilities: list[dict] = (), **warnings: list[dict]) -> dict:
    return {"vulnerabilities": {"list": list(vulnerabilities)}, "warnings": warnings}


class JudgeTest(unittest.TestCase):
    def test_clean_report_passes(self) -> None:
        self.assertEqual(car.judge(report(), {}), [])

    def test_vulnerability_fails_even_when_its_id_is_listed(self) -> None:
        vulnerability = {"package": package("smallvec", "1.6.0"), "advisory": {"id": "RUSTSEC-2021-0003", "title": "t"}}
        violations = car.judge(report([vulnerability]), {"advisories": {"RUSTSEC-2021-0003": "reason"}})
        self.assertIn("audit: smallvec@1.6.0 has vulnerability RUSTSEC-2021-0003", violations[0])

    def test_each_unlisted_warning_kind_fails(self) -> None:
        for kind in ("unmaintained", "unsound", "notice", "a-future-kind"):
            with self.subTest(kind=kind):
                violations = car.judge(report(**{kind: [advisory_warning(kind, "RUSTSEC-2099-0001")]}), {})
                self.assertEqual(
                    violations,
                    [f"audit: old@1.0.0 has a {kind} warning RUSTSEC-2099-0001 that the exceptions file does not list"],
                )

    def test_unlisted_yanked_crate_fails_even_beside_a_listed_one(self) -> None:
        exceptions = {"yanked": {"inout@0.2.3": "reason"}}
        violations = car.judge(report(yanked=[yanked_warning("inout", "0.2.3"), yanked_warning("other", "1.0.0")]), exceptions)
        self.assertEqual(violations, ["audit: other@1.0.0 has a yanked warning that the exceptions file does not list"])

    def test_listed_warnings_pass(self) -> None:
        exceptions = {"advisories": {"RUSTSEC-2026-0173": "reason"}, "yanked": {"inout@0.2.3": "reason"}}
        warnings = {
            "unmaintained": [advisory_warning("unmaintained", "RUSTSEC-2026-0173")],
            "yanked": [yanked_warning("inout", "0.2.3")],
        }
        self.assertEqual(car.judge(report(**warnings), exceptions), [])

    def test_yanked_exception_does_not_cover_another_version(self) -> None:
        violations = car.judge(report(yanked=[yanked_warning("inout", "0.2.4")]), {"yanked": {"inout@0.2.3": "reason"}})
        self.assertEqual(len(violations), 2, violations)
        self.assertIn("inout@0.2.4 has a yanked warning", violations[0])
        self.assertIn("[yanked] inout@0.2.3 matches nothing", violations[1])

    def test_stale_or_unreasoned_exceptions_fail(self) -> None:
        violations = car.judge(report(), {"advisories": {"RUSTSEC-2026-0173": " "}})
        self.assertEqual(
            violations,
            [
                "audit: exception [advisories] RUSTSEC-2026-0173 gives no reason",
                "audit: exception [advisories] RUSTSEC-2026-0173 matches nothing in the report; remove it",
            ],
        )

    def test_spike_exceptions_file_gives_a_reason_for_each_entry(self) -> None:
        exceptions = tomllib.loads(SPIKE_EXCEPTIONS.read_text(encoding="utf-8"))
        self.assertEqual(set(exceptions), {"advisories", "yanked"})
        for table in exceptions.values():
            for key, reason in table.items():
                with self.subTest(key=key):
                    self.assertTrue(reason.strip())


if __name__ == "__main__":
    unittest.main()
