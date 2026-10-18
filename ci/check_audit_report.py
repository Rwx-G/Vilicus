#!/usr/bin/env python3
"""Judges a `cargo audit --json` report against a file of reasoned exceptions.

Every vulnerability fails. Every warning fails (unmaintained, unsound, yanked, notice, any other
kind), which is `cargo audit --deny warnings`, unless the exceptions file lists it: an advisory
warning by its id under `[advisories]`, a yanked crate as `"<name>@<version>"` under `[yanked]`,
each with a non-empty reason. An exception that matches nothing in the report fails, so the file
cannot outlive the lockfile it was written for. cargo-audit can ignore an advisory id but cannot
except a single yanked crate without disabling the yanked check, which is why this script exists.

Usage: check_audit_report.py <exceptions.toml> <report.json>
Standard library only, Python 3.11 or later. Exits 1 and prints every violation when a check fails.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/check_audit_report.py needs Python 3.11 or later (tomllib); this is {sys.version.split()[0]}")

import argparse
import json
import tomllib
from pathlib import Path


def _crate(entry: dict) -> str:
    return f"{entry['package']['name']}@{entry['package']['version']}"


def judge(report: dict, exceptions: dict) -> list[str]:
    advisories = exceptions.get("advisories", {})
    yanked = exceptions.get("yanked", {})
    violations = [
        f"audit: {_crate(entry)} has vulnerability {entry['advisory']['id']} ({entry['advisory']['title']})"
        for entry in report["vulnerabilities"]["list"]
    ]
    used: set[tuple[str, str]] = set()
    for kind, entries in sorted(report.get("warnings", {}).items()):
        for entry in entries:
            advisory = entry.get("advisory")
            if advisory:
                key, described = ("advisories", advisory["id"]), f"{kind} warning {advisory['id']}"
            else:
                key, described = (kind, _crate(entry)), f"{kind} warning"
            listed = {"advisories": advisories, "yanked": yanked}.get(key[0], {})
            if key[1] in listed:
                used.add(key)
            else:
                violations.append(f"audit: {_crate(entry)} has a {described} that the exceptions file does not list")
    for table_name, table in (("advisories", advisories), ("yanked", yanked)):
        for key, reason in sorted(table.items()):
            if not isinstance(reason, str) or not reason.strip():
                violations.append(f"audit: exception [{table_name}] {key} gives no reason")
            if (table_name, key) not in used:
                violations.append(f"audit: exception [{table_name}] {key} matches nothing in the report; remove it")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("exceptions", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)

    exceptions = tomllib.loads(args.exceptions.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    violations = judge(report, exceptions)
    for violation in violations:
        print(violation)
    if violations:
        return 1
    warnings = sum(len(entries) for entries in report.get("warnings", {}).values())
    print(f"audit report passed: no vulnerability, {warnings} warning(s), each a listed exception")
    return 0


if __name__ == "__main__":
    sys.exit(main())
