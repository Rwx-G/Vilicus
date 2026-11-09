#!/usr/bin/env python3
"""Fails when the official SQLCipher repository has a release newer than the one pinned (D157).

cargo-audit and cargo-deny judge crates, not the C source vilicus-storage compiles, so a fix in
SQLCipher that no advisory ties to a crate would reach neither. This compares the tag
regenerate.sh pins with the release tags of the official repository, in the same major series:
a newer major version is printed and does not fail, since moving to it is a design decision and
not a maintenance update. Pre-release tags are ignored.

Needs the network, so it runs in the weekly and manual runs of the `sqlcipher-upstream` job only.
Standard library only, Python 3.11 or later. Exits 1 when a newer release exists or when the
pinned tag is not among the official releases.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from check_sqlcipher_source import CRATE_DIR, OFFICIAL_REPOSITORY, SOURCE_DIR_NAME, TAG

Version = tuple[int, int, int]

RELEASE_REF = re.compile(r"^[0-9a-f]{40}\s+refs/tags/v(\d+)\.(\d+)\.(\d+)$", re.MULTILINE)


def released_versions(ls_remote_output: str) -> set[Version]:
    """The versions of the release tags in `git ls-remote --tags` output."""
    return {(int(major), int(minor), int(patch)) for major, minor, patch in RELEASE_REF.findall(ls_remote_output)}


def label(version: Version) -> str:
    return "v" + ".".join(str(part) for part in version)


def check(pinned: Version, released: set[Version]) -> tuple[list[str], list[str]]:
    """The violations, then the notices, of comparing `pinned` with the released versions."""
    if pinned not in released:
        return [f"sqlcipher: the pinned {label(pinned)} is not among the official release tags"], []
    newer = sorted(version for version in released if version > pinned)
    in_series = [version for version in newer if version[0] == pinned[0]]
    later_majors = [version for version in newer if version[0] != pinned[0]]
    violations = [
        f"sqlcipher: {label(version)} is released and this tree pins {label(pinned)}; "
        "move to it as crates/vilicus-storage/sqlcipher/README.md describes (D143)"
        for version in in_series
    ]
    notices = [f"sqlcipher: {label(version)} is a later major version, to decide on separately" for version in later_majors]
    return violations, notices


def pinned_version(regenerate_script: str) -> Version:
    major, minor, patch = TAG.search(regenerate_script).group(1).split(".")
    return int(major), int(minor), int(patch)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--crate-dir", type=Path, default=CRATE_DIR, help="the vilicus-storage crate directory")
    args = parser.parse_args(argv)
    script = (args.crate_dir / SOURCE_DIR_NAME / "regenerate.sh").read_text(encoding="utf-8")
    pinned = pinned_version(script)
    listing = subprocess.run(
        ["git", "ls-remote", "--tags", OFFICIAL_REPOSITORY],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    violations, notices = check(pinned, released_versions(listing))
    for line in [*notices, *violations]:
        print(line)
    if violations:
        return 1
    print(f"sqlcipher upstream check passed: {label(pinned)} is the latest of its major version")
    return 0


if __name__ == "__main__":
    sys.exit(main())
