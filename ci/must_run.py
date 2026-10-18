#!/usr/bin/env python3
"""Whether a path-filtered CI job must run: prints `true` or `false`.

The filter runs inside the job rather than as a workflow-level `paths:` filter, so that the job
can be a required check: a workflow skipped by `paths:` leaves a required check pending.

An event that compares two commits (`pull_request`, `merge_group`, `push`) runs the job when
`git diff <base> HEAD` touches one of the paths. Any other event (`workflow_dispatch`,
`schedule`, or one this script does not know) runs it. So does an empty base, a base the clone
does not hold (a new branch, a force push, a shallow clone) and a diff git cannot compute.

Usage: must_run.py --event <github.event_name> --base <sha or empty> <path>...
Standard library only.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

DIFF_EVENTS = frozenset({"pull_request", "merge_group", "push"})


def _git(repo: Path, *args: str) -> int:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True).returncode


def must_run(event: str, base: str, paths: list[str], repo: Path) -> bool:
    if event not in DIFF_EVENTS or not base:
        return True
    if _git(repo, "cat-file", "-e", f"{base}^{{commit}}") != 0:
        return True
    # 0: no change under the paths; 1: a change; anything else: git failed, so run.
    return _git(repo, "diff", "--quiet", base, "HEAD", "--", *paths) != 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    print("true" if must_run(args.event, args.base, args.paths, args.repo) else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
