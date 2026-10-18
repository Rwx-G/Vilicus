#!/usr/bin/env python3
"""Supply-chain checks that cargo-deny, cargo-vet and cargo-audit do not make (D28).

- Build-time code: every package of the dependency tree, across all features and all platforms,
  that has a build script (a `custom-build` target) or is a procedural macro (a `proc-macro`
  target) is on the allowlist of ci/build_time_code.toml, workspace members included, and every
  allowlist entry names a package of the tree with such a target.
- Duplicate exceptions: every `[bans] skip` entry of deny.toml names one exact version and gives,
  as its reason, `forced by <name>@<version>: <why>`, where that package is in the tree and
  depends on the skipped version, which has another version beside it; `skip-tree` stays empty,
  since it would hide a whole subtree.
- Vendored sources (`--vendor`): vendor/ holds exactly what `cargo vendor --locked
  --versioned-dirs` writes from Cargo.lock, byte for byte.

Standard library only, Python 3.11 or later. Exits 1 and prints every violation when a check fails.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/check_supply_chain.py needs Python 3.11 or later (tomllib); this is {sys.version.split()[0]}")

import argparse
import json
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path

CI_DIR = Path(__file__).resolve().parent
REPO_ROOT = CI_DIR.parent
ALLOWLIST_FILE = CI_DIR / "build_time_code.toml"
DENY_FILE = REPO_ROOT / "deny.toml"
VENDOR_DIRECTORY = "vendor"
# The `--config` file that makes cargo read vendor/ (see ci/check_workspace.py).
VENDORED_CONFIG_FILE = "ci/cargo-vendored.toml"

BUILD_TIME_KINDS = {"custom-build": "a build script", "proc-macro": "a procedural macro"}
EXACT_SPEC = re.compile(r"^([A-Za-z0-9_-]+)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)$")
FORCED_BY = re.compile(r"^forced by ([A-Za-z0-9_-]+)@(\S+): (\S.*)$")


def _packages(metadata: dict) -> dict[str, dict]:
    return {package["id"]: package for package in metadata["packages"]}


def check_build_time_code(metadata: dict, allowlist: dict[str, str]) -> list[str]:
    violations = []
    with_build_code: set[str] = set()
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        kinds = sorted({kind for target in package["targets"] for kind in target["kind"]} & set(BUILD_TIME_KINDS))
        if not kinds:
            continue
        with_build_code.add(package["name"])
        if package["name"] not in allowlist:
            what = " and ".join(BUILD_TIME_KINDS[kind] for kind in kinds)
            violations.append(
                f"build-time code: {package['name']} {package['version']} has {what} "
                f"({', '.join(kinds)} target) and is not on the allowlist of ci/{ALLOWLIST_FILE.name}"
            )
    for name, reason in sorted(allowlist.items()):
        if not isinstance(reason, str) or not reason.strip():
            violations.append(f"build-time code: allowlist entry {name} gives no reason")
        if name not in with_build_code:
            violations.append(
                f"build-time code: allowlist entry {name} matches no package with a build script "
                "or a procedural macro in the tree; remove it"
            )
    return violations


def check_duplicate_exceptions(metadata: dict, deny_config: dict) -> list[str]:
    violations = []
    bans = deny_config.get("bans", {})
    if bans.get("skip-tree"):
        violations.append("bans: deny.toml has `skip-tree` entries; list each duplicate under `skip` instead")
    packages = _packages(metadata)
    versions: dict[str, set[str]] = {}
    for package in packages.values():
        versions.setdefault(package["name"], set()).add(package["version"])
    dependents: dict[str, set[tuple[str, str]]] = {}
    for node in (metadata.get("resolve") or {}).get("nodes", []):
        source = packages[node["id"]]
        for dep in node["deps"]:
            dependents.setdefault(dep["pkg"], set()).add((source["name"], source["version"]))

    for entry in bans.get("skip", []):
        if not isinstance(entry, dict) or set(entry) != {"crate", "reason"}:
            violations.append(
                f"bans: skip entry {entry!r} must be a table with exactly `crate = \"<name>@<version>\"` and `reason`"
            )
            continue
        spec, reason = entry["crate"], entry["reason"]
        spec_match, reason_match = EXACT_SPEC.match(spec), FORCED_BY.match(reason)
        if spec_match is None:
            violations.append(f"bans: skip entry {spec!r} must name one exact version, as <name>@<x.y.z>")
            continue
        if reason_match is None:
            violations.append(f"bans: skip entry {spec} has reason {reason!r}; write \"forced by <name>@<version>: <why>\"")
            continue
        name, version = spec_match.groups()
        forcing = reason_match.group(1), reason_match.group(2)
        if version not in versions.get(name, set()):
            violations.append(f"bans: skip entry {spec} matches no package of the tree; remove it")
            continue
        if versions[name] == {version}:
            violations.append(f"bans: skip entry {spec} is the only version of {name} in the tree; remove it")
        skipped_ids = [pid for pid, package in packages.items() if (package["name"], package["version"]) == (name, version)]
        if not any(forcing in dependents.get(pid, set()) for pid in skipped_ids):
            violations.append(
                f"bans: skip entry {spec} says it is forced by {forcing[0]}@{forcing[1]}, "
                f"which does not depend on {spec} in the tree"
            )
    return violations


def run_checks(metadata: dict, allowlist: dict[str, str], deny_config: dict) -> list[str]:
    return [*check_build_time_code(metadata, allowlist), *check_duplicate_exceptions(metadata, deny_config)]


def _files(root: Path) -> dict[str, Path]:
    if not root.is_dir():
        return {}
    return {path.relative_to(root).as_posix(): path for path in root.rglob("*") if path.is_file()}


def vendor_differences(committed: Path, fresh: Path) -> list[str]:
    """What separates the committed vendor/ from a fresh `cargo vendor`; a missing directory is empty."""
    expected, found = _files(fresh), _files(committed)
    violations = [f"vendor: {name} is missing from {VENDOR_DIRECTORY}/" for name in sorted(expected.keys() - found.keys())]
    violations += [
        f"vendor: {VENDOR_DIRECTORY}/{name} is not written by cargo vendor from Cargo.lock"
        for name in sorted(found.keys() - expected.keys())
    ]
    violations += [
        f"vendor: {VENDOR_DIRECTORY}/{name} differs from what cargo vendor writes"
        for name in sorted(expected.keys() & found.keys())
        if expected[name].read_bytes() != found[name].read_bytes()
    ]
    return violations


def check_vendor(root: Path) -> list[str]:
    with tempfile.TemporaryDirectory() as temp:
        fresh = Path(temp) / VENDOR_DIRECTORY
        # `cargo vendor` ignores the [source] replacement it is given and reads crates.io.
        subprocess.run(
            ["cargo", "vendor", "--locked", "--versioned-dirs", "--config", VENDORED_CONFIG_FILE, str(fresh)],
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return vendor_differences(root / VENDOR_DIRECTORY, fresh)


def cargo_metadata(root: Path) -> dict:
    output = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--all-features", "--config", VENDORED_CONFIG_FILE],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return json.loads(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--metadata", type=Path, help="read cargo metadata JSON from this file instead of running cargo")
    parser.add_argument("--vendor", action="store_true", help="compare vendor/ with a fresh `cargo vendor` instead")
    args = parser.parse_args(argv)

    if args.vendor:
        violations = check_vendor(REPO_ROOT)
        passed = "vendor check passed"
    else:
        metadata = json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else cargo_metadata(REPO_ROOT)
        allowlist = tomllib.loads(ALLOWLIST_FILE.read_text(encoding="utf-8"))["allowed"]
        deny_config = tomllib.loads(DENY_FILE.read_text(encoding="utf-8"))
        violations = run_checks(metadata, allowlist, deny_config)
        passed = f"supply-chain checks passed: {len(metadata['packages'])} packages"
    for violation in violations:
        print(violation)
    if violations:
        return 1
    print(passed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
