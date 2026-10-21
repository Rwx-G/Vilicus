#!/usr/bin/env python3
"""Checks the vendored SQLCipher amalgamation of crates/vilicus-storage/sqlcipher/ (D143).

cargo-vet and cargo-deny judge crates, not this C source, which vilicus-storage's build script
compiles into every build. So:

- every file listed in SHA256SUMS has that SHA-256, and SHA256SUMS lists each file once, in the
  `<64 hex digits>  <name>` form `sha256sum` writes;
- the directory holds nothing but the listed files, SHA256SUMS itself, README.md and
  regenerate.sh, so no unchecked file can sit beside them;
- the source build.rs compiles (its `SOURCE` constant) is one of the listed files;
- the release tag regenerate.sh clones names the SQLCipher version the amalgamation defines;
- README.md states the tag, tag object and commit of regenerate.sh and every hash of SHA256SUMS,
  so the record a reader sees cannot drift from what is pinned.

Regenerating the amalgamation from the tag needs the network and runs by hand
(`regenerate.sh`, README.md); this check needs neither. Standard library only, Python 3.11 or
later. Exits 1 and prints every violation when a check fails.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/check_sqlcipher_source.py needs Python 3.11 or later; this is {sys.version.split()[0]}")

import argparse
import hashlib
import re
from pathlib import Path

CI_DIR = Path(__file__).resolve().parent
REPO_ROOT = CI_DIR.parent
CRATE_DIR = REPO_ROOT / "crates" / "vilicus-storage"
SOURCE_DIR_NAME = "sqlcipher"
SUMS_NAME = "SHA256SUMS"
UNHASHED = frozenset({SUMS_NAME, "README.md", "regenerate.sh"})

SUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$")
BUILD_SOURCE = re.compile(r'^const SOURCE: &str = "([^"]+)";$', re.MULTILINE)
TAG = re.compile(r"^TAG=v(\d+\.\d+\.\d+)$", re.MULTILINE)
CIPHER_VERSION = re.compile(r"^#define CIPHER_VERSION_NUMBER (\d+\.\d+\.\d+)$", re.MULTILINE)
PINNED_IDS = re.compile(r"^(TAG_OBJECT|COMMIT)=([0-9a-f]{40})$", re.MULTILINE)


def read_sums(sums_file: Path) -> tuple[dict[str, str], list[str]]:
    sums: dict[str, str] = {}
    violations = []
    text = sums_file.read_bytes().decode("utf-8")
    if not text.endswith("\n") or "\r" in text:
        violations.append(f"sqlcipher: {sums_file} must end with a newline and use LF line endings")
    # Bytes, not read_text, which would turn CRLF into LF before the check above sees it.
    for number, line in enumerate(text.removesuffix("\n").split("\n"), start=1):
        match = SUM_LINE.match(line)
        if match is None:
            violations.append(f"sqlcipher: {sums_file} line {number} is not `<sha256>  <name>`: {line!r}")
        elif match.group(2) in sums:
            violations.append(f"sqlcipher: {sums_file} lists {match.group(2)} twice")
        else:
            sums[match.group(2)] = match.group(1)
    return sums, violations


def check(crate_dir: Path) -> list[str]:
    source_dir = crate_dir / SOURCE_DIR_NAME
    sums_file = source_dir / SUMS_NAME
    if not sums_file.is_file():
        return [f"sqlcipher: {sums_file} is missing"]
    sums, violations = read_sums(sums_file)

    for name, expected in sorted(sums.items()):
        path = source_dir / name
        if not path.is_file():
            violations.append(f"sqlcipher: {path} is listed in {SUMS_NAME} but missing")
            continue
        found = hashlib.sha256(path.read_bytes()).hexdigest()
        if found != expected:
            violations.append(f"sqlcipher: {path} has SHA-256 {found}, {SUMS_NAME} says {expected}")

    for path in sorted(source_dir.iterdir()):
        if path.name not in sums and path.name not in UNHASHED:
            violations.append(f"sqlcipher: {path} is neither listed in {SUMS_NAME} nor one of {sorted(UNHASHED)}")

    build_script = crate_dir / "build.rs"
    compiled = BUILD_SOURCE.findall(build_script.read_text(encoding="utf-8")) if build_script.is_file() else []
    if len(compiled) != 1:
        violations.append(f"sqlcipher: {build_script} must declare exactly one `const SOURCE: &str = \"...\";`")
    elif not compiled[0].startswith(f"{SOURCE_DIR_NAME}/") or compiled[0].removeprefix(f"{SOURCE_DIR_NAME}/") not in sums:
        violations.append(f"sqlcipher: build.rs compiles {compiled[0]}, which {SUMS_NAME} does not list")

    script = (source_dir / "regenerate.sh").read_text(encoding="utf-8") if (source_dir / "regenerate.sh").is_file() else ""
    tags = TAG.findall(script)
    versions = []
    for name in sums:
        if name.endswith(".c") and (source_dir / name).is_file():
            versions += CIPHER_VERSION.findall((source_dir / name).read_text(encoding="utf-8", errors="replace"))
    if len(tags) != 1:
        violations.append("sqlcipher: regenerate.sh must set exactly one TAG=v<x.y.z>")
    elif sorted(set(versions)) != tags:
        violations.append(f"sqlcipher: regenerate.sh clones v{tags[0]}, the amalgamation defines {sorted(set(versions))}")

    readme = source_dir / "README.md"
    stated = readme.read_text(encoding="utf-8") if readme.is_file() else ""
    pinned = [f"v{tag}" for tag in tags] + [value for _, value in PINNED_IDS.findall(script)] + sorted(sums.values())
    if len(PINNED_IDS.findall(script)) != 2:
        violations.append("sqlcipher: regenerate.sh must set TAG_OBJECT and COMMIT to 40-digit object ids")
    for value in pinned:
        if value not in stated:
            violations.append(f"sqlcipher: {readme} does not state {value}, pinned by regenerate.sh or {SUMS_NAME}")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--crate-dir", type=Path, default=CRATE_DIR, help="the vilicus-storage crate directory")
    args = parser.parse_args(argv)
    violations = check(args.crate_dir)
    for violation in violations:
        print(violation)
    if violations:
        return 1
    sums, _ = read_sums(args.crate_dir / SOURCE_DIR_NAME / SUMS_NAME)
    print(f"sqlcipher source check passed: {len(sums)} files match {SUMS_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
