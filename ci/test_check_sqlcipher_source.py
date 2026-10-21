"""Tests for ci/check_sqlcipher_source.py on synthetic crate directories and on the tree.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

import check_sqlcipher_source as cs

AMALGAMATION = "/* amalgamation */\n#define CIPHER_VERSION_NUMBER 4.19.0\nint x;\n"
BUILD_RS = 'const SOURCE: &str = "sqlcipher/sqlite3.c";\nfn main() {}\n'
TAG_OBJECT = "58beb4a302f0e3c37341d2312cef521f858b1273"
COMMIT = "c4b275a47932888216bade83aff2bbc73df0ff85"
REGENERATE = (
    f"#!/usr/bin/env bash\nTAG=v4.19.0\nTAG_OBJECT={TAG_OBJECT}\nCOMMIT={COMMIT}\n"
    f"REPOSITORY={cs.OFFICIAL_REPOSITORY}\n"
    'git clone --branch "$TAG" "$REPOSITORY" "$work/src"\n'
)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class SyntheticCrate:
    """A crate directory with a consistent vendored source, which each test then breaks."""

    def __init__(self, root: Path) -> None:
        self.crate = root / "vilicus-storage"
        self.source = self.crate / "sqlcipher"
        self.source.mkdir(parents=True)
        self.files = {"sqlite3.c": AMALGAMATION, "LICENSE.md": "licence\n"}
        for name, text in self.files.items():
            self.write(name, text)
        self.write_sums()
        self.write_readme()
        self.write("regenerate.sh", REGENERATE)
        (self.crate / "build.rs").write_text(BUILD_RS, encoding="utf-8", newline="\n")

    def write(self, name: str, text: str) -> None:
        (self.source / name).write_text(text, encoding="utf-8", newline="\n")

    def write_readme(self, skip: str = "") -> None:
        stated = ["v4.19.0", TAG_OBJECT, COMMIT, *(sha256(text) for text in self.files.values())]
        self.write("README.md", "".join(f"- {value}\n" for value in stated if value != skip))

    def write_sums(self, lines: list[str] | None = None) -> None:
        if lines is None:
            lines = [f"{sha256(text)}  {name}" for name, text in sorted(self.files.items())]
        self.write("SHA256SUMS", "".join(f"{line}\n" for line in lines))


class CheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.crate = SyntheticCrate(Path(self.directory.name))

    def violations(self) -> list[str]:
        return cs.check(self.crate.crate)

    def assert_violation(self, fragment: str) -> None:
        violations = self.violations()
        self.assertTrue(any(fragment in violation for violation in violations), violations)

    def test_a_consistent_directory_passes(self) -> None:
        self.assertEqual(self.violations(), [])

    def test_an_edited_source_fails(self) -> None:
        self.crate.write("sqlite3.c", AMALGAMATION + "/* edited */\n")
        self.assert_violation("sqlite3.c has SHA-256")

    def test_an_unlisted_file_fails(self) -> None:
        self.crate.write("sqlite3.h", "header\n")
        self.assert_violation("sqlite3.h is neither listed")

    def test_a_listed_file_that_is_missing_fails(self) -> None:
        (self.crate.source / "LICENSE.md").unlink()
        self.assert_violation("LICENSE.md is listed")

    def test_a_malformed_or_duplicate_sum_line_fails(self) -> None:
        good = f"{sha256(AMALGAMATION)}  sqlite3.c"
        for lines, expected in [
            ([good, f"{sha256('licence')} LICENSE.md"], "is not `<sha256>  <name>`"),
            ([good, good], "lists sqlite3.c twice"),
            ([good.upper()], "is not `<sha256>  <name>`"),
        ]:
            with self.subTest(lines=lines):
                self.crate.write_sums(lines)
                self.assert_violation(expected)

    def test_crlf_sums_fail(self) -> None:
        sums = self.crate.source / "SHA256SUMS"
        sums.write_bytes(sums.read_bytes().replace(b"\n", b"\r\n"))
        self.assert_violation("LF line endings")

    def test_build_rs_compiling_an_unlisted_source_fails(self) -> None:
        build_rs = self.crate.crate / "build.rs"
        build_rs.write_text('const SOURCE: &str = "sqlcipher/other.c";\n', encoding="utf-8")
        self.assert_violation("compiles sqlcipher/other.c")
        build_rs.write_text("fn main() {}\n", encoding="utf-8")
        self.assert_violation("exactly one `const SOURCE")

    def test_a_tag_that_differs_from_the_amalgamation_fails(self) -> None:
        self.crate.write("regenerate.sh", REGENERATE.replace("v4.19.0", "v4.20.0"))
        self.assert_violation("clones v4.20.0")
        self.crate.write("regenerate.sh", REGENERATE + "TAG=v4.19.0\n")
        self.assert_violation("exactly one TAG")

    def test_a_readme_that_omits_a_pinned_value_fails(self) -> None:
        for value in [COMMIT, TAG_OBJECT, "v4.19.0", sha256(AMALGAMATION)]:
            with self.subTest(value=value):
                self.crate.write_readme(skip=value)
                self.assert_violation(f"does not state {value}")
        self.crate.write_readme()
        self.crate.write("regenerate.sh", "TAG=v4.19.0\n")
        self.assert_violation("TAG_OBJECT and COMMIT")


    def test_a_regeneration_pointed_elsewhere_fails(self) -> None:
        fork = "https://github.com/someone/sqlcipher"
        self.crate.write("regenerate.sh", REGENERATE.replace(cs.OFFICIAL_REPOSITORY, fork))
        self.assert_violation(f"must set exactly REPOSITORY={cs.OFFICIAL_REPOSITORY}")
        self.assert_violation(f"names {fork}")
        self.crate.write(
            "regenerate.sh",
            REGENERATE.replace('"$REPOSITORY"', f'"{fork}"'),
        )
        self.assert_violation(f"names {fork}")
        self.crate.write("regenerate.sh", REGENERATE + "git fetch git@example.com:x/y.git\n")
        self.assert_violation("names git@example.com:x/y.git")


class TreeTest(unittest.TestCase):
    def test_the_vendored_source_of_the_tree_passes(self) -> None:
        self.assertEqual(cs.check(cs.CRATE_DIR), [])


if __name__ == "__main__":
    unittest.main()
