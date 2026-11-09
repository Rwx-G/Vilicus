"""Tests for ci/check_sqlcipher_upstream.py on synthetic tag listings.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import unittest

import check_sqlcipher_upstream as cu

OBJECT = "52252487a5cada9b430e8d4b20025790c5a6ba20"


def listing(*tags: str) -> str:
    return "".join(f"{OBJECT}\trefs/tags/{tag}\n" for tag in tags)


class ReleasedVersionsTest(unittest.TestCase):
    def test_reads_release_tags_only(self) -> None:
        output = listing("v4.19.0", "v4.20.0", "v5.0.0-beta.1", "v4.20.0^{}", "not-a-release")
        self.assertEqual(cu.released_versions(output), {(4, 19, 0), (4, 20, 0)})


class CheckTest(unittest.TestCase):
    def test_the_latest_of_the_series_passes(self) -> None:
        self.assertEqual(cu.check((4, 20, 0), {(4, 19, 0), (4, 20, 0)}), ([], []))

    def test_a_newer_patch_fails(self) -> None:
        violations, _ = cu.check((4, 20, 0), {(4, 20, 0), (4, 20, 1)})
        self.assertEqual(len(violations), 1)
        self.assertIn("v4.20.1", violations[0])

    def test_a_newer_minor_fails_and_compares_numerically(self) -> None:
        violations, _ = cu.check((4, 9, 0), {(4, 9, 0), (4, 10, 0)})
        self.assertEqual(len(violations), 1)
        self.assertIn("v4.10.0", violations[0])

    def test_a_later_major_is_a_notice_only(self) -> None:
        violations, notices = cu.check((4, 20, 0), {(4, 20, 0), (5, 0, 0)})
        self.assertEqual(violations, [])
        self.assertEqual(len(notices), 1)
        self.assertIn("v5.0.0", notices[0])

    def test_a_pinned_tag_absent_upstream_fails(self) -> None:
        violations, _ = cu.check((4, 20, 0), {(4, 19, 0)})
        self.assertEqual(len(violations), 1)
        self.assertIn("not among", violations[0])


class PinnedVersionTest(unittest.TestCase):
    def test_reads_the_tag_of_the_script(self) -> None:
        self.assertEqual(cu.pinned_version("#!/usr/bin/env bash\nTAG=v4.20.0\nCOMMIT=abc\n"), (4, 20, 0))


if __name__ == "__main__":
    unittest.main()
