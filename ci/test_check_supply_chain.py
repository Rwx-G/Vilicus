"""Tests for ci/check_supply_chain.py, over synthetic `cargo metadata` documents, plus a run on
a real `cargo metadata` and the agreement of the workflow's tool versions with the spine.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import inspect
import json
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import check_supply_chain as sc
import check_workspace as cw
import fuzz as fz
import release_gates as rg

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
WORKFLOW = sc.REPO_ROOT / ".github" / "workflows" / "ci.yml"
SPINE = sc.REPO_ROOT / "doc" / "architecture-spine.md"


class Tree:
    """A synthetic `cargo metadata` document: packages, their targets and resolved edges."""

    def __init__(self) -> None:
        self.packages: dict[str, dict] = {}
        self.edges: dict[str, list[str]] = {}

    def add(self, name: str, version: str, *kinds: str) -> str:
        package_id = f"{REGISTRY}#{name}@{version}"
        targets = [{"kind": [kind], "name": name} for kind in (kinds or ("lib",))]
        self.packages[package_id] = {"id": package_id, "name": name, "version": version, "targets": targets}
        self.edges.setdefault(package_id, [])
        return package_id

    def depend(self, source: str, target: str) -> None:
        self.edges[source].append(target)

    def metadata(self) -> dict:
        nodes = [{"id": pid, "deps": [{"pkg": dep} for dep in deps]} for pid, deps in self.edges.items()]
        # The workspace members are the packages nothing depends on.
        targets = {dep for deps in self.edges.values() for dep in deps}
        members = [pid for pid in self.packages if pid not in targets]
        return {"packages": list(self.packages.values()), "workspace_members": members, "resolve": {"nodes": nodes}}


class BuildTimeCodeTest(unittest.TestCase):
    def test_tree_without_build_time_code_passes_with_an_empty_allowlist(self) -> None:
        tree = Tree()
        tree.add("plain", "1.0.0")
        tree.add("tool", "1.0.0", "lib", "bin")
        self.assertEqual(sc.check_build_time_code(tree.metadata(), {}), [])

    def test_each_kind_of_build_time_code_off_the_allowlist_fails_naming_the_crate(self) -> None:
        for kind, description in sc.BUILD_TIME_KINDS.items():
            with self.subTest(kind=kind):
                tree = Tree()
                tree.add("plain", "1.0.0")
                tree.add("builder", "2.3.4", "lib", kind)
                violations = sc.check_build_time_code(tree.metadata(), {"other": "x"})
                self.assertIn(
                    f"build-time code: builder 2.3.4 has {description} ({kind} target) and is not on the allowlist",
                    violations[0],
                )
                self.assertEqual(len(violations), 2, violations)
                self.assertIn("allowlist entry other matches no package", violations[1])

    def test_both_kinds_in_one_package_are_named_once(self) -> None:
        tree = Tree()
        tree.add("both", "1.0.0", *sc.BUILD_TIME_KINDS)
        violations = sc.check_build_time_code(tree.metadata(), {})
        self.assertEqual(len(violations), 1, violations)
        for description in sc.BUILD_TIME_KINDS.values():
            self.assertIn(description, violations[0])

    def test_each_kind_on_the_allowlist_passes(self) -> None:
        for kind in sc.BUILD_TIME_KINDS:
            with self.subTest(kind=kind):
                tree = Tree()
                tree.add("builder", "1.0.0", "lib", kind)
                tree.add("builder", "2.0.0", "lib", kind)
                self.assertEqual(sc.check_build_time_code(tree.metadata(), {"builder": "reviewed"}), [])

    def test_allowlist_entry_without_a_reason_fails(self) -> None:
        tree = Tree()
        tree.add("builder", "1.0.0", "proc-macro")
        for reason in ("", "  "):
            with self.subTest(reason=reason):
                violations = sc.check_build_time_code(tree.metadata(), {"builder": reason})
                self.assertEqual(violations, ["build-time code: allowlist entry builder gives no reason"])

    def test_repository_allowlist_is_a_table_of_reasons(self) -> None:
        allowlist = tomllib.loads(sc.ALLOWLIST_FILE.read_text(encoding="utf-8"))["allowed"]
        self.assertIsInstance(allowlist, dict)
        for name, reason in allowlist.items():
            with self.subTest(name=name):
                self.assertIsInstance(reason, str)


class DuplicateExceptionTest(unittest.TestCase):
    """rand_chacha 0.2.2 forces rand_core 0.5.1 next to the workspace's rand_core 0.6.4."""

    def setUp(self) -> None:
        self.tree = Tree()
        member = self.tree.add("member", "0.0.0")
        new = self.tree.add("rand_core", "0.6.4")
        old = self.tree.add("rand_core", "0.5.1")
        chacha = self.tree.add("rand_chacha", "0.2.2")
        self.tree.depend(member, new)
        self.tree.depend(member, chacha)
        self.tree.depend(chacha, old)

    def check(self, skip: list, **bans: object) -> list[str]:
        return sc.check_duplicate_exceptions(self.tree.metadata(), {"bans": {"skip": skip, **bans}})

    def test_no_exception_passes(self) -> None:
        self.assertEqual(self.check([]), [])
        self.assertEqual(sc.check_duplicate_exceptions(self.tree.metadata(), {}), [])

    def test_exception_naming_the_forcing_dependency_passes(self) -> None:
        entry = {"crate": "rand_core@0.5.1", "reason": "forced by rand_chacha@0.2.2: no release on rand_core 0.6"}
        self.assertEqual(self.check([entry]), [])

    def test_malformed_exceptions_fail(self) -> None:
        cases = {
            "bare string": ("rand_core@0.5.1", "must be a table"),
            "no reason": ({"crate": "rand_core@0.5.1"}, "must be a table"),
            "extra field": (
                {"crate": "rand_core@0.5.1", "reason": "forced by rand_chacha@0.2.2: x", "depth": 1},
                "must be a table",
            ),
            "version range": ({"crate": "rand_core@<0.6", "reason": "forced by rand_chacha@0.2.2: x"}, "exact version"),
            "name only": ({"crate": "rand_core", "reason": "forced by rand_chacha@0.2.2: x"}, "exact version"),
            "reason without the forcing dependency": (
                {"crate": "rand_core@0.5.1", "reason": "old crate"},
                "forced by <name>@<version>: <why>",
            ),
            "reason without why": (
                {"crate": "rand_core@0.5.1", "reason": "forced by rand_chacha@0.2.2: "},
                "forced by <name>@<version>: <why>",
            ),
        }
        for label, (entry, fragment) in cases.items():
            with self.subTest(case=label):
                violations = self.check([entry])
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(fragment, violations[0])

    def test_exception_whose_forcing_dependency_does_not_force_it_fails(self) -> None:
        for forcing in ("member@0.0.0", "rand_chacha@0.2.1", "absent@1.0.0"):
            with self.subTest(forcing=forcing):
                violations = self.check([{"crate": "rand_core@0.5.1", "reason": f"forced by {forcing}: x"}])
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(f"forced by {forcing}, which does not depend on rand_core@0.5.1", violations[0])

    def test_stale_exceptions_fail(self) -> None:
        violations = self.check([{"crate": "rand_core@0.4.0", "reason": "forced by rand_chacha@0.2.2: x"}])
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("matches no package of the tree", violations[0])
        violations = self.check([{"crate": "rand_chacha@0.2.2", "reason": "forced by member@0.0.0: x"}])
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("is the only version of rand_chacha", violations[0])

    def test_skip_tree_fails(self) -> None:
        violations = self.check([], **{"skip-tree": [{"crate": "rand_chacha@0.2.2"}]})
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("skip-tree", violations[0])


class PrimitiveSourceTest(unittest.TestCase):
    """Story 4.1, AC1 and AC6, and its review (findings 3, 4, 6, 7): the primitive sources of D28
    and their recorded exceptions."""

    # An exception of D28 and its recorded amendment, as recorded_exceptions reads them.
    EXCEPTIONS = {"D61": {"D61", "D120"}, "D123": {"D123"}}

    def setUp(self) -> None:
        self.tree = Tree()
        self.member = self.tree.add("member", "0.0.0")
        self.features: dict[str, list[str]] = {}
        self.config = {
            "source": {
                "aws-lc-rs": {"record": "the audited library"},
                "kem": {"version": "1.0.0", "exception": ["D61", "D120"], "brings_primitives": True, "record": "x"},
                "stretch": {"version": "2.0.0", "exception": ["D123"], "forbidden_features": ["parallel"], "record": "y"},
            },
            "not_primitive": {"wiper": {"reason": "wipes memory"}},
        }
        self.tree.depend(self.member, self.cryptographic("wiper", "1.0.0"))

    def cryptographic(self, name: str, version: str, *, keyword: bool = False) -> str:
        package_id = self.tree.add(name, version)
        if keyword:
            self.tree.packages[package_id]["keywords"] = ["Crypto"]
        else:
            self.tree.packages[package_id]["categories"] = ["cryptography::cryptocurrencies"]
        return package_id

    def check(self, config: dict | None = None) -> tuple[list[str], list[str]]:
        metadata = self.tree.metadata()
        for node in metadata["resolve"]["nodes"]:
            node["features"] = self.features.get(node["id"], [])
        return sc.check_primitive_sources(metadata, config or self.config, self.EXCEPTIONS)

    def assert_single(self, *fragments: str) -> None:
        violations, _ = self.check()
        self.assertEqual(len(violations), 1, violations)
        for fragment in fragments:
            self.assertIn(fragment, violations[0])

    def kem_bringing(self, *names: tuple[str, str]) -> dict[str, str]:
        kem = self.cryptographic("kem", "1.0.0")
        self.tree.depend(self.member, kem)
        brought = {}
        for name, version in names:
            brought[name] = self.cryptographic(name, version)
            self.tree.depend(kem, brought[name])
        return brought

    def test_listed_sources_and_a_classified_package_reached_only_through_one_that_brings_its_own_pass(self) -> None:
        for name, version in (("aws-lc-rs", "3.1.0"), ("stretch", "2.0.0")):
            self.tree.depend(self.member, self.cryptographic(name, version))
        self.kem_bringing(("curve", "4.0.0"))
        violations, listing = self.check()
        self.assertEqual(violations, [])
        self.assertIn(
            "primitive source: kem 1.0.0 (exception to D28: D61, D120; in the tree at 1.0.0; "
            "with the primitive crates it depends on: curve 4.0.0): x",
            listing,
        )

    def test_a_classified_package_off_the_list_fails_by_category_or_keyword(self) -> None:
        for keyword in (False, True):
            with self.subTest(keyword=keyword):
                self.setUp()
                self.tree.depend(self.member, self.cryptographic("homemade", "0.1.0", keyword=keyword))
                self.assert_single("homemade 0.1.0 is classified as cryptographic and is neither a primitive source")

    def test_a_package_a_source_brings_is_not_covered_where_a_member_reaches_it_another_way(self) -> None:
        # The review's probe: hpke brings aes-gcm 0.10.3, and a member also depends on it.
        brought = self.kem_bringing(("cipher", "0.10.3"))
        self.tree.depend(self.member, brought["cipher"])
        self.assert_single("cipher 0.10.3 is classified as cryptographic")

    def test_coverage_is_by_package_id_not_by_name(self) -> None:
        # Another version of a crate the source brings, reached directly: not covered.
        self.kem_bringing(("cipher", "0.10.3"))
        self.tree.depend(self.member, self.cryptographic("cipher", "0.11.0"))
        self.assert_single("cipher 0.11.0 is classified as cryptographic")

    def test_a_package_reached_through_a_non_source_beside_the_source_is_not_covered(self) -> None:
        brought = self.kem_bringing(("digest", "0.10.7"))
        helper = self.tree.add("helper", "1.0.0")
        self.tree.depend(self.member, helper)
        self.tree.depend(helper, brought["digest"])
        self.assert_single("digest 0.10.7 is classified as cryptographic")

    def test_argon2s_real_closure_is_covered_by_argon2_and_its_digest_is_not_hpkes(self) -> None:
        """argon2 0.6.0 with its dependency closure as `spikes/argon2id-params/Cargo.lock` resolves
        it, without the crates of its `parallel` feature, the crates.io-classified ones marked,
        beside hpke 0.13.0 bringing digest 0.10.7: each source covers its own versions only."""
        config = tomllib.loads(sc.PRIMITIVE_SOURCES_FILE.read_text(encoding="utf-8"))
        tree = Tree()
        crypto = tree.add("vilicus-crypto", "0.0.0")
        classified = {"argon2", "base64ct", "blake2", "digest", "block-buffer", "crypto-common", "password-hash",
                      "ctutils", "cmov", "zeroize", "hpke"}
        ids: dict[tuple[str, str], str] = {}

        def add(name: str, version: str) -> str:
            ids[(name, version)] = tree.add(name, version)
            if name in classified:
                tree.packages[ids[(name, version)]]["categories"] = ["cryptography", "no-std"]
            return ids[(name, version)]

        edges = {
            ("argon2", "0.6.0"): [("base64ct", "1.8.3"), ("blake2", "0.11.0"), ("cpufeatures", "0.3.1"),
                                  ("password-hash", "0.6.1"), ("zeroize", "1.9.1")],
            ("blake2", "0.11.0"): [("digest", "0.11.3")],
            ("digest", "0.11.3"): [("block-buffer", "0.12.1"), ("crypto-common", "0.2.2"), ("ctutils", "0.4.3")],
            ("block-buffer", "0.12.1"): [("hybrid-array", "0.4.15")],
            ("crypto-common", "0.2.2"): [("hybrid-array", "0.4.15")],
            ("hybrid-array", "0.4.15"): [("typenum", "1.20.1")],
            ("ctutils", "0.4.3"): [("cmov", "0.5.4")],
            ("password-hash", "0.6.1"): [("phc", "0.6.1")],
            ("phc", "0.6.1"): [("base64ct", "1.8.3")],
            ("hpke", "0.13.0"): [("digest", "0.10.7")],
        }
        for source, targets in edges.items():
            source_id = ids.get(source) or add(*source)
            for target in targets:
                tree.depend(source_id, ids.get(target) or add(*target))
        tree.depend(crypto, ids[("argon2", "0.6.0")])
        tree.depend(crypto, ids[("hpke", "0.13.0")])
        tree.depend(crypto, ids[("zeroize", "1.9.1")])

        def check(metadata_tree: Tree, features: dict[str, list[str]] | None = None) -> tuple[list[str], list[str]]:
            metadata = metadata_tree.metadata()
            for node in metadata["resolve"]["nodes"]:
                node["features"] = (features or {}).get(node["id"], [])
            exceptions = sc.recorded_exceptions(sc.DECISIONS_FILE.read_text(encoding="utf-8"))
            return sc.check_primitive_sources(metadata, config, exceptions)

        violations, listing = check(tree)
        self.assertEqual(violations, [])
        argon2 = next(line for line in listing if line.startswith("primitive source: argon2 "))
        for crate in ("blake2 0.11.0", "digest 0.11.3", "block-buffer 0.12.1", "crypto-common 0.2.2", "password-hash 0.6.1"):
            self.assertIn(crate, argon2)
        self.assertNotIn("base64ct", argon2)
        hpke = next(line for line in listing if line.startswith("primitive source: hpke "))
        self.assertIn("digest 0.10.7", hpke)
        self.assertNotIn("digest 0.11.3", hpke)

        # Usage rule U1 of doc/qa/argon2-review.md: `zeroize` alone passes, and each feature the
        # record forbids fails on its own, whatever else is enabled.
        argon2_id = ids[("argon2", "0.6.0")]
        violations, _ = check(tree, {argon2_id: ["zeroize"]})
        self.assertEqual(violations, [])
        forbidden = config["source"]["argon2"]["forbidden_features"]
        self.assertTrue({"parallel", "alloc"} <= set(forbidden), forbidden)
        for feature in forbidden:
            with self.subTest(feature=feature):
                violations, _ = check(tree, {argon2_id: ["zeroize", feature]})
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(f"argon2 0.6.0 has the feature `{feature}`", violations[0])

        # The Core reaching argon2's digest directly loses the coverage.
        tree.depend(crypto, ids[("digest", "0.11.3")])
        violations, _ = check(tree)
        self.assertTrue(any("digest 0.11.3 is classified as cryptographic" in v for v in violations), violations)
        self.assertFalse(any(v.startswith("primitive sources: blake2 ") for v in violations), violations)

    def test_a_source_at_another_version_than_its_record_fails(self) -> None:
        self.tree.depend(self.member, self.cryptographic("kem", "1.0.1"))
        self.assert_single("kem 1.0.1 is in the tree, and its record is for 1.0.0")

    def test_a_forbidden_feature_fails(self) -> None:
        stretch = self.cryptographic("stretch", "2.0.0")
        self.tree.depend(self.member, stretch)
        self.features[stretch] = ["alloc", "parallel"]
        self.assert_single("stretch 2.0.0 has the feature `parallel`, which its record forbids")

    def test_every_exception_must_be_one_of_d28_or_a_recorded_amendment(self) -> None:
        self.config["source"]["stretch"]["exception"] = ["D123", "D9999"]
        self.assert_single("stretch names D9999, which is neither an exception of D28's row")
        self.setUp()
        self.config["source"]["kem"]["exception"] = ["D99"]
        violations, _ = self.check()
        self.assertEqual(len(violations), 2, violations)
        self.assertIn("kem names D99", violations[0])
        self.assertIn("D28's exception D61 has no source", violations[1])

    def test_an_amendment_alone_names_its_exception(self) -> None:
        self.config["source"]["kem"]["exception"] = ["D120"]
        self.assertEqual(self.check()[0], [])

    def test_only_the_audited_sources_go_without_an_exception(self) -> None:
        # The review's probe: a new source with no exception at all.
        self.config["source"]["ring"] = {"record": "faster"}
        self.assert_single("ring names no exception; only aws-lc-rs, aws-lc-sys are sources without one")
        self.setUp()
        self.config["source"]["aws-lc-rs"]["exception"] = ["D61"]
        self.assert_single("aws-lc-rs is an audited source of D28 and names an exception")

    def test_entries_without_a_record_or_a_reason_fail(self) -> None:
        self.config["source"]["aws-lc-rs"]["record"] = " "
        self.assert_single("aws-lc-rs gives no record")
        self.setUp()
        self.config["not_primitive"]["wiper"] = {"reason": ""}
        self.assert_single("not_primitive entry wiper gives no reason")

    def test_d28_exceptions_are_read_from_its_exceptions_clause_only(self) -> None:
        row = sc.DECISIONS_FILE.read_text(encoding="utf-8").split("\n| D28 |", 1)[1].split("\n", 1)[0]
        status = row.split("|")[1].strip()
        self.assertIn("exceptions in ", status)
        # D153 will amend D28 and D129; the "amended by" clause names no exception.
        amended = f"{status}, amended by D153"
        table = f"| D28 | Supply chain controls | {amended} |\n| D129 | argon2 | Accepted, amended by D153 |\n"
        table += "| D61 | HPKE | Accepted, amended by D74, D107 and D120 |\n| D123 | OPAQUE | Accepted |\n"
        self.assertEqual(sc.d28_exceptions(table), sc.d28_exceptions(sc.DECISIONS_FILE.read_text(encoding="utf-8")))
        self.assertNotIn("D153", sc.d28_exceptions(table))
        self.assertEqual(sc.recorded_exceptions(table)["D129"], {"D129", "D153"})
        self.assertEqual(sc.recorded_exceptions(table)["D61"], {"D61", "D74", "D107", "D120"})

    def test_the_repository_list_agrees_with_d28_and_names_the_sources_of_its_records(self) -> None:
        config = tomllib.loads(sc.PRIMITIVE_SOURCES_FILE.read_text(encoding="utf-8"))
        exceptions = sc.recorded_exceptions(sc.DECISIONS_FILE.read_text(encoding="utf-8"))
        violations, listing = sc.check_primitive_sources(Tree().metadata(), config, exceptions)
        self.assertEqual(violations, [])
        self.assertEqual(len(listing), len(config["source"]))
        # Written out on purpose: the sources and pins of AC6 of Story 4.1 (D28, D120, D123, D129).
        for name, pin, exception in (
            ("aws-lc-rs", "", "no exception"),
            ("hpke", " 0.13.0", "exception to D28: D61, D120"),
            ("argon2", " 0.6.0", "exception to D28: D129"),
            ("opaque-ke", " 4.0.1", "exception to D28: D123"),
        ):
            with self.subTest(source=name):
                self.assertTrue(
                    any(line.startswith(f"primitive source: {name}{pin} ({exception};") for line in listing),
                    listing,
                )
        for name in ("hpke", "argon2"):
            line = next(line for line in listing if line.startswith(f"primitive source: {name} "))
            self.assertIn("with the primitive crates it depends on", line)
        argon2 = next(line for line in listing if line.startswith("primitive source: argon2 "))
        for feature in config["source"]["argon2"]["forbidden_features"]:
            self.assertIn(f"`{feature}`", argon2)
        self.assertIn("without `parallel`", argon2)
        self.assertIn("blake2", argon2)


class VendorTest(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.committed = Path(temp.name) / "committed"
        self.fresh = Path(temp.name) / "fresh"

    def write(self, root: Path, relative: str, content: bytes) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_no_vendored_crate_on_either_side_passes(self) -> None:
        self.assertEqual(sc.vendor_differences(self.committed, self.fresh), [])

    def test_identical_trees_pass(self) -> None:
        for root in (self.committed, self.fresh):
            self.write(root, "itoa-1.0.15/src/lib.rs", b"code\n")
            self.write(root, "itoa-1.0.15/.cargo-checksum.json", b"{}")
        self.assertEqual(sc.vendor_differences(self.committed, self.fresh), [])

    def test_missing_extra_and_changed_files_fail(self) -> None:
        self.write(self.fresh, "a-1.0.0/src/lib.rs", b"code\n")
        self.write(self.fresh, "b-1.0.0/src/lib.rs", b"code\n")
        self.write(self.committed, "b-1.0.0/src/lib.rs", b"code\r\n")
        self.write(self.committed, "c-1.0.0/src/lib.rs", b"code\n")
        self.assertEqual(
            sc.vendor_differences(self.committed, self.fresh),
            [
                "vendor: a-1.0.0/src/lib.rs is missing from vendor/",
                "vendor: vendor/c-1.0.0/src/lib.rs is not written by cargo vendor from Cargo.lock",
                "vendor: vendor/b-1.0.0/src/lib.rs differs from what cargo vendor writes",
            ],
        )


@unittest.skipUnless(shutil.which("cargo"), "cargo is needed for the end-to-end test")
class EndToEndTest(unittest.TestCase):
    """The build-time code check on what a real `cargo metadata` reports, without the network."""

    def test_build_script_and_procedural_macro_are_named_on_real_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["*"]\n', encoding="utf-8")
            for name, extra in (("with-build", ""), ("macro", "\n[lib]\nproc-macro = true\n"), ("plain", "")):
                (root / name / "src").mkdir(parents=True)
                (root / name / "src" / "lib.rs").write_text("", encoding="utf-8")
                (root / name / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2024"\n{extra}', encoding="utf-8"
                )
            (root / "with-build" / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
            output = subprocess.run(
                ["cargo", "metadata", "--format-version", "1", "--offline", "--all-features"],
                cwd=root,
                check=True,
                capture_output=True,
            ).stdout
            metadata = json.loads(output)

        violations = sc.check_build_time_code(metadata, {})
        self.assertEqual(len(violations), 2, violations)
        self.assertIn("macro 0.1.0 has a procedural macro (proc-macro target)", violations[0])
        self.assertIn("with-build 0.1.0 has a build script (custom-build target)", violations[1])
        self.assertEqual(sc.check_build_time_code(metadata, {"macro": "test", "with-build": "test"}), [])


def stack_versions() -> dict[str, str]:
    """Name -> version for every row of the spine's Stack table, `a / b | 1 / 2` rows split."""
    section = SPINE.read_text(encoding="utf-8").split("\n## Stack\n", 1)[1].split("\n## ", 1)[0]
    versions = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2:
            continue
        names, values = cells[0].split(" / "), cells[1].split(" / ")
        if len(names) == len(values):
            versions.update(zip(names, values))
    return versions


# The merge gates of AD-33 this workflow carries, written out by hand on purpose: the job id, the
# check name a branch protection rule requires, and the command lines that must appear whole in the job,
# so that dropping a job, renaming its check, or losing `-D warnings`, `--frozen`, `--locked` or
# the audit report check (`cargo audit --deny warnings` with reasoned exceptions) turns this test
# red.
GATE_JOBS = {
    "workspace-policy": (
        "Policy - workspace, unsafe code and vendored sources",
        (
            "python3 -m unittest discover -s ci -v",
            "python3 ci/check_workspace.py",
            "python3 ci/check_supply_chain.py",
            "python3 ci/check_supply_chain.py --vendor",
            "python3 ci/check_sqlcipher_source.py",
            "python3 ci/check_packaging.py",
            "python3 ci/release_gates.py check",
        ),
    ),
    "lint": (
        "Build - format and lint",
        (
            "dpkg -s libssl-dev | grep -E '^(Status|Version):'",
            "pkg-config --modversion openssl",
            "cargo fmt --all --check",
            "cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings",
        ),
    ),
    "build-and-test": (
        "Build - compile and test",
        (
            "dpkg -s libssl-dev | grep -E '^(Status|Version):'",
            "pkg-config --modversion openssl",
            "cargo build --workspace --frozen --config ci/cargo-vendored.toml",
            "cargo test --workspace --frozen --config ci/cargo-vendored.toml",
        ),
    ),
    "deny": ("Supply chain - cargo deny", ("cargo deny --locked check",)),
    "vet": ("Supply chain - cargo vet", ("cargo vet --locked",)),
    "audit": (
        "Supply chain - cargo audit",
        (
            'cargo audit --json > "$RUNNER_TEMP/audit.json" || true',
            'python3 ci/check_audit_report.py ci/audit-exceptions.toml "$RUNNER_TEMP/audit.json"',
        ),
    ),
    "hpke-review": (
        "Crypto - HPKE vectors and cross-test",
        (
            'run="$(python3 ci/must_run.py --event "$EVENT" --base "$BASE" "${watched[@]}")"',
            "bash spikes/hpke-review/run.sh",
            'cargo audit --file spikes/hpke-review/Cargo.lock --json > "$RUNNER_TEMP/hpke-audit.json" || true',
            'python3 ci/check_audit_report.py spikes/hpke-review/audit-exceptions.toml "$RUNNER_TEMP/hpke-audit.json"',
        ),
    ),
    "sqlcipher-regenerate": (
        "Supply chain - SQLCipher matches its tag",
        (
            'run="$(python3 ci/must_run.py --event "$EVENT" --base "$BASE" "${watched[@]}")"',
            'docker run --rm -v "$PWD:/w:ro" -w /w rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a bash crates/vilicus-storage/sqlcipher/regenerate.sh',
        ),
    ),
}
# Gate jobs whose steps after a path detection run only when it says so (ci/must_run.py).
PATH_FILTERED_JOBS = ("hpke-review", "sqlcipher-regenerate")
# The Debian 13 VM job of Story 2.3, written out by hand like GATE_JOBS. It is not a merge gate
# yet, so it may run its result collection and its teardown under `if: always()`, and the smoke
# and the release gates of Story 2.6 on any booted VM, even after a failed run step, so that the
# AC3 journals and the gate logs are collected; nothing else is conditional. The check of nested
# virtualisation comes first, right after the checkout (AC1), and a guest `exit 3` must come back
# as 3 (AC2).
VM_JOB = (
    "vm-smoke",
    "End to end - Debian 13 VM smoke test",
    "sudo python3 ci/vm_harness.py check-kvm",
    (
        "dpkg -s libssl-dev | grep -E '^(Status|Version):'",
        "pkg-config --modversion openssl",
        "python3 ci/release_gates.py build",
        "python3 ci/vm_harness.py up",
        "python3 ci/vm_harness.py copy target/debug/vilicus",
        "python3 ci/vm_harness.py run -- 'exit 3' || status=$?",
        'test "$status" -eq 3',
        "python3 ci/vm_harness.py smoke --out \"$VM_RESULTS\"",
        "python3 ci/release_gates.py run --out \"$VM_RESULTS/release-gates\"",
        "python3 ci/vm_harness.py collect --out \"$VM_RESULTS\"",
        "python3 ci/vm_harness.py down",
    ),
)
# The fuzz job of Story 2.7, written out by hand like GATE_JOBS: its check name, the dated nightly
# it alone installs, and its run of ci/fuzz.py. The upload of the failing inputs is the only step
# that runs once the job has failed, and nothing in the job is allowed to fail.
FUZZ_JOB = (
    "fuzz",
    "Fuzz - vilicus-proto decoders",
    (
        'rustup toolchain install "$FUZZ_TOOLCHAIN" --profile minimal',
        'python3 ci/check_fuzz_coverage.py --toolchain "$FUZZ_TOOLCHAIN"',
        'python3 ci/fuzz.py --toolchain "$FUZZ_TOOLCHAIN" --seconds "$FUZZ_SECONDS" --out "$FUZZ_OUT"',
    ),
)
FUZZ_UPLOAD_CONDITION = "failure() || cancelled()"
# What the fuzz job's timeout must hold besides fuzzing and minimization: the nightly install, the
# rustdoc and plan builds, and the build of every target with AddressSanitizer.
FUZZ_BUILD_MARGIN_MINUTES = 20
# Only the fuzz job may compile the fuzzing runtime: no other job enables every feature or the
# `libfuzzer` feature of vilicus-fuzz.
FUZZING_FEATURE = re.compile(r"--all-features|--features[ =]\S*libfuzzer|-F *\S*libfuzzer")
FUZZ_BUDGET = re.compile(r"FUZZ_SECONDS: \$\{\{ github\.event_name == 'schedule' && '(\d+)' \|\| '(\d+)' \}\}")
VM_ALWAYS_STEPS = ("ci/vm_harness.py collect", "actions/upload-artifact@", "ci/vm_harness.py down")
VM_BOOTED_STEPS = ("ci/vm_harness.py smoke", "ci/release_gates.py run ")
VM_BOOTED_CONDITION = "${{ !cancelled() && steps.up.outcome == 'success' }}"
# Steps that wait on the guest and so carry their own timeout, below the job's.
VM_TIMED_STEPS = ("ci/vm_harness.py up", "ci/vm_harness.py run ", *VM_BOOTED_STEPS)
PINNED_ACTION = re.compile(r"uses: (\./\S+|[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40} # v\d+(\.\d+)*)$")
# Workspace cargo subcommands that compile or fetch crates; each must read the vendored sources.
# `cargo fmt` reads no dependency, and the cargo-deny, cargo-vet and cargo-audit runs read
# metadata or the lockfile only.
VENDORED_SUBCOMMANDS = re.compile(r"\bcargo (build|test|clippy|check|run|doc|vendor|metadata)\b")
TRIGGERS = ("push", "pull_request", "merge_group", "workflow_dispatch", "schedule")


def workflow_jobs(text: str) -> dict[str, str]:
    """Job id -> the job's lines, split on the two-space keys under `jobs:`."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\n", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2]))


def command_lines(job: str) -> set[str]:
    """Every shell line of a job: one-line `run:` values and the lines of `run: |` blocks."""
    lines = set()
    for line in job.splitlines():
        stripped = line.strip()
        lines.add(stripped.removeprefix("run: ") if stripped.startswith("run: ") else stripped)
    return lines


class WorkflowAgreementTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.jobs = workflow_jobs(self.text)

    def test_each_gate_job_has_its_check_name_and_its_commands(self) -> None:
        for job_id, (name, commands) in GATE_JOBS.items():
            with self.subTest(job=job_id):
                self.assertIn(job_id, self.jobs)
                job = self.jobs[job_id]
                self.assertIn(f"    name: {name}\n", job)
                lines = command_lines(job)
                for command in commands:
                    self.assertIn(command, lines)

    def test_no_gate_step_is_skipped_or_allowed_to_fail(self) -> None:
        self.assertNotIn("continue-on-error", self.text)
        for job_id in GATE_JOBS:
            job = self.jobs[job_id]
            with self.subTest(job=job_id):
                self.assertNotRegex(job, r"(?m)^    if:")
                if job_id not in PATH_FILTERED_JOBS:
                    self.assertNotRegex(job, r"(?m)^\s+if:")

    def test_path_filtered_steps_after_the_detection_run_only_on_its_decision(self) -> None:
        for job_id in PATH_FILTERED_JOBS:
            steps = self.jobs[job_id].split("\n      - ")
            detection = next(i for i, step in enumerate(steps) if "id: changes" in step)
            self.assertLess(detection, len(steps) - 1, job_id)
            for step in steps[detection + 1 :]:
                with self.subTest(job=job_id, step=step.splitlines()[0]):
                    self.assertIn("if: steps.changes.outputs.run == 'true'", step)

    def test_sqlcipher_regeneration_watches_the_vendored_source(self) -> None:
        job = self.jobs["sqlcipher-regenerate"]
        self.assertIn("crates/vilicus-storage/sqlcipher", job)
        self.assertIn("ci/check_sqlcipher_source.py", job)
        self.assertIn('-v "$PWD:/w:ro"', job)

    def test_every_workspace_cargo_build_reads_the_vendored_sources(self) -> None:
        flag = f"--config {sc.VENDORED_CONFIG_FILE}"
        commands = [
            line
            for job_id, job in self.jobs.items()
            if job_id != "hpke-review"
            for line in command_lines(job)
            if VENDORED_SUBCOMMANDS.search(line)
        ]
        self.assertTrue(commands)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn(flag, command)

    def test_scripts_pass_the_vendored_configuration_to_cargo(self) -> None:
        for function in (
            sc.cargo_metadata,
            sc.check_vendor,
            cw.cargo_metadata,
            rg.cargo_build_commands,
            fz.plan_command,
            fz.build_command,
        ):
            with self.subTest(function=f"{function.__module__}.{function.__name__}"):
                source = inspect.getsource(function)
                self.assertIn('"--config"', source)
                self.assertRegex(source, r"VENDORED_CONFIG_FILE")
        self.assertEqual(sc.VENDORED_CONFIG_FILE, cw.VENDORED_CONFIG_FILE.as_posix())

    def test_fuzz_job_runs_every_target_on_a_nightly_pinned_by_date(self) -> None:
        job_id, name, commands = FUZZ_JOB
        self.assertIn(job_id, self.jobs)
        job = self.jobs[job_id]
        self.assertIn(f"    name: {name}\n", job)
        lines = command_lines(job)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn(command, lines)
        toolchain = re.search(r"(?m)^      FUZZ_TOOLCHAIN: (\S+)$", job)
        self.assertIsNotNone(toolchain)
        self.assertRegex(toolchain.group(1), fz.DATED_NIGHTLY)
        # The nightly is the fuzz job's alone: rust-toolchain.toml stays on stable, and no other
        # job names the nightly.
        channel = tomllib.loads((sc.REPO_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
        self.assertNotIn("nightly", channel)
        others = "".join(text for other, text in self.jobs.items() if other != job_id)
        self.assertNotRegex(others, r"nightly-\d|\+nightly|FUZZ_TOOLCHAIN")

    def test_fuzz_job_budget_is_short_on_changes_and_longer_on_the_schedule(self) -> None:
        budget = FUZZ_BUDGET.search(self.jobs[FUZZ_JOB[0]])
        self.assertIsNotNone(budget)
        scheduled, otherwise = (int(seconds) for seconds in budget.groups())
        self.assertGreater(otherwise, 0)
        self.assertGreater(scheduled, otherwise)

    def test_fuzz_job_runs_only_its_upload_after_a_failure(self) -> None:
        steps = self.jobs[FUZZ_JOB[0]].split("\n      - ")[1:]
        for step in steps:
            with self.subTest(step=step.splitlines()[0]):
                conditions = re.findall(r"(?m)^\s+if: (.*)$", step)
                if "actions/upload-artifact@" in step:
                    self.assertEqual(conditions, [FUZZ_UPLOAD_CONDITION])
                else:
                    self.assertEqual(conditions, [])

    def test_fuzz_job_timeout_holds_the_scheduled_budget_of_every_target(self) -> None:
        job = self.jobs[FUZZ_JOB[0]]
        timeout = re.search(r"(?m)^    timeout-minutes: (\d+)$", job)
        self.assertIsNotNone(timeout)
        scheduled = int(FUZZ_BUDGET.search(job).group(1))
        targets = [path.stem for path in (sc.REPO_ROOT / "fuzz" / "src" / "bin").glob("*.rs") if path.stem != fz.PLAN_BINARY]
        self.assertTrue(targets)
        needed = len(targets) * (scheduled + fz.MINIMIZE_SECONDS) / 60 + FUZZ_BUILD_MARGIN_MINUTES
        self.assertGreaterEqual(int(timeout.group(1)), needed)

    def test_no_job_but_the_fuzz_job_builds_the_fuzzing_runtime(self) -> None:
        for job_id, job in self.jobs.items():
            if job_id == FUZZ_JOB[0]:
                continue
            for line in command_lines(job):
                with self.subTest(job=job_id, line=line):
                    self.assertNotRegex(line, FUZZING_FEATURE)
        self.assertRegex("cargo build --all-features", FUZZING_FEATURE)
        self.assertRegex("cargo test -p vilicus-fuzz --features libfuzzer", FUZZING_FEATURE)
        self.assertRegex("cargo build -F vilicus-fuzz/libfuzzer", FUZZING_FEATURE)

    def test_triggers_include_the_merge_queue_and_the_weekly_run(self) -> None:
        triggers = self.text.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        for trigger in TRIGGERS:
            with self.subTest(trigger=trigger):
                self.assertRegex(triggers, rf"(?m)^  {trigger}:")
        self.assertRegex(triggers, r'(?m)^    - cron: "[^"]+"$')

    def test_every_cargo_tool_of_the_workflow_is_at_its_stack_version(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"uses: \./\.github/actions/cargo-tool\n\s+with:\n\s+tool: (\S+)\n\s+version: (\S+)\n", workflow)
        self.assertEqual(len(uses), workflow.count("uses: ./.github/actions/cargo-tool"))
        self.assertTrue(uses)
        stack = stack_versions()
        for tool, version in uses:
            with self.subTest(tool=tool):
                self.assertEqual(stack.get(tool), version)

    def test_vm_job_checks_nested_virtualisation_first_and_runs_the_harness(self) -> None:
        job_id, name, first, commands = VM_JOB
        self.assertIn(job_id, self.jobs)
        job = self.jobs[job_id]
        self.assertIn(f"    name: {name}\n", job)
        lines = command_lines(job)
        for command in (first, *commands):
            with self.subTest(command=command):
                self.assertIn(command, lines)
        self.assertTrue(any(line.startswith("python3 ci/vm_harness.py run ") for line in lines))
        steps = job.split("\n      - ")[1:]
        self.assertTrue(steps[0].startswith("uses: actions/checkout@"))
        self.assertIn(first, command_lines(steps[1]))

    def test_vm_job_runs_only_its_collection_and_teardown_under_always(self) -> None:
        steps = self.jobs[VM_JOB[0]].split("\n      - ")[1:]
        for step in steps:
            with self.subTest(step=step.splitlines()[0]):
                conditions = re.findall(r"(?m)^\s+if: (.*)$", step)
                if any(marker in step for marker in VM_ALWAYS_STEPS):
                    self.assertEqual(conditions, ["always()"])
                elif any(marker in step for marker in VM_BOOTED_STEPS):
                    self.assertEqual(conditions, [VM_BOOTED_CONDITION])
                else:
                    self.assertEqual(conditions, [])

    def test_vm_job_smoke_condition_names_the_boot_step_and_guest_steps_time_out(self) -> None:
        steps = self.jobs[VM_JOB[0]].split("\n      - ")[1:]
        boot = [step for step in steps if "run: python3 ci/vm_harness.py up\n" in step + "\n"]
        self.assertEqual(len(boot), 1)
        self.assertRegex(boot[0], r"(?m)^\s+id: up$")
        for marker in VM_TIMED_STEPS:
            matching = [step for step in steps if marker in step]
            self.assertTrue(matching, marker)
            for step in matching:
                with self.subTest(step=step.splitlines()[0]):
                    self.assertRegex(step, r"(?m)^\s+timeout-minutes: \d+$")

    def test_vm_job_caches_the_image_by_its_lock(self) -> None:
        job = self.jobs[VM_JOB[0]]
        self.assertIn("key: debian-cloud-image-${{ hashFiles('e2e/vm/IMAGE.lock') }}", job)
        self.assertIn("path: ${{ env.VM_IMAGES_DIR }}", job)
        self.assertRegex(job, r"(?m)^      VM_IMAGES_DIR: ")

    def test_every_action_is_local_or_pinned_by_commit_with_its_version(self) -> None:
        files = [WORKFLOW, *sorted((sc.REPO_ROOT / ".github" / "actions").rglob("action.yml"))]
        uses = [
            (path.name, line.strip().removeprefix("- "))
            for path in files
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().removeprefix("- ").startswith("uses:")
        ]
        self.assertTrue(uses)
        for path, line in uses:
            with self.subTest(file=path, line=line):
                self.assertRegex(line, PINNED_ACTION)

    def test_workflow_reads_the_repository_only(self) -> None:
        self.assertIn("\npermissions:\n  contents: read\n", self.text)
        for job_id, job in self.jobs.items():
            with self.subTest(job=job_id):
                self.assertNotIn("permissions:", job)

    def test_repository_deny_configuration_denies_every_duplicate_and_git_source(self) -> None:
        config = tomllib.loads(sc.DENY_FILE.read_text(encoding="utf-8"))
        self.assertEqual(config["bans"]["multiple-versions"], "deny")
        self.assertEqual(config["sources"]["unknown-git"], "deny")
        self.assertEqual(config["sources"].get("allow-git", []), [])


if __name__ == "__main__":
    unittest.main()
