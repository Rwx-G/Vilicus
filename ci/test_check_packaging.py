"""Tests for ci/check_packaging.py, over synthetic `cargo metadata` documents derived from
ci/crate_graph.toml and ci/release_artefacts.toml, plus a run on the repository's own metadata.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import copy
import fnmatch
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

import check_packaging as cp
import check_workspace as cw
import test_check_workspace as tcw

CONFIG = tomllib.loads(cp.ARTEFACTS_FILE.read_text(encoding="utf-8"))
GRAPH = tcw.GRAPH
# A test double next to the node samples, so that the testbed artefact holds more than one
# executable, as it does in the repository.
DOUBLE = "vilicus-double-sample"


class Metadata:
    """An in-memory `cargo metadata` document: one sample crate per node of the graph, an edge per
    `depends_on`, and a test double under the dev-only path."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.packages: dict[str, dict] = {}
        for node in GRAPH.nodes.values():
            name, directory = tcw.sample_crate(node)
            self.add(name, directory, "bin" if node.shipped or node.id == "testbed" else "lib")
        testing = next(node for node in GRAPH.nodes.values() if node.dev_only)
        self.add(DOUBLE, f"{testing.paths[0]}/{DOUBLE}", "bin")
        names = self.node_names()
        for node in GRAPH.nodes.values():
            for target in node.depends_on:
                self.depend(names[node.id], names[target])

    def node_names(self) -> dict[str, str]:
        return {node.id: tcw.sample_crate(node)[0] for node in GRAPH.nodes.values()}

    def add(self, name: str, directory: str, kind: str = "lib", target_name: str | None = None) -> None:
        crate_dir = self.root / directory
        self.packages[name] = {
            "id": f"path+file://{crate_dir.as_posix()}#{name}@0.0.0",
            "name": name,
            "manifest_path": str(crate_dir / "Cargo.toml"),
            "targets": [{"kind": [kind], "name": target_name or name, "src_path": str(crate_dir / "src" / "lib.rs")}],
            "dependencies": [],
        }

    def depend(self, source: str, target: str, kind: str = "normal") -> None:
        target_dir = Path(self.packages[target]["manifest_path"]).parent
        self.packages[source]["dependencies"].append(
            {"name": target, "kind": None if kind == "normal" else kind, "path": str(target_dir)}
        )

    def document(self) -> dict:
        return {
            "packages": list(self.packages.values()),
            "workspace_members": [package["id"] for package in self.packages.values()],
            "workspace_root": str(self.root),
        }


class PackagingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.metadata = Metadata(Path(temp.name))
        self.names = self.metadata.node_names()
        self.shipped = next(self.names[node.id] for node in GRAPH.nodes.values() if node.shipped)

    def check(self, config: dict = CONFIG) -> list[str]:
        return cp.check_artefacts(self.metadata.document(), GRAPH, config)

    def never_packaged(self) -> dict[str, str]:
        found = cp.never_packaged_crates(self.metadata.document(), GRAPH, CONFIG)
        self.assertTrue(found)
        return found

    def with_artefact(self, package: str, binary: str) -> dict:
        config = copy.deepcopy(CONFIG)
        config["artefact"]["extra"] = {"package": package, "binary": binary}
        return config


class ArtefactTest(PackagingTestCase):
    def test_repository_artefacts_over_the_declared_graph_pass(self) -> None:
        self.assertEqual(self.check(), [])

    def test_repository_artefacts_are_built_by_the_shipped_node(self) -> None:
        shipped = {self.names[node.id] for node in GRAPH.nodes.values() if node.shipped}
        for artefact in cp.load_artefacts(CONFIG):
            with self.subTest(artefact=artefact.name):
                self.assertIn(artefact.package, shipped)

    def test_never_packaged_crates_are_those_of_the_listed_nodes(self) -> None:
        found = self.never_packaged()
        self.assertEqual(set(found.values()), set(CONFIG["never_packaged"]))
        self.assertIn(DOUBLE, found)

    def test_artefact_built_from_a_never_packaged_crate_fails(self) -> None:
        members = cp.workspace_members(self.metadata.document())
        for name, node_id in self.never_packaged().items():
            for binary in cp.bin_targets(members[name]):
                with self.subTest(crate=name):
                    violations = "\n".join(self.check(self.with_artefact(name, binary)))
                    self.assertIn(f"is built from {name}, a crate of never-packaged node {node_id}", violations)
                    self.assertIn(f"carries the name of testbed executable {binary}", violations)

    def test_never_packaged_crate_linked_into_an_artefact_fails(self) -> None:
        for name in self.never_packaged():
            for kind in sorted(cw.LINKED_KINDS):
                with self.subTest(crate=name, kind=kind):
                    self.setUp()
                    self.metadata.depend(self.shipped, name, kind)
                    violations = self.check()
                    self.assertTrue(any(f"links {name}, a crate of never-packaged node" in v for v in violations), violations)

    def test_never_packaged_crate_linked_at_depth_names_the_path(self) -> None:
        core = self.names["core"]
        self.metadata.depend(core, DOUBLE)
        violations = self.check()
        self.assertEqual(len(violations), 1, violations)
        self.assertIn(f"({self.shipped} -> {core} -> {DOUBLE}; D102)", violations[0])

    def test_never_packaged_crate_as_dev_dependency_of_an_artefact_passes(self) -> None:
        for name in self.never_packaged():
            self.metadata.depend(self.shipped, name, "dev")
        self.assertEqual(self.check(), [])

    def test_artefact_named_like_a_testbed_executable_fails(self) -> None:
        artefact = cp.load_artefacts(CONFIG)[0]
        testing = next(node for node in GRAPH.nodes.values() if node.dev_only)
        self.metadata.add("vilicus-double-clash", f"{testing.paths[0]}/vilicus-double-clash", "bin", artefact.binary)
        violations = self.check()
        self.assertEqual(len(violations), 1, violations)
        self.assertIn(f"carries the name of testbed executable {artefact.binary}", violations[0])

    def test_artefact_named_by_the_pattern_of_a_never_packaged_node_fails(self) -> None:
        patterned = [GRAPH.nodes[node_id] for node_id in CONFIG["never_packaged"] if GRAPH.nodes[node_id].pattern]
        self.assertTrue(patterned)
        for node in patterned:
            with self.subTest(node=node.id):
                self.setUp()
                binary = node.pattern.replace("*", "mail")
                self.metadata.packages[self.shipped]["targets"].append({"kind": ["bin"], "name": binary, "src_path": "x"})
                violations = self.check(self.with_artefact(self.shipped, binary))
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(f"matches {node.pattern}, the name pattern of never-packaged node {node.id}", violations[0])

    def test_artefact_of_an_unknown_package_or_binary_fails(self) -> None:
        violations = self.check(self.with_artefact("not-a-member", "x"))
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("names a package that is not a workspace member", violations[0])
        violations = self.check(self.with_artefact(self.shipped, "other-binary"))
        self.assertEqual(len(violations), 1, violations)
        self.assertIn(f"names a binary that {self.shipped} does not build", violations[0])


class ConfigTest(PackagingTestCase):
    def test_malformed_configuration_fails(self) -> None:
        shipped_node = next(node.id for node in GRAPH.nodes.values() if node.shipped)
        cases = {
            "unknown key": ({**CONFIG, "extra": 1}, "unknown key 'extra'"),
            "no never_packaged": ({"artefact": CONFIG["artefact"]}, "never_packaged must list"),
            "empty never_packaged": ({**CONFIG, "never_packaged": []}, "never_packaged must list"),
            "unknown node": ({**CONFIG, "never_packaged": ["nowhere"]}, "'nowhere', which is not a node"),
            "shipped node": ({**CONFIG, "never_packaged": [shipped_node]}, "which ci/crate_graph.toml marks shipped"),
            "no artefact": ({"never_packaged": CONFIG["never_packaged"]}, "no [artefact.*] entry"),
            "artefact without binary": (
                {**CONFIG, "artefact": {"x": {"package": self.shipped}}},
                "must hold exactly `package` and `binary`",
            ),
            "artefact with another key": (
                {**CONFIG, "artefact": {"x": {"package": self.shipped, "binary": self.shipped, "path": "/usr/bin"}}},
                "must hold exactly `package` and `binary`",
            ),
            "empty binary": (
                {**CONFIG, "artefact": {"x": {"package": self.shipped, "binary": ""}}},
                "must hold exactly `package` and `binary`",
            ),
        }
        for label, (config, fragment) in cases.items():
            with self.subTest(case=label):
                violations = self.check(config)
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(fragment, violations[0])


class ContentsTest(PackagingTestCase):
    def names_forbidden(self) -> set[str]:
        return cp.forbidden_names(self.metadata.document(), GRAPH, CONFIG)

    def test_listing_without_test_code_passes(self) -> None:
        listing = [f"/usr/bin/{artefact.binary}" for artefact in cp.load_artefacts(CONFIG)]
        listing += ["/usr/share/doc/vilicus/copyright", "/usr/lib/systemd/system/vilicus-core.service"]
        self.assertEqual(cp.check_contents(listing, self.names_forbidden()), [])

    def test_listing_naming_any_never_packaged_crate_or_target_fails(self) -> None:
        members = cp.workspace_members(self.metadata.document())
        for name in self.never_packaged():
            for target in (name, *(t["name"] for t in members[name]["targets"])):
                for path in (f"/usr/bin/{target}", f"/usr/lib/vilicus/lib{target.replace('-', '_')}.rlib", f"/opt/{target}/x"):
                    with self.subTest(path=path):
                        violations = cp.check_contents([path], self.names_forbidden())
                        self.assertEqual(len(violations), 1, violations)
                        self.assertIn(f"release file {path} names never-packaged", violations[0])


class SpineAgreementTest(unittest.TestCase):
    """The never-packaged nodes are those the AD-3 flowchart labels dev only or never packaged."""

    def test_never_packaged_nodes_are_the_labelled_ones(self) -> None:
        labels, _ = tcw.spine_flowchart()
        labelled = {node for node, label in labels.items() if "(dev only)" in label or "(never packaged)" in label}
        self.assertEqual(set(CONFIG["never_packaged"]), labelled)


@unittest.skipUnless(shutil.which("cargo"), "cargo is needed for the repository metadata")
class RepositoryTest(unittest.TestCase):
    """AC1 to AC3 on the repository's own `cargo metadata`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = cw.cargo_metadata(cw.REPO_ROOT)
        cls.crates = {crate.name: crate for crate in cw.load_workspace(cls.metadata)}

    def test_repository_passes_the_packaging_check(self) -> None:
        self.assertEqual(cp.check_artefacts(self.metadata, GRAPH, CONFIG), [])

    def test_testbed_artefact_holds_every_executable_under_testing(self) -> None:
        members = cp.workspace_members(self.metadata)
        testing = next(node for node in GRAPH.nodes.values() if node.dev_only)
        under_testing = {
            binary
            for name, crate in self.crates.items()
            if any(crate.directory.startswith(f"{directory}/") for directory in testing.paths)
            for binary in cp.bin_targets(members[name])
        }
        testbed = set(cp.testbed_binaries(self.metadata, GRAPH, CONFIG))
        self.assertTrue(under_testing)
        self.assertEqual(testbed, under_testing)
        self.assertFalse(testbed & {artefact.binary for artefact in cp.load_artefacts(CONFIG)})

    def test_each_test_double_is_its_own_executable(self) -> None:
        members = cp.workspace_members(self.metadata)
        testing = next(node for node in GRAPH.nodes.values() if node.dev_only)
        doubles = [name for name in self.crates if testing.pattern and fnmatch.fnmatchcase(name, testing.pattern)]
        self.assertTrue(doubles)
        for name in doubles:
            with self.subTest(double=name):
                self.assertEqual(cp.bin_targets(members[name]), [name])

    def test_testbed_links_what_ad3_draws(self) -> None:
        """AC2: the testbed links a crate of every node AD-3 draws an edge to from it."""
        testbed = GRAPH.nodes["testbed"]
        (name,) = [n for n, c in self.crates.items() if GRAPH.classify(n, c.directory) is testbed]
        linked = {reached for reached, _ in cw.linked_closure(self.crates[name], self.crates)}
        for target in testbed.depends_on:
            with self.subTest(node=target):
                self.assertTrue(
                    any(GRAPH.classify(n, self.crates[n].directory).id == target for n in linked),
                    f"{name} links no crate of node {target}: {sorted(linked)}",
                )


if __name__ == "__main__":
    unittest.main()
