"""Tests for ci/check_workspace.py, over synthetic `cargo metadata` documents.

Most fixtures are derived from ci/crate_graph.toml and the workspace lints of Cargo.toml: one
sample crate per node, edges from the file's own `depends_on`, so a change to the graph changes
the fixtures with it. The allowlist itself is pinned to the AD-3 flowchart of
doc/architecture-spine.md by `SpineAgreementTest`. `HandWrittenEdgeTest` is the one deliberate
exception: an independent table of edges AD-3 forbids, so an encoding error in the data file
that the derived tests would reproduce still turns a test red. `EndToEndTest` runs the checks on
the output of a real `cargo metadata`.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import copy
import fnmatch
import json
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import check_workspace as cw

CONFIG = tomllib.loads(cw.GRAPH_FILE.read_text(encoding="utf-8"))
GRAPH = cw.Graph.from_config(CONFIG)
SPINE = cw.REPO_ROOT / "doc" / "architecture-spine.md"
DECISIONS = cw.REPO_ROOT / "doc" / "decisions.md"
CHANNEL = "1.0.0"
WORKSPACE_LINTS = tomllib.loads((cw.REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["lints"]
ROOT_MANIFEST = {"workspace": {"lints": WORKSPACE_LINTS}}
UNSAFE_ALLOWED = CONFIG["unsafe_code"]["allowed"]
INHERITED_LINTS = "[lints]\nworkspace = true\n"
# The repository's vendored-build configuration, which every synthetic workspace carries.
VENDORED_CONFIG_TEXT = (cw.REPO_ROOT / cw.VENDORED_CONFIG_FILE).read_text(encoding="utf-8")


def lints_toml(levels: dict[tuple[str, str], str | None], as_tables: bool = False) -> str:
    """Manifest [lints.*] tables for (table, lint) -> level."""
    text = ""
    for table_name in dict.fromkeys(table for table, _ in levels):
        text += f"\n[lints.{table_name}]\n"
        for (table, lint), level in levels.items():
            if table == table_name:
                text += f'{lint} = {{ level = "{level}", priority = 0 }}\n' if as_tables else f'{lint} = "{level}"\n'
    return text


UNSAFE_CRATE_LEVELS = cw._unsafe_crate_lints(WORKSPACE_LINTS)
UNSAFE_CRATE_LINTS = lints_toml(UNSAFE_CRATE_LEVELS)


def sample_crate(node: cw.Node) -> tuple[str, str]:
    """A crate name and directory that `node` matches."""
    if node.crates:
        name = node.crates[0]
    elif node.pattern:
        name = node.pattern.replace("*", "sample")
    else:
        name = f"{node.id}-sample"
    parent = node.paths[0] if node.paths else "crates"
    return name, f"{parent}/{name}"


def needs_forbid_attribute(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in CONFIG["unsafe_code"]["forbid_attribute"])


class Workspace:
    """A synthetic workspace on disk and the cargo metadata document describing it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.vendored_config = root / cw.VENDORED_CONFIG_FILE
        self.vendored_config.parent.mkdir(parents=True, exist_ok=True)
        self.vendored_config.write_text(VENDORED_CONFIG_TEXT, encoding="utf-8")
        self.packages: dict[str, dict] = {}
        self.outside: list[dict] = []
        self.extra_resolved: dict[str, list[str]] = {}

    def add(
        self,
        name: str,
        directory: str | None = None,
        *,
        target_kind: str = "lib",
        license: str | None = cw.LICENSE,
        edition: str = cw.EDITION,
        rust_version: str = CHANNEL,
        publish: tuple[str, ...] | None = (),
        lints: str | None = None,
        forbid_attribute: bool | None = None,
        root_source: str | None = None,
    ) -> Path:
        crate_dir = self.root / (directory or f"crates/{name}")
        (crate_dir / "src").mkdir(parents=True, exist_ok=True)
        if lints is None:
            lints = UNSAFE_CRATE_LINTS if name in UNSAFE_ALLOWED else INHERITED_LINTS
        if forbid_attribute is None:
            forbid_attribute = needs_forbid_attribute(name)
        (crate_dir / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n\n{lints}', encoding="utf-8")
        root_file = crate_dir / "src" / ("main.rs" if target_kind == "bin" else "lib.rs")
        if root_source is None:
            root_source = f"//! {name}\n"
            if forbid_attribute:
                root_source += f"\n{cw.FORBID_ATTRIBUTE}\n"
        root_file.write_text(root_source, encoding="utf-8")
        self.packages[name] = {
            "id": f"path+file://{crate_dir.as_posix()}#{name}@0.0.0",
            "name": name,
            "manifest_path": str(crate_dir / "Cargo.toml"),
            "license": license,
            "edition": edition,
            "rust_version": rust_version,
            "publish": None if publish is None else list(publish),
            "targets": [{"kind": [target_kind], "src_path": str(root_file)}],
            "dependencies": [],
        }
        return crate_dir

    def depend(self, source: str, target: str, kind: str = "normal") -> None:
        target_dir = Path(self.packages[target]["manifest_path"]).parent
        self.declare(source, {"name": target, "kind": None if kind == "normal" else kind, "path": str(target_dir)})

    def declare(self, source: str, dependency: dict) -> None:
        self.packages[source]["dependencies"].append({"source": None, **dependency})

    def resolve_outside(self, source: str, name: str, package_id: str) -> None:
        """`source` resolves a dependency to a package that is not a workspace member; its source
        and version are read from the package id, and a `path+` id has no source, as in cargo."""
        location, version = package_id.split("#", 1)[0], package_id.rsplit("@", 1)[1]
        self.outside.append(
            {
                "id": package_id,
                "name": name,
                "version": version,
                "source": None if location.startswith("path+") else location,
                "manifest_path": f"{location}/Cargo.toml",
                "dependencies": [],
            }
        )
        self.extra_resolved.setdefault(source, []).append(package_id)

    def metadata(self) -> dict:
        members = list(self.packages.values())
        by_dir = {str(Path(package["manifest_path"]).parent): package["id"] for package in members}
        nodes = []
        for package in members:
            deps = [by_dir[dep["path"]] for dep in package["dependencies"] if dep.get("path") in by_dir]
            deps += self.extra_resolved.get(package["name"], [])
            nodes.append({"id": package["id"], "deps": [{"pkg": dep} for dep in deps]})
        return {
            "packages": [*members, *self.outside],
            "workspace_members": [package["id"] for package in members],
            "workspace_root": str(self.root),
            "resolve": {"nodes": nodes},
        }

    def check(self, config: dict = CONFIG, root_manifest: dict = ROOT_MANIFEST, files: list[Path] = ()) -> list[str]:
        return cw.run_checks(self.metadata(), config, root_manifest, CHANNEL, files)


class WorkspaceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.workspace = Workspace(Path(temp.name))

    def full_graph(self, graph: cw.Graph = GRAPH, skip: tuple[str, ...] = ()) -> dict[str, str]:
        """One sample crate per node and one dependency per edge; returns node id -> crate name."""
        names = {}
        for node in graph.nodes.values():
            if node.id in skip:
                continue
            name, directory = sample_crate(node)
            self.workspace.add(name, directory, target_kind="bin" if node.shipped else "lib")
            names[node.id] = name
        for node in graph.nodes.values():
            for target in node.depends_on:
                if node.id in names and target in names:
                    self.workspace.depend(names[node.id], names[target])
        return names

    def assert_names_edge(self, violations: list[str], source: str, target: str) -> None:
        self.assertTrue(
            any(f"forbidden edge {source} -> {target} " in v for v in violations),
            f"no violation names {source} -> {target}: {violations}",
        )

    def assert_single(self, violations: list[str], *fragments: str) -> None:
        self.assertEqual(len(violations), 1, violations)
        for fragment in fragments:
            self.assertIn(fragment, violations[0])


class GraphTest(WorkspaceTestCase):
    def test_graph_as_declared_passes(self) -> None:
        self.full_graph()
        self.assertEqual(self.workspace.check(), [])

    def test_gateway_depending_on_storage_fails_naming_the_edge(self) -> None:
        names = self.full_graph()
        self.workspace.depend(names["gw"], names["storage"])
        self.assert_single(self.workspace.check(), "forbidden edge vilicus-gateway -> vilicus-storage ")

    def test_every_edge_the_graph_does_not_allow_fails(self) -> None:
        for source in GRAPH.nodes.values():
            for target in GRAPH.nodes.values():
                if source is target or GRAPH.allows(source, target, "normal"):
                    continue
                with self.subTest(edge=f"{source.id} -> {target.id}"):
                    self.setUp()
                    names = self.full_graph()
                    self.workspace.depend(names[source.id], names[target.id])
                    self.assert_names_edge(self.workspace.check(), names[source.id], names[target.id])

    def test_every_edge_the_graph_allows_passes(self) -> None:
        for source in GRAPH.nodes.values():
            for target_id in GRAPH.reachable(source.id):
                target = GRAPH.nodes[target_id]
                if not GRAPH.allows(source, target, "normal"):
                    continue
                with self.subTest(edge=f"{source.id} -> {target.id}"):
                    self.setUp()
                    names = self.full_graph()
                    self.workspace.depend(names[source.id], names[target.id])
                    self.assertEqual(self.workspace.check(), [])

    def test_two_crates_of_one_pattern_node_may_not_depend_on_each_other(self) -> None:
        for node in GRAPH.nodes.values():
            if node.pattern is None:
                continue
            with self.subTest(node=node.id):
                self.setUp()
                names = self.full_graph()
                other = node.pattern.replace("*", "other")
                self.workspace.add(other)
                for target in node.depends_on:
                    self.workspace.depend(other, names[target])
                self.workspace.depend(other, names[node.id])
                self.assert_names_edge(self.workspace.check(), other, names[node.id])

    def test_crate_matching_no_node_fails(self) -> None:
        self.full_graph()
        self.workspace.add("unclassified-crate")
        self.assert_single(self.workspace.check(), "unclassified-crate", "matches no node")

    def test_each_required_node_without_a_crate_fails(self) -> None:
        required = [node for node in GRAPH.nodes.values() if node.required]
        self.assertTrue(required)
        for node in required:
            with self.subTest(node=node.id):
                self.setUp()
                self.full_graph(skip=(node.id,))
                self.assertIn(f"graph: required node {node.id} ", "\n".join(self.workspace.check()))


class HandWrittenEdgeTest(WorkspaceTestCase):
    """Edges AD-3 forbids, written out by hand rather than derived from the data file. The graph
    allows plugins -> proto (plugins reach proto through sdk), so it is not in the table."""

    FORBIDDEN = (
        ("vilicus-ai", "vilicus-core"),
        ("vilicus-gateway", "vilicus-crypto"),
        ("vilicus-gateway", "vilicus-storage"),
        ("vilicus-mod-sample", "vilicus-core"),
        ("vilicus-mod-sample", "vilicus-proto"),
        ("vilicus-plugin-sdk", "vilicus-core"),
        ("vilicus-audit", "vilicus-storage"),
        ("vilicus-egress", "vilicus-core"),
        ("vilicus-plugin-sample", "vilicus-core"),
        ("vilicus-plugin-sample", "vilicus-module-api"),
        ("vilicus-module-api", "vilicus-core"),
        ("vilicus", "vilicus-storage"),
        ("vilicus-testbed", "vilicus-crypto"),
        ("vilicus-types", "vilicus-proto"),
    )
    DEV_DEPENDENCY_ON_TESTING_ALLOWED = ("vilicus-core", "vilicus", "vilicus-testbed")
    DEV_DEPENDENCY_ON_TESTING_FORBIDDEN = (
        "vilicus-gateway",
        "vilicus-audit",
        "vilicus-egress",
        "vilicus-ai",
        "vilicus-plugin-sdk",
        "vilicus-module-api",
        "vilicus-proto",
        "vilicus-types",
        "vilicus-mod-sample",
        "vilicus-plugin-sample",
    )

    def test_forbidden_edges_fail(self) -> None:
        for source, target in self.FORBIDDEN:
            for kind in ("normal", "build", "dev"):
                with self.subTest(edge=f"{source} -> {target}", kind=kind):
                    self.setUp()
                    self.full_graph()
                    self.workspace.depend(source, target, kind)
                    self.assert_names_edge(self.workspace.check(), source, target)

    def test_dev_dependency_on_a_test_crate_only_from_crates_that_reach_the_core(self) -> None:
        for source in (*self.DEV_DEPENDENCY_ON_TESTING_ALLOWED, *self.DEV_DEPENDENCY_ON_TESTING_FORBIDDEN):
            with self.subTest(source=source):
                self.setUp()
                self.full_graph()
                self.workspace.depend(source, "vilicus-mod-reference", "dev")
                violations = self.workspace.check()
                if source in self.DEV_DEPENDENCY_ON_TESTING_ALLOWED:
                    self.assertEqual(violations, [])
                else:
                    self.assert_single(violations, f"forbidden edge {source} -> vilicus-mod-reference (dev dependency")


class PrivateAndShippedTest(WorkspaceTestCase):
    """AC4: test crates stay out of the shipped binary; crypto and storage serve the Core only."""

    def shipped_name(self, names: dict[str, str]) -> str:
        return next(names[node.id] for node in GRAPH.nodes.values() if node.shipped)

    def dev_only_nodes(self) -> list[cw.Node]:
        nodes = [node for node in GRAPH.nodes.values() if node.dev_only]
        self.assertTrue(nodes)
        return nodes

    def test_reference_module_as_normal_or_build_dependency_of_the_binary_fails(self) -> None:
        for kind in sorted(cw.LINKED_KINDS):
            with self.subTest(kind=kind):
                self.setUp()
                names = self.full_graph()
                self.workspace.depend(self.shipped_name(names), "vilicus-mod-reference", kind)
                violations = self.workspace.check()
                self.assert_names_edge(violations, self.shipped_name(names), "vilicus-mod-reference")
                self.assertTrue(any("dev-only crate vilicus-mod-reference is linked" in v for v in violations))

    def test_reference_module_is_dev_only_wherever_it_lives(self) -> None:
        names = self.full_graph()
        self.workspace.add("vilicus-mod-reference", "crates/vilicus-mod-reference")
        self.assertIs(GRAPH.classify("vilicus-mod-reference", "crates/vilicus-mod-reference").dev_only, True)
        self.workspace.depend(self.shipped_name(names), "vilicus-mod-reference")
        self.assert_names_edge(self.workspace.check(), self.shipped_name(names), "vilicus-mod-reference")

    def test_any_crate_under_a_dev_only_path_as_linked_dependency_of_the_binary_fails(self) -> None:
        for node in self.dev_only_nodes():
            for path in node.paths:
                for kind in sorted(cw.LINKED_KINDS):
                    with self.subTest(path=path, kind=kind):
                        self.setUp()
                        names = self.full_graph()
                        double = "channel-double"
                        self.workspace.add(double, f"{path}/doubles/{double}")
                        self.workspace.depend(self.shipped_name(names), double, kind)
                        self.assert_names_edge(self.workspace.check(), self.shipped_name(names), double)

    def test_dev_only_crate_as_dev_dependency_of_the_binary_passes(self) -> None:
        names = self.full_graph()
        for node in self.dev_only_nodes():
            self.workspace.depend(self.shipped_name(names), names[node.id], "dev")
        self.assertEqual(self.workspace.check(), [])

    def test_closure_check_holds_even_if_the_allowlist_admits_the_edge(self) -> None:
        config = copy.deepcopy(CONFIG)
        shipped = next(node_id for node_id, table in config["node"].items() if table.get("shipped"))
        dev_only = next(node_id for node_id, table in config["node"].items() if table.get("dev_only"))
        config["node"][shipped]["depends_on"].append(dev_only)
        names = self.full_graph(cw.Graph.from_config(config))
        self.assert_single(
            self.workspace.check(config),
            f"dev-only crate {names[dev_only]} is linked into shipped crate {names[shipped]}",
        )

    def test_private_crates_accept_only_their_direct_dependents(self) -> None:
        private = [node for node in GRAPH.nodes.values() if node.private]
        self.assertTrue(private)
        for target in private:
            for source in GRAPH.nodes.values():
                if source is target or target.id in source.depends_on:
                    continue
                for kind in ("normal", "build", "dev"):
                    with self.subTest(edge=f"{source.id} -> {target.id}", kind=kind):
                        self.setUp()
                        names = self.full_graph()
                        self.workspace.depend(names[source.id], names[target.id], kind)
                        violations = self.workspace.check()
                        self.assert_names_edge(violations, names[source.id], names[target.id])
                        self.assertTrue(any(f"{target.id} is private to" in v for v in violations))


class PathOnlyTest(WorkspaceTestCase):
    """A crate under a node's directory must also be named by that node, so name-keyed checks see it."""

    def test_crate_matching_a_node_by_directory_only_fails(self) -> None:
        for node in GRAPH.nodes.values():
            for path in node.paths:
                with self.subTest(node=node.id):
                    self.setUp()
                    self.full_graph()
                    self.workspace.add("stray-crate", f"{path}/stray-crate")
                    self.assert_single(self.workspace.check(), "stray-crate", "by its directory only")

    def test_listed_or_patterned_crate_under_the_directory_passes(self) -> None:
        for node in GRAPH.nodes.values():
            for path in node.paths:
                with self.subTest(node=node.id):
                    self.setUp()
                    self.full_graph()
                    self.assertTrue(node.crates or node.pattern)
                    if node.pattern:
                        name = node.pattern.replace("*", "other")
                        self.workspace.add(name, f"{path}/{name}")
                    self.assertEqual(self.workspace.check(), [])


class IsolatedTest(WorkspaceTestCase):
    """Story 2.7, AC5: an isolated crate (the fuzz targets) is a dependency of no crate, and
    depends only on what the nodes of its table reach."""

    def tables(self) -> list[cw.Isolated]:
        tables = list(GRAPH.isolated.values())
        self.assertTrue(tables)
        return tables

    def add_isolated(self, table: cw.Isolated, names: dict[str, str]) -> str:
        """The table's crate, at its directory, with an edge to each node it lists."""
        name = table.crates[0]
        self.workspace.add(name, table.paths[0] if table.paths else f"crates/{name}")
        for node_id in table.depends_on:
            self.workspace.depend(name, names[node_id])
        return name

    def test_isolated_crates_with_their_edges_pass(self) -> None:
        names = self.full_graph()
        for table in self.tables():
            self.add_isolated(table, names)
        self.assertEqual(self.workspace.check(), [])

    def test_no_crate_may_depend_on_an_isolated_crate_by_any_kind_of_edge(self) -> None:
        for table in self.tables():
            for node in GRAPH.nodes.values():
                for kind in ("normal", "build", "dev"):
                    with self.subTest(table=table.id, node=node.id, kind=kind):
                        self.setUp()
                        names = self.full_graph()
                        isolated = self.add_isolated(table, names)
                        self.workspace.depend(names[node.id], isolated, kind)
                        self.assert_single(
                            self.workspace.check(),
                            f"forbidden edge {names[node.id]} -> {isolated} ({kind} dependency",
                            f"[isolated.{table.id}]: no crate may depend on it",
                        )

    def test_the_repository_isolates_the_fuzz_targets_from_every_crate(self) -> None:
        # Written out on purpose: the crate of Story 2.7 and the crates that must never link it.
        table = GRAPH.classify_isolated("vilicus-fuzz", "fuzz")
        self.assertIsNotNone(table)
        for source in ("vilicus", "vilicus-core", "vilicus-proto", "vilicus-gateway", "vilicus-testbed"):
            for kind in ("normal", "build", "dev"):
                with self.subTest(source=source, kind=kind):
                    self.setUp()
                    names = self.full_graph()
                    self.add_isolated(table, names)
                    self.workspace.depend(source, "vilicus-fuzz", kind)
                    self.assert_single(self.workspace.check(), f"forbidden edge {source} -> vilicus-fuzz ")

    def test_an_isolated_crate_depends_only_on_what_its_nodes_reach(self) -> None:
        for table in self.tables():
            reached = set(table.depends_on).union(*(GRAPH.reachable(node_id) for node_id in table.depends_on))
            for node in GRAPH.nodes.values():
                with self.subTest(table=table.id, node=node.id):
                    self.setUp()
                    names = self.full_graph()
                    isolated = self.add_isolated(table, names)
                    self.workspace.depend(isolated, names[node.id])
                    violations = self.workspace.check()
                    if node.id in reached and not (node.private and node.id not in table.depends_on):
                        self.assertEqual(violations, [])
                    else:
                        self.assert_single(violations, f"forbidden edge {isolated} -> {names[node.id]} ")

    def test_a_crate_under_an_isolated_directory_must_be_listed(self) -> None:
        for table in self.tables():
            for path in table.paths:
                with self.subTest(table=table.id, path=path):
                    self.setUp()
                    self.full_graph()
                    self.workspace.add("stray-crate", f"{path}/stray-crate")
                    self.assert_single(self.workspace.check(), "stray-crate", f"[isolated.{table.id}] by its directory only")

    def test_an_isolated_crate_stays_isolated_under_a_node_directory(self) -> None:
        for table in self.tables():
            for node in GRAPH.nodes.values():
                for path in node.paths:
                    with self.subTest(table=table.id, path=path):
                        self.setUp()
                        names = self.full_graph()
                        name = table.crates[0]
                        self.workspace.add(name, f"{path}/{name}")
                        self.workspace.depend(names["testbed"], name, "dev")
                        self.assert_single(self.workspace.check(), f"forbidden edge {names['testbed']} -> {name} ")

    def test_an_isolated_table_must_name_known_nodes_and_its_own_id(self) -> None:
        for label, isolated in {
            "unknown node": {"stray": {"crates": ["stray"], "depends_on": ["no-such-node"]}},
            "id of a node": {"proto": {"crates": ["stray"], "depends_on": ["types"]}},
        }.items():
            with self.subTest(case=label):
                config = copy.deepcopy(CONFIG)
                config["isolated"] = isolated
                with self.assertRaises(ValueError):
                    cw.Graph.from_config(config)


class ShippedSourcesTest(WorkspaceTestCase):
    """FR-109: no crate in the shipped closure compiles a file outside its own package."""

    OUTSIDE = '"../../../testing/vilicus-testbed/src/main.rs"'

    def setUp(self) -> None:
        super().setUp()
        self.names = self.full_graph()
        self.shipped = next(self.names[node.id] for node in GRAPH.nodes.values() if node.shipped)
        # A crate the shipped crate links, and one outside its closure.
        self.linked = self.names["core"]
        self.unlinked = next(self.names[node.id] for node in GRAPH.nodes.values() if node.id == "testbed")

    def write(self, crate: str, relative: str, source: str) -> None:
        path = Path(self.workspace.packages[crate]["manifest_path"]).parent / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def test_target_compiled_from_outside_the_package_fails(self) -> None:
        outside = self.workspace.root / "testing" / "vilicus-testbed" / "src" / "main.rs"
        self.workspace.packages[self.shipped]["targets"].append({"kind": ["bin"], "src_path": str(outside)})
        self.assert_single(self.workspace.check(), f"a target of {self.shipped} compiles {outside}")

    def test_path_module_or_include_outside_the_package_fails(self) -> None:
        sources = {
            "path attribute": f"#[path = {self.OUTSIDE}]\nmod x;\n",
            "path in cfg_attr": f"#[cfg_attr(unix, path = {self.OUTSIDE})]\nmod x;\n",
            "absolute path": '#[path = "/etc/x.rs"]\nmod x;\n',
            "include": f"include!({self.OUTSIDE});\n",
            "include_str": f"const X: &str = include_str!({self.OUTSIDE});\n",
            "include_bytes": f"const X: &[u8] = include_bytes![{self.OUTSIDE}];\n",
            "computed include": 'include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testing/x.rs"));\n',
        }
        for crate in (self.shipped, self.linked):
            for label, source in sources.items():
                with self.subTest(crate=crate, case=label):
                    self.setUp()
                    self.write(crate, "src/extra.rs", source)
                    self.assert_single(self.workspace.check(), f"extra.rs of {crate}")

    def test_paths_inside_the_package_comments_and_unlinked_crates_pass(self) -> None:
        self.write(
            self.shipped,
            "src/extra.rs",
            '#[path = "other.rs"]\nmod other;\nconst X: &str = include_str!("../data/x.txt");\n'
            f"// #[path = {self.OUTSIDE}]\n/* include!({self.OUTSIDE}); */\n",
        )
        self.write(self.unlinked, "src/extra.rs", f"#[path = {self.OUTSIDE}]\nmod x;\n")
        self.assertEqual(self.workspace.check(), [])

    def test_symbolic_link_out_of_the_package_fails(self) -> None:
        link = Path(self.workspace.packages[self.shipped]["manifest_path"]).parent / "src" / "linked"
        try:
            link.symlink_to(self.workspace.root / "testing", target_is_directory=True)
        except OSError as error:
            self.skipTest(f"cannot create a symbolic link here: {error}")
        self.assert_single(self.workspace.check(), f"{link} of {self.shipped} links to")


class SourceTest(WorkspaceTestCase):
    """Dependencies that would carry workspace code in without passing through the graph."""

    def test_path_dependency_outside_the_members_fails_for_every_kind(self) -> None:
        for kind in ("normal", "build", "dev"):
            for target in (None, "cfg(unix)"):
                with self.subTest(kind=kind, target=target):
                    self.setUp()
                    self.full_graph()
                    shim = self.workspace.root.parent / "shim"
                    self.workspace.declare(
                        "vilicus-gateway",
                        {"name": "shim", "kind": None if kind == "normal" else kind, "path": str(shim), "target": target},
                    )
                    self.assert_single(
                        self.workspace.check(),
                        f"source: vilicus-gateway -> shim ({kind} dependency",
                        "is a path dependency on",
                        "which is not a workspace member",
                    )

    def test_path_dependency_on_an_excluded_directory_fails(self) -> None:
        self.full_graph()
        shim = self.workspace.root / "spikes" / "shim"
        self.workspace.declare("vilicus-gateway", {"name": "shim", "kind": None, "path": str(shim)})
        self.assert_single(self.workspace.check(), "vilicus-gateway -> shim", "is a path dependency on")

    def test_git_dependency_fails(self) -> None:
        self.full_graph()
        self.workspace.declare(
            "vilicus-gateway",
            {"name": "vilicus-crypto", "rename": "crypto", "kind": None, "source": "git+file:///tmp/repo"},
        )
        self.assert_single(self.workspace.check(), "vilicus-gateway -> vilicus-crypto", "is a git dependency")

    def test_registry_package_with_a_vilicus_name_fails(self) -> None:
        for name in ("vilicus-crypto", "vilicus-anything", "vilicus"):
            with self.subTest(name=name):
                self.setUp()
                self.full_graph()
                source = "registry+https://github.com/rust-lang/crates.io-index"
                self.workspace.declare("vilicus-gateway", {"name": name, "kind": None, "source": source})
                self.assert_single(self.workspace.check(), f"vilicus-gateway -> {name} ", "not the workspace member")

    def test_resolution_to_a_package_that_is_not_the_member_fails(self) -> None:
        self.full_graph()
        self.workspace.resolve_outside("vilicus-gateway", "vilicus-crypto", "git+file:///tmp/repo#vilicus-crypto@0.0.0")
        self.assert_single(self.workspace.check(), "vilicus-gateway resolves vilicus-crypto to git+file:///tmp/repo")

    def test_path_package_outside_the_members_fails(self) -> None:
        self.full_graph()
        location = (self.workspace.root / "third_party" / "itoa").as_uri()
        self.workspace.resolve_outside("vilicus-gateway", "itoa", f"path+{location}#itoa@1.0.99")
        self.assert_single(self.workspace.check(), "source: itoa 1.0.99", "is a path package that is not a workspace member")

    def test_patch_or_replace_table_in_the_root_manifest_fails(self) -> None:
        tables = {
            "patch": {"crates-io": {"itoa": {"path": "third_party/itoa"}}},
            "replace": {"itoa:1.0.15": {"path": "third_party/itoa"}},
        }
        for table, content in tables.items():
            with self.subTest(table=table):
                self.setUp()
                self.full_graph()
                violations = self.workspace.check(root_manifest={**ROOT_MANIFEST, table: content})
                self.assert_single(violations, f"the root Cargo.toml has a [{table}] table")

    def test_registry_dependency_with_another_name_passes(self) -> None:
        self.full_graph()
        source = "registry+https://github.com/rust-lang/crates.io-index"
        self.workspace.declare("vilicus-gateway", {"name": "serde", "kind": None, "source": source})
        self.workspace.resolve_outside("vilicus-gateway", "serde", f"{source}#serde@1.0.229")
        self.assertEqual(self.workspace.check(), [])


class ManifestTest(WorkspaceTestCase):
    def test_each_manifest_field_out_of_policy_fails(self) -> None:
        cases = {
            "license": {"license": "MIT"},
            "missing license": {"license": None},
            "edition": {"edition": "2021"},
            "rust-version": {"rust_version": "0.9.0"},
            "publishable": {"publish": None},
            "publishable to a registry": {"publish": ("crates-io",)},
        }
        for label, override in cases.items():
            with self.subTest(case=label):
                self.setUp()
                self.full_graph()
                self.workspace.add("vilicus-types", **override)
                self.assert_single(self.workspace.check(), "manifest: vilicus-types")

    def test_manifest_under_a_crate_directory_that_is_not_a_member_fails(self) -> None:
        for directory in cw.CRATE_DIRECTORIES:
            with self.subTest(directory=directory):
                self.setUp()
                self.full_graph()
                stray = self.workspace.root / directory / "stray"
                stray.mkdir(parents=True)
                (stray / "Cargo.toml").write_text('[package]\nname = "stray"\n', encoding="utf-8")
                self.assert_single(self.workspace.check(), str(stray / "Cargo.toml"), "is not a workspace member")

    def test_spdx_header_in_the_first_lines_of_a_source_or_config_file_fails(self) -> None:
        marker_variants = (cw.SPDX_MARKER, cw.SPDX_MARKER.lower(), cw.SPDX_MARKER.upper())
        for suffix in sorted(cw.SPDX_SCANNED_SUFFIXES):
            for marker in marker_variants:
                with self.subTest(suffix=suffix, marker=marker):
                    self.setUp()
                    self.full_graph()
                    tagged = self.workspace.root / f"tagged{suffix}"
                    lines = ["line"] * (cw.SPDX_HEADER_LINES - 1) + [f"# {marker}: {cw.LICENSE}"]
                    tagged.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    self.assert_single(self.workspace.check(files=[tagged]), str(tagged), "SPDX header")

    def test_spdx_marker_below_the_header_or_in_prose_passes(self) -> None:
        self.full_graph()
        deep = self.workspace.root / "deep.rs"
        deep.write_text("\n" * cw.SPDX_HEADER_LINES + f"// {cw.SPDX_MARKER}\n", encoding="utf-8")
        prose = self.workspace.root / "README.md"
        prose.write_text(f"Files carry no {cw.SPDX_MARKER} header.\n", encoding="utf-8")
        self.assertEqual(self.workspace.check(files=[deep, prose]), [])

    def test_spdx_header_in_vendored_sources_passes(self) -> None:
        self.full_graph()
        vendored = self.workspace.root / cw.VENDOR_DIRECTORY / "some-crate-1.0.0" / "src" / "lib.rs"
        vendored.parent.mkdir(parents=True)
        vendored.write_text(f"// {cw.SPDX_MARKER}: MIT\n", encoding="utf-8")
        self.assertEqual(self.workspace.check(files=[vendored]), [])

    def test_file_listing_without_git_walks_the_tree(self) -> None:
        root = self.workspace.root
        for relative in ("kept.rs", "sub/kept.toml", "target/skipped.rs", ".git/skipped", "sub/target/skipped.rs"):
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text("x\n", encoding="utf-8")
        listed = {path.relative_to(root).as_posix() for path in cw.repository_files(root)}
        self.assertEqual(listed, {"kept.rs", "sub/kept.toml", cw.VENDORED_CONFIG_FILE.as_posix()})


class UnsafeTest(WorkspaceTestCase):
    def test_workspace_without_forbid_fails(self) -> None:
        self.full_graph()
        for rust_lints in ({}, {"unsafe_code": "deny"}):
            with self.subTest(rust_lints=rust_lints):
                lints = {**WORKSPACE_LINTS, "rust": {**WORKSPACE_LINTS["rust"], **rust_lints}}
                if not rust_lints:
                    lints["rust"].pop("unsafe_code")
                violations = self.workspace.check(root_manifest={"workspace": {"lints": lints}})
                self.assertIn("unsafe: [workspace.lints.rust] unsafe_code is", "\n".join(violations))

    def sample_crates(self, unsafe_allowed: bool) -> list[tuple[str, str]]:
        crates = [sample_crate(node) for node in GRAPH.nodes.values()]
        selected = [(name, directory) for name, directory in crates if (name in UNSAFE_ALLOWED) == unsafe_allowed]
        self.assertTrue(selected)
        return selected

    def test_every_allowed_crate_is_a_node_of_the_graph(self) -> None:
        self.assertEqual({name for name, _ in self.sample_crates(unsafe_allowed=True)}, set(UNSAFE_ALLOWED))

    def test_crate_outside_the_list_not_inheriting_or_relaxing_fails(self) -> None:
        cases = {
            "no lints": "",
            "deny": '[lints.rust]\nunsafe_code = "deny"\n',
            "allow": '[lints.rust]\nunsafe_code = "allow"\n',
            "the shape of an allowed crate": UNSAFE_CRATE_LINTS,
        }
        for name, directory in self.sample_crates(unsafe_allowed=False):
            for label, lints in cases.items():
                with self.subTest(crate=name, case=label):
                    self.setUp()
                    self.full_graph()
                    self.workspace.add(name, directory, lints=lints)
                    fragments = [f"{name} does not inherit the workspace lints"]
                    if lints:
                        fragments.append("which only D140's crates may relax")
                    self.assert_single(self.workspace.check(), *fragments)

    def test_crate_in_the_list_missing_any_lint_fails(self) -> None:
        cases = {"inherits the workspace": INHERITED_LINTS}
        for key, level in UNSAFE_CRATE_LEVELS.items():
            cases[f"{key} missing"] = lints_toml({k: v for k, v in UNSAFE_CRATE_LEVELS.items() if k != key})
            weaker = "warn" if level != "warn" else "allow"
            cases[f"{key} at {weaker}"] = lints_toml({**UNSAFE_CRATE_LEVELS, key: weaker})
        for name, directory in self.sample_crates(unsafe_allowed=True):
            for label, lints in cases.items():
                with self.subTest(crate=name, case=label):
                    self.setUp()
                    self.full_graph()
                    self.workspace.add(name, directory, lints=lints)
                    self.assert_single(self.workspace.check(), f"unsafe: {name} may hold unsafe code")

    def test_crate_in_the_list_repeats_a_lint_the_workspace_adds(self) -> None:
        lints = {**WORKSPACE_LINTS, "clippy": {**WORKSPACE_LINTS.get("clippy", {}), "dbg_macro": "deny"}}
        root_manifest = {"workspace": {"lints": lints}}
        allowed = self.sample_crates(unsafe_allowed=True)
        for name, directory in allowed:
            with self.subTest(crate=name):
                self.setUp()
                self.full_graph()
                for other, other_directory in allowed:
                    if other != name:
                        self.workspace.add(other, other_directory, lints=lints_toml(cw._unsafe_crate_lints(lints)))
                self.assert_single(
                    self.workspace.check(root_manifest=root_manifest),
                    f"unsafe: {name} may hold unsafe code",
                    "[lints.clippy] dbg_macro is None, expected 'deny'",
                )
                self.workspace.add(name, directory, lints=lints_toml(cw._unsafe_crate_lints(lints)))
                self.assertEqual(self.workspace.check(root_manifest=root_manifest), [])

    def test_crate_in_the_list_may_write_lint_levels_as_tables(self) -> None:
        for name, directory in self.sample_crates(unsafe_allowed=True):
            with self.subTest(crate=name):
                self.setUp()
                self.full_graph()
                self.workspace.add(name, directory, lints=lints_toml(UNSAFE_CRATE_LEVELS, as_tables=True))
                self.assertEqual(self.workspace.check(), [])

    def test_crate_in_the_list_allowing_unsafe_code_for_a_module_fails(self) -> None:
        attributes = (
            "#![allow(unsafe_code)]",
            "#![expect(unsafe_code)]",
            "#![allow(dead_code, unsafe_code)]",
            "#![cfg_attr(test, allow(unsafe_code))]",
            "#![ allow ( unsafe_code ) ]",
        )
        for name, directory in self.sample_crates(unsafe_allowed=True):
            for attribute in attributes:
                with self.subTest(crate=name, attribute=attribute):
                    self.setUp()
                    self.full_graph()
                    ffi = self.workspace.add(name, directory) / "src" / "ffi" / "sqlite.rs"
                    ffi.parent.mkdir()
                    ffi.write_text(f"//! FFI wrappers.\n\n{attribute}\n", encoding="utf-8")
                    self.assert_single(self.workspace.check(), f"{ffi} of {name} allows unsafe code for a whole module")

    def test_crate_in_the_list_allowing_unsafe_code_per_block_or_in_comments_passes(self) -> None:
        source = (
            "//! FFI wrappers.\n"
            "// #![allow(unsafe_code)]\n"
            "/* #![expect(unsafe_code)]\n   #![allow(unsafe_code)] */\n"
            "#[allow(unsafe_code)]\n"
            "fn read() {}\n"
        )
        for name, directory in self.sample_crates(unsafe_allowed=True):
            with self.subTest(crate=name):
                self.setUp()
                self.full_graph()
                self.workspace.add(name, directory, root_source=source)
                self.assertEqual(self.workspace.check(), [])

    def test_module_or_plugin_crate_without_forbid_attribute_fails(self) -> None:
        sources = {
            "absent": "//! Crate.\n",
            "in a line comment": f"//! Crate.\n// {cw.FORBID_ATTRIBUTE}\n",
            "in a block comment": f"//! Crate.\n/*\n{cw.FORBID_ATTRIBUTE}\n*/\n",
            "another lint": "//! Crate.\n#![forbid(missing_docs)]\n",
            "deny instead": "//! Crate.\n#![deny(unsafe_code)]\n",
        }
        for pattern in CONFIG["unsafe_code"]["forbid_attribute"]:
            for target_kind in ("lib", "bin"):
                for label, source in sources.items():
                    with self.subTest(pattern=pattern, target_kind=target_kind, case=label):
                        self.setUp()
                        self.full_graph()
                        name = pattern.replace("*", "sample")
                        self.workspace.add(name, target_kind=target_kind, root_source=source)
                        self.assert_single(self.workspace.check(), f"of {name} lacks {cw.FORBID_ATTRIBUTE}")

    def test_forbid_attribute_with_a_lint_list_passes(self) -> None:
        sources = (
            "//! Crate.\n#![forbid(unsafe_code, missing_docs)]\n",
            "//! Crate.\n#![forbid(missing_docs, unsafe_code)]\n",
            "//! Crate.\n#![forbid(\n    unsafe_code,\n    missing_docs,\n)]\n",
        )
        for pattern in CONFIG["unsafe_code"]["forbid_attribute"]:
            for source in sources:
                with self.subTest(pattern=pattern, source=source):
                    self.setUp()
                    self.full_graph()
                    self.workspace.add(pattern.replace("*", "sample"), root_source=source)
                    self.assertEqual(self.workspace.check(), [])

    def test_cargo_configuration_in_the_workspace_fails(self) -> None:
        for directory in (".", *(f"{parent}/some-crate" for parent in cw.CRATE_DIRECTORIES)):
            for name in cw.CARGO_CONFIG_NAMES:
                with self.subTest(directory=directory, name=name):
                    self.setUp()
                    self.full_graph()
                    config = self.workspace.root / directory / ".cargo" / name
                    config.parent.mkdir(parents=True, exist_ok=True)
                    config.write_text('[build]\nrustflags = ["--cap-lints", "allow"]\n', encoding="utf-8")
                    self.assert_single(self.workspace.check(), str(config), "could override the workspace lint levels")

    def test_cargo_configuration_in_the_workspace_fails_whatever_it_holds(self) -> None:
        for directory in (".", *(f"{parent}/some-crate" for parent in cw.CRATE_DIRECTORIES)):
            for name in cw.CARGO_CONFIG_NAMES:
                with self.subTest(directory=directory, name=name):
                    self.setUp()
                    self.full_graph()
                    config = self.workspace.root / directory / ".cargo" / name
                    config.parent.mkdir(parents=True, exist_ok=True)
                    config.write_text(VENDORED_CONFIG_TEXT, encoding="utf-8")
                    self.assert_single(self.workspace.check(), str(config), "could override the workspace lint levels")

    def test_vendored_configuration_of_the_repository_holds_only_the_source_replacement(self) -> None:
        self.assertEqual(tomllib.loads(VENDORED_CONFIG_TEXT), cw.VENDORED_SOURCE_CONFIG)

    def test_vendored_configuration_missing_fails(self) -> None:
        self.full_graph()
        self.workspace.vendored_config.unlink()
        self.assert_single(self.workspace.check(), "vendor:", "is missing")

    def test_vendored_configuration_with_anything_but_the_source_replacement_fails(self) -> None:
        cases = {
            "rustflags added": VENDORED_CONFIG_TEXT + '\n[build]\nrustflags = ["--cap-lints", "allow"]\n',
            "environment added": VENDORED_CONFIG_TEXT + '\n[env]\nRUSTFLAGS = "--cap-lints allow"\n',
            "other directory": VENDORED_CONFIG_TEXT.replace(f'"{cw.VENDOR_DIRECTORY}"', '"elsewhere"'),
            "other replacement": VENDORED_CONFIG_TEXT.replace('replace-with = "vendored-sources"', 'replace-with = "mirror"'),
            "extra source": VENDORED_CONFIG_TEXT + '\n[source.mirror]\nregistry = "https://example.com/index"\n',
            "replacement only": '[source.crates-io]\nreplace-with = "vendored-sources"\n',
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                self.setUp()
                self.full_graph()
                self.assertNotEqual(tomllib.loads(text), cw.VENDORED_SOURCE_CONFIG)
                self.workspace.vendored_config.write_text(text, encoding="utf-8")
                self.assert_single(
                    self.workspace.check(), str(self.workspace.vendored_config), "must hold only the replacement"
                )

    def test_vendored_configuration_that_is_not_toml_fails(self) -> None:
        self.full_graph()
        self.workspace.vendored_config.write_text("[source\n", encoding="utf-8")
        self.assert_single(self.workspace.check(), "is not valid TOML")

    def test_cargo_configuration_of_a_spike_passes(self) -> None:
        self.full_graph()
        config = self.workspace.root / "spikes" / "some-spike" / ".cargo" / "config.toml"
        config.parent.mkdir(parents=True)
        config.write_text("[build]\n", encoding="utf-8")
        self.assertEqual(self.workspace.check(), [])


@unittest.skipUnless(shutil.which("cargo") and shutil.which("git"), "cargo and git are needed for the end-to-end test")
class EndToEndTest(unittest.TestCase):
    """The source checks on what a real `cargo metadata` reports, not on a synthetic document."""

    @staticmethod
    def write_crate(directory: Path, name: str, dependencies: str = "") -> None:
        (directory / "src").mkdir(parents=True)
        (directory / "src" / "lib.rs").write_text(f"//! {name}\n", encoding="utf-8")
        (directory / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "0.0.0"\nedition = "2024"\n\n[dependencies]\n{dependencies}',
            encoding="utf-8",
        )

    def test_shim_and_git_dependencies_are_caught_on_real_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/*"]\n', encoding="utf-8")
            self.write_crate(workspace / "crates" / "vilicus-storage", "vilicus-storage")
            self.write_crate(workspace / "crates" / "vilicus-crypto", "vilicus-crypto")
            storage = (workspace / "crates" / "vilicus-storage").as_posix()
            self.write_crate(root / "shim", "shim", f'vilicus-storage = {{ path = "{storage}" }}\n')

            repository = root / "repository"
            self.write_crate(repository, "vilicus-crypto")
            git = ["git", "-C", str(repository), "-c", "user.name=test", "-c", "user.email=test@example.com"]
            subprocess.run([*git, "init", "-q"], check=True)
            subprocess.run([*git, "add", "-A"], check=True)
            subprocess.run([*git, "commit", "-q", "-m", "fixture"], check=True)

            self.write_crate(
                workspace / "crates" / "vilicus-gateway",
                "vilicus-gateway",
                f'shim = {{ path = "{(root / "shim").as_posix()}" }}\n'
                f'crypto-copy = {{ git = "{repository.as_uri()}", package = "vilicus-crypto" }}\n',
            )
            output = subprocess.run(
                ["cargo", "metadata", "--format-version", "1"], cwd=workspace, check=True, capture_output=True
            ).stdout
            violations = "\n".join(cw.check_sources(json.loads(output)))

        self.assertIn("source: vilicus-gateway -> shim (normal dependency) is a path dependency on", violations)
        self.assertIn("source: vilicus-gateway -> vilicus-crypto (normal dependency) is a git dependency", violations)
        self.assertIn("source: vilicus-gateway resolves vilicus-crypto to git+", violations)

    def test_crates_io_patch_to_a_path_package_is_caught_on_real_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            manifest = (
                '[workspace]\nresolver = "3"\nmembers = ["crates/*"]\n\n'
                '[patch.crates-io]\nitoa = { path = "third_party/itoa" }\n'
            )
            (workspace / "Cargo.toml").write_text(manifest, encoding="utf-8")
            self.write_crate(workspace / "crates" / "vilicus-types", "vilicus-types", 'itoa = "1"\n')
            self.write_crate(workspace / "third_party" / "itoa", "itoa")
            patched = workspace / "third_party" / "itoa" / "Cargo.toml"
            patched.write_text(patched.read_text(encoding="utf-8").replace('"0.0.0"', '"1.0.99"'), encoding="utf-8")
            output = subprocess.run(
                ["cargo", "metadata", "--format-version", "1", "--offline"], cwd=workspace, check=True, capture_output=True
            ).stdout
            metadata = json.loads(output)
            violations = cw.check_sources(metadata) + cw.check_root_manifest(tomllib.loads(manifest))

        self.assertEqual(len(violations), 2, violations)
        self.assertIn("source: itoa 1.0.99", violations[0])
        self.assertIn("is a path package that is not a workspace member", violations[0])
        self.assertIn("the root Cargo.toml has a [patch] table", violations[1])


def spine_flowchart() -> tuple[dict[str, str], set[tuple[str, str, bool]]]:
    """Node labels and edges (source, target, dashed) of the Mermaid block under AD-3."""
    text = SPINE.read_text(encoding="utf-8")
    section = text.split("### AD-3:", 1)[1].split("\n### ", 1)[0]
    block = section.split("```mermaid", 1)[1].split("```", 1)[0]
    labels: dict[str, str] = {}
    edges: set[tuple[str, str, bool]] = set()
    node = r"(\w+)(?:\[(.*?)\])?"
    for line in block.splitlines():
        line = line.strip()
        if match := re.fullmatch(rf"{node}\s*(-->|-\.->)\s*(\w+)", line):
            source, label, arrow, target = match.groups()
            edges.add((source, target, arrow == "-.->"))
        elif match := re.fullmatch(node, line):
            source, label = match.groups()
        else:
            continue
        if label is not None:
            labels[source] = label.strip('"')
    return labels, edges


class DecisionAgreementTest(unittest.TestCase):
    """The unsafe-allowed list of ci/crate_graph.toml is the list D140 states."""

    def test_allowed_crates_are_those_of_d140(self) -> None:
        record = DECISIONS.read_text(encoding="utf-8").split("\n## D140.", 1)[1].split("\n## ", 1)[0]
        sentence = record.split("`unsafe` is allowed only in ", 1)[1].split(".", 1)[0]
        self.assertEqual(set(re.findall(r"`([a-z0-9-]+)`", sentence)), set(UNSAFE_ALLOWED))


class SpineAgreementTest(unittest.TestCase):
    """ci/crate_graph.toml says what the AD-3 flowchart says, and nothing else."""

    def setUp(self) -> None:
        self.labels, self.edges = spine_flowchart()

    def test_same_nodes(self) -> None:
        self.assertEqual(set(self.labels), set(GRAPH.nodes))

    def test_same_edges(self) -> None:
        declared = {(node.id, target) for node in GRAPH.nodes.values() for target in node.depends_on}
        self.assertEqual({(source, target) for source, target, _ in self.edges}, declared)

    def test_dev_only_nodes_are_the_sources_of_dashed_edges(self) -> None:
        dashed = {source for source, _, is_dashed in self.edges if is_dashed}
        self.assertEqual({node.id for node in GRAPH.nodes.values() if node.dev_only}, dashed)

    def test_each_label_names_what_its_node_matches(self) -> None:
        for node_id, label in self.labels.items():
            node = GRAPH.nodes[node_id]
            first_word = label.split()[0]
            with self.subTest(node=node_id, label=label):
                self.assertIn(first_word, {*node.crates, node.pattern, *(f"{path}/" for path in node.paths)})


if __name__ == "__main__":
    unittest.main()
