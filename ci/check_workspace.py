#!/usr/bin/env python3
"""Workspace policy checks over `cargo metadata`.

- Crate graph (doc/architecture-spine.md AD-3, D140): every edge between workspace crates must be
  allowed by ci/crate_graph.toml, every required node has a crate, and no dev-only crate may sit
  in the normal or build closure of a shipped crate. The reference module is a module (AD-9):
  vilicus-module-api is its only normal or build dependency, workspace or registry, although the
  testing node it shares with the test doubles reaches the Core (Story 3.5 review). A crate that matches a node by its directory
  only (a crate under testing/ that is neither listed nor named vilicus-double-*) fails. A crate
  of an `[isolated.*]` table of ci/crate_graph.toml (the fuzz targets, Story 2.7) is outside the
  graph: no workspace crate may depend on it by any kind of edge, and it may depend only on what
  its table's nodes reach. The table's `exclusive_dependencies` (the fuzzing crates) are reached
  by its crates alone: any other workspace crate that depends on one, directly by any kind of
  dependency or through registry crates, fails.
- Restricted dependencies (AD-4, AD-18, FR-13, Story 4.1): a package of `[restricted.*]` in
  ci/crate_graph.toml is declared as a normal or build dependency only by the workspace crates
  its `linked` table names, and as a dev-dependency only by those its `dev` table names, each
  with a reason: `zeroize`, so no crate but vilicus-crypto defines a key type wiped on drop, and
  the primitive sources, so no crate but vilicus-crypto runs a key operation.
- Shipped sources (FR-109, D102): no crate in the normal or build closure of a shipped crate
  compiles a file outside its package directory, through a target's source path, a `#[path]`
  module, an `include!`, `include_str!` or `include_bytes!` (a computed path fails too) or a
  symbolic link.
- Dependency sources: a workspace crate takes no path dependency outside the workspace members,
  no git dependency, and no Vilicus-named package other than the workspace member of that name;
  the tree holds no path package other than the members, and the root manifest has no `[patch]`
  or `[replace]` table, either of which would swap a registry crate for local code that
  cargo-deny reports as `sources ok` and cargo-vet as first-party.
- Manifests (D29, D1): every workspace crate declares the Apache-2.0 licence, edition 2024 and
  the rust-version of rust-toolchain.toml and is never published (cargo-vet treats unpublished
  crates as first-party, D28), every manifest under the crate directories is a
  member, and no source or configuration file carries an SPDX header.
- Unsafe code (D140, Consistency Conventions): the workspace forbids unsafe code and every crate
  inherits its lints, except the crates ci/crate_graph.toml allows, which repeat those lints with
  unsafe code denied and undocumented unsafe blocks denied, and never allow unsafe code for a
  whole module; module, plugin and test double crates also carry the forbid attribute in each
  crate root; no Cargo configuration file can change lint levels for the workspace. The `unsafe`
  keyword, outside comments and literals, appears only in the module `[unsafe_code.modules]`
  names for its crate, a crate of `allowed` (Story 4.2, AC3): in no other file of any workspace
  crate, tests and examples included, doc tests (fenced code of `///` and `//!` comments)
  included. An entry names one module under `src/`, never `src` or a crate root, and no
  `#[path]` or `include!` literal brings a file into or out of it; a computed `include!` in such
  a crate fails too.
- Vendored sources (D28): ci/cargo-vendored.toml, the configuration CI passes to every workspace
  build with `--config`, exists and holds nothing but the replacement of crates.io by vendor/.
- Oracles (D153, Story 4.4): a cross-test oracle of an `[oracle.*]` table of ci/crate_graph.toml
  is a crate outside the workspace, with its own `[workspace]` table and Cargo.lock; no workspace
  crate is it or depends on it, it takes nothing from git, and its path dependencies are workspace
  crates of the nodes its table lists, or what they reach, none of which is or reaches a shipped
  crate.

Standard library only, Python 3.11 or later. Exits 1 and prints every violation when a check fails.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/check_workspace.py needs Python 3.11 or later (tomllib); this is {sys.version.split()[0]}")

import argparse
import fnmatch
import json
import os
import re
import subprocess
import tomllib
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

CI_DIR = Path(__file__).resolve().parent
REPO_ROOT = CI_DIR.parent
GRAPH_FILE = CI_DIR / "crate_graph.toml"
TOOLCHAIN_FILE = REPO_ROOT / "rust-toolchain.toml"

LICENSE = "Apache-2.0"
EDITION = "2024"
# Assembled from two halves so that this file does not carry the marker it looks for.
SPDX_MARKER = "SPDX-" + "License-Identifier"
SPDX_HEADER_LINES = 10
SPDX_SCANNED_SUFFIXES = frozenset({".rs", ".toml", ".py", ".yml", ".yaml", ".sh"})
FORBID_ATTRIBUTE = "#![forbid(unsafe_code)]"
VILICUS_NAMES = ("vilicus", "vilicus-*")
# Directories whose manifests must all be workspace members, and where no Cargo configuration
# file may sit (with the repository root). Spikes keep their own configuration.
CRATE_DIRECTORIES = ("crates", "testing", "fuzz")
CARGO_CONFIG_NAMES = ("config", "config.toml")
# Third-party sources as `cargo vendor` writes them (D28); they keep their own headers.
VENDOR_DIRECTORY = "vendor"
# Passed with `--config`, not kept in a root .cargo/config.toml, which cargo would also apply
# inside spikes/. Cargo resolves its `directory` against the parent of ci/, the repository root.
VENDORED_CONFIG_FILE = PurePosixPath("ci/cargo-vendored.toml")
VENDORED_SOURCE_CONFIG = {
    "source": {
        "crates-io": {"replace-with": "vendored-sources"},
        "vendored-sources": {"directory": VENDOR_DIRECTORY},
    }
}
WALK_SKIPPED_DIRECTORIES = frozenset({".git", "target"})
ROOT_TARGET_KINDS = frozenset({"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro", "bin"})
LINKED_KINDS = frozenset({"normal", "build"})
# AD-9: a module reaches the Core through the module port alone. The graph keeps shipped modules
# to it; the reference module shares the testing node, whose doubles may reach the Core, so this
# check holds it to the port (Story 3.5 review). Its dev-dependencies may serve its tests.
REFERENCE_MODULE = "vilicus-mod-reference"
MODULE_PORT = "vilicus-module-api"

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"//[^\n]*")
INNER_ATTRIBUTE = re.compile(r"#!\[(.*?)\]", re.DOTALL)
FORBID_LINTS = re.compile(r"^\s*forbid\s*\(([^)]*)\)\s*$", re.DOTALL)
ALLOW_OR_EXPECT_LINTS = re.compile(r"\b(?:allow|expect)\s*\(([^)]*)\)")
# Comments, string literals (raw and byte strings included) and character literals, removed
# before a source is searched for the `unsafe` keyword, in one pass, so that a quote inside a
# comment or a comment marker inside a literal is never read as the start of the other.
SOURCE_NOISE = re.compile(
    r"""//[^\n]*|/\*.*?\*/|b?r(#*)".*?"\1|b?"(?:[^"\\]|\\.)*"|b?'(?:[^'\\\n]|\\.[^'\n]*)'""",
    re.DOTALL,
)
UNSAFE_KEYWORD = re.compile(r"\bunsafe\b")
# An entry of [unsafe_code.modules]: one module directly under src/, which a crate root is not.
UNSAFE_MODULE_ENTRY = re.compile(r"src/[A-Za-z_][A-Za-z0-9_]*")
CRATE_ROOT_MODULES = frozenset({"src/lib", "src/main"})
# `path = "..."` inside an attribute (`cfg_attr` included), and the `include!` family with its
# argument when that is a single string literal; group 2 is None for a computed path.
STRING_LITERAL = r'"(?:[^"\\]|\\.)*"'
PATH_ATTRIBUTE = re.compile(rf"#!?\[[^\]]*\bpath\s*=\s*({STRING_LITERAL})")
INCLUDE_MACRO = re.compile(rf"\b(include|include_str|include_bytes)\s*!\s*[(\[{{]\s*(?:({STRING_LITERAL})\s*[)\]}}])?")


@dataclass(frozen=True)
class Node:
    id: str
    crates: tuple[str, ...]
    paths: tuple[str, ...]
    pattern: str | None
    depends_on: tuple[str, ...]
    private: bool
    dev_only: bool
    shipped: bool
    required: bool


@dataclass(frozen=True)
class Isolated:
    """Crates outside the AD-3 graph that no crate may depend on."""

    id: str
    crates: tuple[str, ...]
    paths: tuple[str, ...]
    depends_on: tuple[str, ...]
    exclusive_dependencies: tuple[str, ...] = ()


class Graph:
    """The AD-3 graph as ci/crate_graph.toml encodes it, and the isolated crates beside it."""

    def __init__(self, nodes: dict[str, Node], isolated: dict[str, Isolated] | None = None) -> None:
        isolated = isolated or {}
        for source in [*nodes.values(), *isolated.values()]:
            for target in source.depends_on:
                if target not in nodes:
                    raise ValueError(f"node {source.id} depends on unknown node {target}")
        for table_id in isolated.keys() & nodes.keys():
            raise ValueError(f"[isolated.{table_id}] has the id of a node")
        self.nodes = nodes
        self.isolated = isolated

    @classmethod
    def from_config(cls, config: dict) -> Graph:
        nodes = {}
        for node_id, table in config["node"].items():
            nodes[node_id] = Node(
                id=node_id,
                crates=tuple(table.get("crates", ())),
                paths=tuple(PurePosixPath(p).as_posix() for p in table.get("paths", ())),
                pattern=table.get("pattern"),
                depends_on=tuple(table.get("depends_on", ())),
                private=table.get("private", False),
                dev_only=table.get("dev_only", False),
                shipped=table.get("shipped", False),
                required=table.get("required", False),
            )
        isolated = {
            table_id: Isolated(
                id=table_id,
                crates=tuple(table.get("crates", ())),
                paths=tuple(PurePosixPath(p).as_posix() for p in table.get("paths", ())),
                depends_on=tuple(table.get("depends_on", ())),
                exclusive_dependencies=tuple(table.get("exclusive_dependencies", ())),
            )
            for table_id, table in config.get("isolated", {}).items()
        }
        return cls(nodes, isolated)

    def classify_isolated(self, crate_name: str, crate_dir: str) -> Isolated | None:
        """Exact name first, then manifest directory; tried before the nodes, so that neither a
        node's directory nor its name pattern claims an isolated crate."""
        for table in self.isolated.values():
            if crate_name in table.crates:
                return table
        directory = PurePosixPath(crate_dir)
        for table in self.isolated.values():
            if any(directory.is_relative_to(path) for path in table.paths):
                return table
        return None

    def isolated_allows(self, source: Isolated, target: Node) -> bool:
        """An isolated crate may depend on the nodes it lists and on what they reach, except a
        private node it does not list."""
        if target.private and target.id not in source.depends_on:
            return False
        return target.id in source.depends_on or any(target.id in self.reachable(node) for node in source.depends_on)

    def classify(self, crate_name: str, crate_dir: str) -> Node | None:
        """Exact name first, then manifest directory, then name pattern."""
        for node in self.nodes.values():
            if crate_name in node.crates:
                return node
        directory = PurePosixPath(crate_dir)
        for node in self.nodes.values():
            if any(directory.is_relative_to(path) for path in node.paths):
                return node
        for node in self.nodes.values():
            if node.pattern and fnmatch.fnmatchcase(crate_name, node.pattern):
                return node
        return None

    def reachable(self, node_id: str) -> set[str]:
        seen: set[str] = set()
        queue = deque(self.nodes[node_id].depends_on)
        while queue:
            current = queue.popleft()
            if current not in seen:
                seen.add(current)
                queue.extend(self.nodes[current].depends_on)
        return seen

    def allows(self, source: Node, target: Node, kind: str) -> bool:
        if target.private and target.id not in source.depends_on:
            return False
        reached = self.reachable(source.id)
        if target.id in reached:
            return True
        # A dev-only crate may serve the tests of a crate that already sees everything it links.
        return (
            kind == "dev"
            and target.dev_only
            and all(dep == source.id or dep in reached for dep in target.depends_on)
        )


@dataclass(frozen=True)
class Dependency:
    name: str
    kind: str


@dataclass(frozen=True)
class Crate:
    name: str
    directory: str
    manifest_path: Path
    license: str | None
    edition: str | None
    rust_version: str | None
    publish: list[str] | None
    roots: tuple[Path, ...]
    # The source file of every target, tests, examples and build script included.
    targets: tuple[Path, ...]
    dependencies: tuple[Dependency, ...]


def _members(metadata: dict) -> list[dict]:
    member_ids = set(metadata["workspace_members"])
    return [package for package in metadata["packages"] if package["id"] in member_ids]


def _member_directories(metadata: dict) -> dict[Path, str]:
    return {Path(package["manifest_path"]).parent: package["name"] for package in _members(metadata)}


def load_workspace(metadata: dict) -> list[Crate]:
    """The workspace members of a `cargo metadata --format-version 1` document, with their
    path dependencies on other members (every other dependency source is `check_sources`'s)."""
    workspace_root = Path(metadata["workspace_root"])
    member_dirs = _member_directories(metadata)
    crates = []
    for package in _members(metadata):
        manifest_path = Path(package["manifest_path"])
        crates.append(
            Crate(
                name=package["name"],
                directory=manifest_path.parent.relative_to(workspace_root).as_posix(),
                manifest_path=manifest_path,
                license=package.get("license"),
                edition=package.get("edition"),
                rust_version=package.get("rust_version"),
                publish=package.get("publish"),
                roots=tuple(
                    Path(target["src_path"])
                    for target in package["targets"]
                    if ROOT_TARGET_KINDS.intersection(target["kind"])
                ),
                targets=tuple(Path(target["src_path"]) for target in package["targets"]),
                dependencies=tuple(
                    Dependency(name=member_dirs[Path(dep["path"])], kind=dep["kind"] or "normal")
                    for dep in package["dependencies"]
                    if dep.get("path") is not None and Path(dep["path"]) in member_dirs
                ),
            )
        )
    return crates


def _is_vilicus_name(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in VILICUS_NAMES)


def check_sources(metadata: dict) -> list[str]:
    violations = []
    members = _members(metadata)
    member_ids = {package["id"] for package in members}
    member_names = {package["name"] for package in members}
    member_dirs = _member_directories(metadata)
    for package in members:
        for dep in package["dependencies"]:
            target = f", target {dep['target']}" if dep.get("target") else ""
            edge = f"{package['name']} -> {dep['name']} ({dep['kind'] or 'normal'} dependency{target})"
            path = Path(dep["path"]) if dep.get("path") is not None else None
            source = dep.get("source") or ""
            if path is not None and path not in member_dirs:
                violations.append(f"source: {edge} is a path dependency on {path}, which is not a workspace member")
            elif source.startswith("git+"):
                violations.append(f"source: {edge} is a git dependency ({source}); only members and the registry are allowed")
            elif (dep["name"] in member_names or _is_vilicus_name(dep["name"])) and (
                path is None or member_dirs[path] != dep["name"]
            ):
                violations.append(f"source: {edge} names a Vilicus crate that is not the workspace member of that name")

    for package in metadata["packages"]:
        if package["id"] not in member_ids and package.get("source") is None:
            violations.append(
                f"source: {package['name']} {package['version']} ({package['manifest_path']}) is a path "
                "package that is not a workspace member; no supply-chain gate reviews it"
            )

    packages = {package["id"]: package for package in metadata["packages"]}
    for node in (metadata.get("resolve") or {}).get("nodes", []):
        if node["id"] not in member_ids:
            continue
        for dep in node["deps"]:
            name = packages[dep["pkg"]]["name"]
            if (name in member_names or _is_vilicus_name(name)) and dep["pkg"] not in member_ids:
                violations.append(
                    f"source: {packages[node['id']]['name']} resolves {name} to {dep['pkg']}, not a workspace member"
                )
    return violations


def check_root_manifest(root_manifest: dict) -> list[str]:
    return [
        f"source: the root Cargo.toml has a [{table}] table, which substitutes a dependency's source; "
        "add the crate as a dependency instead"
        for table in ("patch", "replace")
        if table in root_manifest
    ]


def check_graph(graph: Graph, crates: list[Crate]) -> list[str]:
    violations = []
    nodes: dict[str, Node] = {}
    isolated: dict[str, Isolated] = {}
    for crate in crates:
        table = graph.classify_isolated(crate.name, crate.directory)
        if table is not None:
            isolated[crate.name] = table
            if crate.name not in table.crates:
                violations.append(
                    f"graph: crate {crate.name} ({crate.directory}) matches [isolated.{table.id}] by its directory "
                    f"only; list it in {GRAPH_FILE.name}, so that the checks keyed on names cover it"
                )
            continue
        node = graph.classify(crate.name, crate.directory)
        if node is None:
            violations.append(
                f"graph: crate {crate.name} ({crate.directory}) matches no node of "
                f"{GRAPH_FILE.name}; add it to AD-3 first"
            )
        else:
            nodes[crate.name] = node
            if crate.name not in node.crates and not (node.pattern and fnmatch.fnmatchcase(crate.name, node.pattern)):
                expected = f" or name it {node.pattern}" if node.pattern else ""
                violations.append(
                    f"graph: crate {crate.name} ({crate.directory}) matches node {node.id} by its directory only; "
                    f"list it in {GRAPH_FILE.name}{expected}, so that the checks keyed on names cover it"
                )

    for crate in crates:
        for dep in crate.dependencies:
            if dep.name in isolated:
                violations.append(
                    f"graph: forbidden edge {crate.name} -> {dep.name} ({dep.kind} dependency; {dep.name} is "
                    f"isolated by [isolated.{isolated[dep.name].id}]: no crate may depend on it)"
                )
            elif crate.name in isolated and dep.name in nodes:
                source, target = isolated[crate.name], nodes[dep.name]
                if not graph.isolated_allows(source, target):
                    violations.append(
                        f"graph: forbidden edge {crate.name} -> {dep.name} ({dep.kind} dependency; "
                        f"[isolated.{source.id}] reaches {', '.join(source.depends_on)} only)"
                    )

    present = {node.id for node in nodes.values()}
    for node in graph.nodes.values():
        if node.required and node.id not in present:
            violations.append(f"graph: required node {node.id} ({', '.join(node.crates)}) has no workspace crate")

    for crate in crates:
        source = nodes.get(crate.name)
        if source is None:
            continue
        for dep in crate.dependencies:
            target = nodes.get(dep.name)
            if target is None or graph.allows(source, target, dep.kind):
                continue
            if target.private:
                reason = f"{target.id} is private to {', '.join(_dependents(graph, target))}"
            elif target.dev_only and dep.kind == "dev":
                reason = f"{target.id} links {', '.join(target.depends_on)}, which {source.id} does not reach"
            else:
                reason = f"AD-3 has no path {source.id} -> {target.id}"
            violations.append(
                f"graph: forbidden edge {crate.name} -> {dep.name} ({dep.kind} dependency; {reason})"
            )

    by_name = {crate.name: crate for crate in crates}
    for crate in crates:
        node = nodes.get(crate.name)
        if node is None or not node.shipped:
            continue
        for reached, path in linked_closure(crate, by_name):
            reached_node = nodes.get(reached)
            if reached_node is not None and reached_node.dev_only:
                violations.append(
                    f"graph: dev-only crate {reached} is linked into shipped crate {crate.name} "
                    f"({' -> '.join(path)})"
                )
    return violations


def shipped_closure(graph: Graph, crates: list[Crate]) -> list[Crate]:
    """Every shipped crate and every workspace crate it links through normal and build edges."""
    by_name = {crate.name: crate for crate in crates}
    closure: dict[str, Crate] = {}
    for crate in crates:
        node = graph.classify(crate.name, crate.directory)
        if node is not None and node.shipped:
            closure[crate.name] = crate
            closure.update((name, by_name[name]) for name, _ in linked_closure(crate, by_name))
    return list(closure.values())


def _outside(path: Path, directory: Path) -> bool:
    return not path.resolve().is_relative_to(directory.resolve())


def _literal_path(literal: str) -> str:
    """The text of a Rust string literal holding a path (quotes and escaped backslashes undone)."""
    return literal[1:-1].replace("\\\\", "\\")


def check_shipped_sources(graph: Graph, crates: list[Crate]) -> list[str]:
    """A crate in the shipped closure compiles only files of its own directory: no target source,
    `#[path]` module, `include!`-family file or symbolic link outside it, so that it cannot
    compile testing/ code that the dependency graph keeps out (FR-109, D102). A computed
    `include!` path cannot be resolved here, so it fails too."""
    violations = []
    for crate in shipped_closure(graph, crates):
        directory = crate.manifest_path.parent
        for source in crate.targets:
            if _outside(source, directory):
                violations.append(f"shipped: a target of {crate.name} compiles {source}, outside its package {directory}")
        for current, subdirectories, names in os.walk(directory):
            subdirectories[:] = [name for name in subdirectories if name not in WALK_SKIPPED_DIRECTORIES]
            for name in [*subdirectories, *names]:
                path = Path(current) / name
                if path.is_symlink() and _outside(path, directory):
                    violations.append(f"shipped: {path} of {crate.name} links to {path.resolve()}, outside its package")
                if not name.endswith(".rs") or not path.is_file():
                    continue
                code = LINE_COMMENT.sub("", BLOCK_COMMENT.sub(" ", path.read_text(encoding="utf-8", errors="replace")))
                for match in PATH_ATTRIBUTE.finditer(code):
                    if _outside(path.parent / _literal_path(match.group(1)), directory):
                        violations.append(f"shipped: {path} of {crate.name} takes a module from {match.group(1)}, outside its package")
                for match in INCLUDE_MACRO.finditer(code):
                    macro, literal = match.groups()
                    if literal is None:
                        violations.append(f"shipped: {path} of {crate.name} calls {macro}! with a computed path")
                    elif _outside(path.parent / _literal_path(literal), directory):
                        violations.append(f"shipped: {path} of {crate.name} calls {macro}!({literal}), outside its package")
    return violations


def _dependents(graph: Graph, target: Node) -> list[str]:
    return sorted(node.id for node in graph.nodes.values() if target.id in node.depends_on)


def linked_closure(root: Crate, by_name: dict[str, Crate]) -> list[tuple[str, list[str]]]:
    """Workspace crates reached from `root` through normal and build edges, with one path each."""
    reached: list[tuple[str, list[str]]] = []
    seen = {root.name}
    queue = deque([(root, [root.name])])
    while queue:
        crate, path = queue.popleft()
        for dep in crate.dependencies:
            if dep.kind not in LINKED_KINDS or dep.name in seen:
                continue
            seen.add(dep.name)
            dep_path = [*path, dep.name]
            reached.append((dep.name, dep_path))
            queue.append((by_name[dep.name], dep_path))
    return reached


def check_manifests(
    crates: list[Crate], workspace_root: Path, toolchain_channel: str, files: Iterable[Path]
) -> list[str]:
    violations = []
    for crate in crates:
        if crate.license != LICENSE:
            violations.append(f"manifest: {crate.name} declares license {crate.license!r}, expected {LICENSE!r}")
        if crate.edition != EDITION:
            violations.append(f"manifest: {crate.name} declares edition {crate.edition!r}, expected {EDITION!r}")
        if crate.rust_version != toolchain_channel:
            violations.append(
                f"manifest: {crate.name} declares rust-version {crate.rust_version!r}, "
                f"expected {toolchain_channel!r} from rust-toolchain.toml"
            )
        # cargo metadata reports `publish = false` as an empty registry list, and its absence as null.
        if crate.publish != []:
            violations.append(f"manifest: {crate.name} may be published ({crate.publish!r}); expected publish = false")
    member_manifests = {crate.manifest_path for crate in crates}
    for directory in CRATE_DIRECTORIES:
        for manifest in sorted((workspace_root / directory).rglob("Cargo.toml")):
            if manifest not in member_manifests and not WALK_SKIPPED_DIRECTORIES.intersection(manifest.parts):
                violations.append(f"manifest: {manifest} is not a workspace member, so no check covers it")
    marker = re.compile(re.escape(SPDX_MARKER), re.IGNORECASE)
    vendor = workspace_root / VENDOR_DIRECTORY
    for path in files:
        if path.suffix not in SPDX_SCANNED_SUFFIXES or path.is_relative_to(vendor):
            continue
        header = path.read_text(encoding="utf-8", errors="replace").splitlines()[:SPDX_HEADER_LINES]
        if any(marker.search(line) for line in header):
            violations.append(f"manifest: {path} carries an SPDX header; the licence is in LICENSE only")
    return violations


def _lint_level(table: dict, lint: str) -> str | None:
    """A lint's level, written either as `lint = "level"` or as `lint = { level = "level" }`."""
    value = table.get(lint)
    return value.get("level") if isinstance(value, dict) else value


def _inner_attributes(path: Path) -> list[str]:
    """The inner attributes of a Rust source file, comments removed first."""
    code = LINE_COMMENT.sub("", BLOCK_COMMENT.sub(" ", path.read_text(encoding="utf-8")))
    return INNER_ATTRIBUTE.findall(code)


def _lint_names(lint_list: str) -> set[str]:
    return {name.strip() for name in lint_list.split(",")}


def _unsafe_crate_lints(workspace_lints: dict) -> dict[tuple[str, str], str | None]:
    """What an unsafe-allowed crate must declare: every workspace lint at its level, with unsafe
    code and undocumented unsafe blocks denied."""
    expected = {
        (table_name, lint): _lint_level(table, lint)
        for table_name, table in workspace_lints.items()
        for lint in table
    }
    expected[("rust", "unsafe_code")] = "deny"
    expected[("clippy", "undocumented_unsafe_blocks")] = "deny"
    return expected


def check_unsafe(config: dict, root_manifest: dict, crates: list[Crate]) -> list[str]:
    violations = []
    policy = config["unsafe_code"]
    workspace_lints = root_manifest.get("workspace", {}).get("lints", {})
    workspace_level = _lint_level(workspace_lints.get("rust", {}), "unsafe_code")
    if workspace_level != "forbid":
        violations.append(f"unsafe: [workspace.lints.rust] unsafe_code is {workspace_level!r}, expected 'forbid'")
    expected = _unsafe_crate_lints(workspace_lints)
    for crate in crates:
        lints = tomllib.loads(crate.manifest_path.read_text(encoding="utf-8")).get("lints", {})
        unsafe_level = _lint_level(lints.get("rust", {}), "unsafe_code")
        if crate.name in policy["allowed"]:
            problems = ["it inherits [workspace.lints]"] if lints.get("workspace") is True else []
            for (table_name, lint), level in expected.items():
                found = _lint_level(lints.get(table_name, {}), lint)
                if found != level:
                    problems.append(f"[lints.{table_name}] {lint} is {found!r}, expected {level!r}")
            if problems:
                violations.append(
                    f"unsafe: {crate.name} may hold unsafe code, so its manifest must repeat the workspace "
                    f"lints with unsafe_code and clippy undocumented_unsafe_blocks denied: {'; '.join(problems)}"
                )
            for source in sorted(crate.manifest_path.parent.joinpath("src").rglob("*.rs")):
                for attribute in _inner_attributes(source):
                    if any("unsafe_code" in _lint_names(found) for found in ALLOW_OR_EXPECT_LINTS.findall(attribute)):
                        violations.append(
                            f"unsafe: {source} of {crate.name} allows unsafe code for a whole module "
                            f"(#![{attribute.strip()}]); allow it per block (D140)"
                        )
        elif lints.get("workspace") is not True:
            relaxed = f"; it sets unsafe_code {unsafe_level!r}, which only D140's crates may relax" if unsafe_level else ""
            violations.append(
                f"unsafe: {crate.name} does not inherit the workspace lints ([lints] workspace = true){relaxed}"
            )
        if any(fnmatch.fnmatchcase(crate.name, pattern) for pattern in policy["forbid_attribute"]):
            for root in crate.roots:
                forbids = (FORBID_LINTS.match(attribute) for attribute in _inner_attributes(root))
                if not any(match and "unsafe_code" in _lint_names(match.group(1)) for match in forbids):
                    violations.append(f"unsafe: crate root {root} of {crate.name} lacks {FORBID_ATTRIBUTE}")
    return violations


def _doc_code(text: str) -> str:
    """The code of the fenced blocks of the doc comments of `text` (`///` and `//!` lines),
    hidden lines included: rustdoc compiles those blocks as doc tests, so their `unsafe` counts."""
    code = []
    fenced = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped.startswith(("///", "//!")):
            fenced = False
            continue
        content = stripped[3:]
        content = content[1:] if content.startswith(" ") else content
        if content.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            hidden = content.lstrip()
            code.append(hidden[2:] if hidden.startswith("# ") else "" if hidden == "#" else content)
    return "\n".join(code)


def _uses_unsafe(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return any(UNSAFE_KEYWORD.search(SOURCE_NOISE.sub(" ", code)) for code in (text, _doc_code(text)))


def _in_module(relative: str, module: str) -> bool:
    return relative == f"{module}.rs" or relative.startswith(f"{module}/")


def _module_entry_violation(name: str, module: object) -> str | None:
    """An entry must name one module under `src/`, never `src` itself or a crate root, either of
    which would let the whole crate hold unsafe code."""
    if isinstance(module, str) and UNSAFE_MODULE_ENTRY.fullmatch(module) and module not in CRATE_ROOT_MODULES:
        return None
    return (
        f"unsafe: [unsafe_code.modules] entry {module!r} of {name} must name one module under src/, "
        f"src/<name>, not src itself, a crate root ({', '.join(sorted(CRATE_ROOT_MODULES))}) or a deeper path"
    )


def _crossings(path: Path, relative: str, crate_dir: Path, module: str) -> list[str]:
    """The `#[path]` and `include!`-family literals of `path` that cross into or out of `module`,
    and its computed `include!` calls, which cannot be resolved. A `#[path]` is resolved against
    the file's directory and, for a module declared inside an inline module, against the
    directory named after the file, both tried."""
    code = LINE_COMMENT.sub("", BLOCK_COMMENT.sub(" ", path.read_text(encoding="utf-8", errors="replace")))
    inside = _in_module(relative, module)
    found = []
    targets: list[tuple[str, str]] = [(match.group(1), "#[path]") for match in PATH_ATTRIBUTE.finditer(code)]
    for match in INCLUDE_MACRO.finditer(code):
        macro, literal = match.groups()
        if literal is None:
            found.append(f"calls {macro}! with a computed path, which cannot be held to its unsafe module")
        else:
            targets.append((literal, f"{macro}!"))
    for literal, how in targets:
        candidates = [path.parent / _literal_path(literal), path.parent / path.stem / _literal_path(literal)]
        for candidate in candidates:
            resolved = Path(os.path.normpath(candidate))
            try:
                target = resolved.relative_to(Path(os.path.normpath(crate_dir))).as_posix()
            except ValueError:
                target = resolved.as_posix()
            if _in_module(target, module) != inside:
                direction = "out of" if inside else "into"
                found.append(f"takes {literal} by {how}, which crosses {direction} its unsafe module {module}")
                break
    return found


def check_unsafe_modules(config: dict, crates: list[Crate]) -> list[str]:
    """The `unsafe` keyword appears only in the module of a crate of `allowed` that
    `[unsafe_code.modules]` names: `<module>.rs` and the files under `<module>/`, doc tests
    included; no `#[path]` or `include!` brings a file into or out of that module."""
    policy = config["unsafe_code"]
    modules = policy.get("modules", {})
    violations = [
        f"unsafe: [unsafe_code.modules] names {name}, which is not a crate D140 allows unsafe code in"
        for name in sorted(modules)
        if name not in policy["allowed"]
    ]
    for name, module in sorted(modules.items()):
        violation = _module_entry_violation(name, module)
        if violation:
            violations.append(violation)
    for crate in crates:
        crate_dir = crate.manifest_path.parent
        module = modules.get(crate.name)
        if module is not None and _module_entry_violation(crate.name, module):
            module = None
        for source in sorted(crate_dir.rglob("*.rs")):
            relative = source.relative_to(crate_dir).as_posix()
            if relative.split("/", 1)[0] in WALK_SKIPPED_DIRECTORIES:
                continue
            if module is not None:
                violations.extend(
                    f"unsafe: {source} of {crate.name} {crossing} (D140)"
                    for crossing in _crossings(source, relative, crate_dir, module)
                )
                if _in_module(relative, module):
                    continue
            if _uses_unsafe(source):
                where = (
                    f"outside its unsafe module {module}"
                    if module is not None
                    else "and its crate has no unsafe module in [unsafe_code.modules] of ci/crate_graph.toml"
                )
                violations.append(f"unsafe: {source} of {crate.name} uses unsafe code {where} (D140)")
    return violations


def check_cargo_config(workspace_root: Path) -> list[str]:
    """Cargo configuration can pass rustflags such as `--cap-lints allow`, which would neutralise
    the lint levels the other checks rely on."""
    directories = [workspace_root / ".cargo"]
    for directory in CRATE_DIRECTORIES:
        directories.extend(sorted((workspace_root / directory).rglob(".cargo")))
    return [
        f"unsafe: {directory / name} exists; Cargo configuration could override the workspace lint levels"
        for directory in directories
        for name in CARGO_CONFIG_NAMES
        if (directory / name).is_file()
    ]


def check_vendored_config(workspace_root: Path) -> list[str]:
    """The `--config` file of the vendored build holds only the source replacement: any other key,
    rustflags above all, would reach every build that reads it."""
    path = workspace_root / VENDORED_CONFIG_FILE
    if not path.is_file():
        return [f"vendor: {path} is missing; builds must read the vendored sources (D28)"]
    try:
        content = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        return [f"vendor: {path} is not valid TOML ({error})"]
    if content != VENDORED_SOURCE_CONFIG:
        return [
            f"vendor: {path} must hold only the replacement of crates.io by `{VENDOR_DIRECTORY}/` "
            f"({json.dumps(VENDORED_SOURCE_CONFIG)}), found {json.dumps(content)}; "
            "any other key could override the workspace lint levels"
        ]
    return []


def check_reference_module(metadata: dict) -> list[str]:
    """The reference module links the module port alone, the workspace member of that name: any
    other normal or build dependency, a workspace crate or a registry package, fails, and so does
    a dependency named like the port that is not a path dependency on that member."""
    port_dirs = [path for path, name in _member_directories(metadata).items() if name == MODULE_PORT]
    violations = []
    for package in _members(metadata):
        if package["name"] != REFERENCE_MODULE:
            continue
        for dep in package["dependencies"]:
            kind = dep["kind"] or "normal"
            if kind not in LINKED_KINDS:
                continue
            path = Path(dep["path"]) if dep.get("path") is not None else None
            if dep["name"] != MODULE_PORT:
                violations.append(
                    f"reference: {package['name']} -> {dep['name']} ({kind} dependency); the reference "
                    f"module is a module and links {MODULE_PORT} alone (AD-9)"
                )
            elif path is None or path not in port_dirs:
                violations.append(
                    f"reference: {package['name']} -> {dep['name']} ({kind} dependency) is not a path "
                    f"dependency on the workspace member {MODULE_PORT}"
                )
    return violations


def check_exclusive_dependencies(graph: Graph, metadata: dict) -> list[str]:
    """A package an isolated table keeps for its crates is reached by no other workspace crate:
    not as a dependency of any kind it declares, nor through the registry packages it resolves
    (another member's own tree is that member's to answer for)."""
    owners = {name: table for table in graph.isolated.values() for name in table.exclusive_dependencies}
    if not owners:
        return []
    members = _members(metadata)
    member_ids = {package["id"] for package in members}
    packages = _packages_by_id(metadata)
    resolved = {node["id"]: [dep["pkg"] for dep in node["deps"]] for node in (metadata.get("resolve") or {}).get("nodes", [])}
    violations = []
    for package in members:
        allowed = {name for name, table in owners.items() if package["name"] in table.crates}
        direct = set()
        for dep in package["dependencies"]:
            if dep["name"] in owners and dep["name"] not in allowed:
                direct.add(dep["name"])
                violations.append(
                    f"isolated: {package['name']} -> {dep['name']} ({dep['kind'] or 'normal'} dependency); only "
                    f"{', '.join(owners[dep['name']].crates)} of [isolated.{owners[dep['name']].id}] may depend on it"
                )
        seen: set[str] = set()
        queue = deque((dep, [package["name"]]) for dep in resolved.get(package["id"], []) if dep not in member_ids)
        while queue:
            package_id, path = queue.popleft()
            if package_id in seen or package_id not in packages:
                continue
            seen.add(package_id)
            name = packages[package_id]["name"]
            if name in owners and name not in allowed and name not in direct:
                violations.append(
                    f"isolated: {package['name']} reaches {name} ({' -> '.join([*path, name])}); only "
                    f"{', '.join(owners[name].crates)} of [isolated.{owners[name].id}] may depend on it"
                )
            queue.extend((dep, [*path, name]) for dep in resolved.get(package_id, []) if dep not in member_ids)
    return violations


def check_restricted_dependencies(config: dict, metadata: dict) -> list[str]:
    """Each package of `[restricted.*]` is declared only by the crates its `linked` table (normal
    and build dependencies) or `dev` table (dev-dependencies) names, each with a reason."""
    restricted = config.get("restricted", {})
    violations = [
        f"restricted: [restricted.{package}.{table}] entry {name} gives no reason"
        for package, tables in sorted(restricted.items())
        for table, crates in sorted(tables.items())
        for name, reason in sorted(crates.items())
        if not isinstance(reason, str) or not reason.strip()
    ]
    for package in _members(metadata):
        for dep in package["dependencies"]:
            if dep["name"] not in restricted:
                continue
            kind = dep["kind"] or "normal"
            table = "linked" if kind in LINKED_KINDS else "dev"
            allowed = restricted[dep["name"]].get(table, {})
            if package["name"] not in allowed:
                violations.append(
                    f"restricted: {package['name']} -> {dep['name']} ({kind} dependency); only "
                    f"{', '.join(sorted(allowed)) or 'no crate'} may take it as a {table} dependency "
                    f"([restricted.{dep['name']}] of ci/crate_graph.toml)"
                )
    return violations


def _packages_by_id(metadata: dict) -> dict[str, dict]:
    return {package["id"]: package for package in metadata["packages"]}


def run_checks(
    metadata: dict, config: dict, root_manifest: dict, toolchain_channel: str, files: Iterable[Path]
) -> list[str]:
    crates = load_workspace(metadata)
    workspace_root = Path(metadata["workspace_root"])
    return [
        *check_sources(metadata),
        *check_root_manifest(root_manifest),
        *check_graph(Graph.from_config(config), crates),
        *check_reference_module(metadata),
        *check_shipped_sources(Graph.from_config(config), crates),
        *check_exclusive_dependencies(Graph.from_config(config), metadata),
        *check_restricted_dependencies(config, metadata),
        *check_manifests(crates, workspace_root, toolchain_channel, files),
        *check_unsafe(config, root_manifest, crates),
        *check_unsafe_modules(config, crates),
        *check_cargo_config(workspace_root),
        *check_vendored_config(workspace_root),
    ]


DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _manifest_dependencies(manifest: dict) -> list[tuple[str, object]]:
    """Every dependency a manifest declares, by name, in its own and its target-specific tables."""
    tables = [manifest.get(table, {}) for table in DEPENDENCY_TABLES]
    for target in manifest.get("target", {}).values():
        tables.extend(target.get(table, {}) for table in DEPENDENCY_TABLES)
    return [(name, spec) for table in tables for name, spec in table.items()]


def check_oracles(config: dict, metadata: dict) -> list[str]:
    """Cross-test oracles outside the workspace ([oracle.*] of ci/crate_graph.toml; D153, Story
    4.4): each is its own workspace with its own lockfile, no workspace crate is it or depends on
    it, and its path dependencies are workspace crates of the nodes it lists, none of which is or
    reaches a shipped crate."""
    violations: list[str] = []
    workspace_root = Path(metadata["workspace_root"])
    graph = Graph.from_config(config)
    crates = load_workspace(metadata)
    by_name = {crate.name: crate for crate in crates}
    by_directory = {(workspace_root / crate.directory).resolve(): crate for crate in crates}
    shipped = set()
    for crate in crates:
        node = graph.classify(crate.name, crate.directory)
        if node is not None and node.shipped:
            shipped.add(crate.name)
    for oracle_id, table in sorted(config.get("oracle", {}).items()):
        where = f"[oracle.{oracle_id}]"
        if not str(table.get("record", "")).strip():
            violations.append(f"oracle: {where} gives no record")
        unknown = [node for node in table.get("depends_on", []) if node not in graph.nodes]
        if unknown:
            violations.append(f"oracle: {where} names unknown node(s) {', '.join(unknown)}")
        directory = (workspace_root / table.get("path", "")).resolve()
        manifest_path = directory / "Cargo.toml"
        if not table.get("path") or not manifest_path.is_file():
            violations.append(f"oracle: {where} names no crate directory with a Cargo.toml ({table.get('path')})")
            continue
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest.get("workspace"), dict):
            violations.append(f"oracle: {where} has no [workspace] table of its own: it would join the Vilicus workspace")
        if not (directory / "Cargo.lock").is_file():
            violations.append(f"oracle: {where} has no Cargo.lock of its own")
        for package in metadata["packages"]:
            if package["id"] not in metadata["workspace_members"]:
                continue
            if Path(package["manifest_path"]).resolve().is_relative_to(directory):
                violations.append(f"oracle: {package['name']} under {where} is a workspace member")
            for dep in package["dependencies"]:
                if dep.get("path") is not None and Path(dep["path"]).resolve().is_relative_to(directory):
                    violations.append(f"oracle: {package['name']} depends on {dep['name']} of {where}; no crate may")
        allowed = set(table.get("depends_on", []))
        for node in table.get("depends_on", []):
            if node in graph.nodes:
                allowed |= graph.reachable(node)
        for name, spec in _manifest_dependencies(manifest):
            if not isinstance(spec, dict):
                continue
            if "git" in spec:
                violations.append(f"oracle: {where} takes {name} from git")
            if "path" not in spec:
                continue
            crate = by_directory.get((directory / spec["path"]).resolve())
            if crate is None:
                violations.append(f"oracle: {where} depends on {name} by a path that is not a workspace crate")
                continue
            node = graph.classify(crate.name, crate.directory)
            if node is None or node.id not in allowed:
                violations.append(
                    f"oracle: {where} depends on {crate.name}, outside the nodes it lists "
                    f"({', '.join(table.get('depends_on', [])) or 'none'})"
                )
            reached = {name for name, _ in linked_closure(crate, by_name)} | {crate.name}
            for reached_name in sorted(reached & shipped):
                violations.append(f"oracle: {where} reaches the shipped crate {reached_name} through {crate.name}")
    return violations


def repository_files(root: Path) -> list[Path]:
    """Tracked files and untracked files not ignored by git, so a new file is checked before its
    commit; without git, every file of the tree outside build output and the git directory."""
    try:
        listing = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=True,
            capture_output=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        files = []
        for directory, subdirectories, names in os.walk(root):
            subdirectories[:] = [name for name in subdirectories if name not in WALK_SKIPPED_DIRECTORIES]
            files.extend(Path(directory) / name for name in names)
        return files
    paths = (root / name for name in listing.decode().split("\0") if name)
    return [path for path in paths if path.is_file()]


def cargo_metadata(root: Path) -> dict:
    output = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--config", str(VENDORED_CONFIG_FILE)],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return json.loads(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--metadata", type=Path, help="read cargo metadata JSON from this file instead of running cargo")
    args = parser.parse_args(argv)

    metadata = json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else cargo_metadata(REPO_ROOT)
    workspace_root = Path(metadata["workspace_root"])
    config = tomllib.loads(GRAPH_FILE.read_text(encoding="utf-8"))
    root_manifest = tomllib.loads((workspace_root / "Cargo.toml").read_text(encoding="utf-8"))
    toolchain_channel = tomllib.loads(TOOLCHAIN_FILE.read_text(encoding="utf-8"))["toolchain"]["channel"]

    violations = [
        *run_checks(metadata, config, root_manifest, toolchain_channel, repository_files(workspace_root)),
        *check_oracles(config, metadata),
    ]
    for violation in violations:
        print(violation)
    if violations:
        return 1
    print(f"workspace checks passed: {len(load_workspace(metadata))} crates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
