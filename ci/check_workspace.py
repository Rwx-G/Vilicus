#!/usr/bin/env python3
"""Workspace policy checks over `cargo metadata`.

- Crate graph (doc/architecture-spine.md AD-3, D140): every edge between workspace crates must be
  allowed by ci/crate_graph.toml, every required node has a crate, and no dev-only crate may sit
  in the normal or build closure of a shipped crate. A crate that matches a node by its directory
  only (a crate under testing/ that is neither listed nor named vilicus-double-*) fails.
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
  crate root; no Cargo configuration file can change lint levels for the workspace.
- Vendored sources (D28): ci/cargo-vendored.toml, the configuration CI passes to every workspace
  build with `--config`, exists and holds nothing but the replacement of crates.io by vendor/.

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
CRATE_DIRECTORIES = ("crates", "testing")
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

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"//[^\n]*")
INNER_ATTRIBUTE = re.compile(r"#!\[(.*?)\]", re.DOTALL)
FORBID_LINTS = re.compile(r"^\s*forbid\s*\(([^)]*)\)\s*$", re.DOTALL)
ALLOW_OR_EXPECT_LINTS = re.compile(r"\b(?:allow|expect)\s*\(([^)]*)\)")
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


class Graph:
    """The AD-3 graph as ci/crate_graph.toml encodes it."""

    def __init__(self, nodes: dict[str, Node]) -> None:
        for node in nodes.values():
            for target in node.depends_on:
                if target not in nodes:
                    raise ValueError(f"node {node.id} depends on unknown node {target}")
        self.nodes = nodes

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
        return cls(nodes)

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
    for crate in crates:
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


def run_checks(
    metadata: dict, config: dict, root_manifest: dict, toolchain_channel: str, files: Iterable[Path]
) -> list[str]:
    crates = load_workspace(metadata)
    workspace_root = Path(metadata["workspace_root"])
    return [
        *check_sources(metadata),
        *check_root_manifest(root_manifest),
        *check_graph(Graph.from_config(config), crates),
        *check_shipped_sources(Graph.from_config(config), crates),
        *check_manifests(crates, workspace_root, toolchain_channel, files),
        *check_unsafe(config, root_manifest, crates),
        *check_cargo_config(workspace_root),
        *check_vendored_config(workspace_root),
    ]


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

    violations = run_checks(metadata, config, root_manifest, toolchain_channel, repository_files(workspace_root))
    for violation in violations:
        print(violation)
    if violations:
        return 1
    print(f"workspace checks passed: {len(load_workspace(metadata))} crates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
