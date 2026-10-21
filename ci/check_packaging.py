#!/usr/bin/env python3
"""Packaging check (doc/prd.md FR-109, D102; Story 2.6 AC3): no release artefact carries test code.

The release artefacts are the [artefact.*] entries of ci/release_artefacts.toml, each a bin
target of a workspace package. The check fails when an artefact

- is built from a crate of a never-packaged node of ci/crate_graph.toml (the testing/ tree and
  vilicus-testbed), carries the name of one of their executables, or has a name matching the
  name pattern of such a node (a `vilicus-double-*` binary built by a shipped crate);
- links such a crate through a normal or build dependency, at any depth, in `cargo metadata`;
- names a package that is not a workspace member, or a binary that package does not build;
- enables the `testing` feature of a workspace crate, which compiles test code such as the write
  path fuzz test of vilicus-core (Story 3.4), from the artefact's package or any crate it links:
  through a normal or build dependency, or in a feature of its own. A dev-dependency may.

With `--contents FILE`, it also reads a listing of the files a release ships, one path per line,
and fails on any path that names a never-packaged crate or one of its targets. No package exists
yet; the Debian package of Epic 5 (Story 5.7) passes its file listing here.

Standard library only, Python 3.11 or later. Exits 1 and prints every violation when the check
fails.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/check_packaging.py needs Python 3.11 or later (tomllib); this is {sys.version.split()[0]}")

import argparse
import fnmatch
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import check_workspace as cw

ARTEFACTS_FILE = cw.CI_DIR / "release_artefacts.toml"
CONFIG_KEYS = frozenset({"never_packaged", "artefact"})
ARTEFACT_KEYS = frozenset({"package", "binary"})
# The feature of a workspace crate that compiles test code; no release artefact enables it.
TEST_FEATURE = "testing"


@dataclass(frozen=True)
class Artefact:
    name: str
    package: str
    binary: str


def load_artefacts(config: dict) -> list[Artefact]:
    return [
        Artefact(name=name, package=table["package"], binary=table["binary"])
        for name, table in config.get("artefact", {}).items()
    ]


def bin_targets(package: dict) -> list[str]:
    return [target["name"] for target in package["targets"] if "bin" in target["kind"]]


def workspace_members(metadata: dict) -> dict[str, dict]:
    member_ids = set(metadata["workspace_members"])
    return {package["name"]: package for package in metadata["packages"] if package["id"] in member_ids}


def never_packaged_crates(metadata: dict, graph: cw.Graph, config: dict) -> dict[str, str]:
    """Workspace crate name -> the never-packaged node it belongs to."""
    nodes = set(config.get("never_packaged", ()))
    found = {}
    for crate in cw.load_workspace(metadata):
        node = graph.classify(crate.name, crate.directory)
        if node is not None and node.id in nodes:
            found[crate.name] = node.id
    return found


def testbed_binaries(metadata: dict, graph: cw.Graph, config: dict) -> list[str]:
    """The executables of the testbed artefact: every bin target of a never-packaged crate."""
    members = workspace_members(metadata)
    return sorted(binary for name in never_packaged_crates(metadata, graph, config) for binary in bin_targets(members[name]))


def forbidden_names(metadata: dict, graph: cw.Graph, config: dict) -> set[str]:
    """Never-packaged crate and target names, in their hyphenated and underscored spellings."""
    members = workspace_members(metadata)
    names = set()
    for name in never_packaged_crates(metadata, graph, config):
        for spelling in (name, *(target["name"] for target in members[name]["targets"])):
            names.update({spelling, spelling.replace("-", "_")})
    return names


def check_config(graph: cw.Graph, config: dict) -> list[str]:
    violations = [
        f"artefacts: unknown key {key!r} in {ARTEFACTS_FILE.name}; expected {sorted(CONFIG_KEYS)}"
        for key in sorted(set(config) - CONFIG_KEYS)
    ]
    nodes = config.get("never_packaged")
    if not isinstance(nodes, list) or not nodes:
        violations.append("artefacts: never_packaged must list the nodes of ci/crate_graph.toml that are never packaged")
        nodes = []
    for node_id in nodes:
        node = graph.nodes.get(node_id)
        if node is None:
            violations.append(f"artefacts: never_packaged names {node_id!r}, which is not a node of ci/crate_graph.toml")
        elif node.shipped:
            violations.append(f"artefacts: never_packaged names {node_id!r}, which ci/crate_graph.toml marks shipped")
    tables = config.get("artefact")
    if not isinstance(tables, dict) or not tables:
        violations.append("artefacts: no [artefact.*] entry; a release ships at least the vilicus executable")
        tables = {}
    for name, table in tables.items():
        if not isinstance(table, dict) or set(table) != ARTEFACT_KEYS or not all(
            isinstance(value, str) and value for value in table.values()
        ):
            violations.append(f"artefacts: [artefact.{name}] must hold exactly `package` and `binary`, as non-empty strings")
    return violations


def check_artefacts(metadata: dict, graph: cw.Graph, config: dict) -> list[str]:
    violations = check_config(graph, config)
    if violations:
        return violations
    members = workspace_members(metadata)
    never_packaged = never_packaged_crates(metadata, graph, config)
    testbed = set(testbed_binaries(metadata, graph, config))
    patterned = [graph.nodes[node_id] for node_id in config["never_packaged"] if graph.nodes[node_id].pattern]
    by_name = {crate.name: crate for crate in cw.load_workspace(metadata)}
    for artefact in load_artefacts(config):
        label = f"release artefact {artefact.name} ({artefact.package}, binary {artefact.binary})"
        package = members.get(artefact.package)
        if package is None:
            violations.append(f"packaging: {label} names a package that is not a workspace member")
            continue
        if artefact.binary not in bin_targets(package):
            violations.append(f"packaging: {label} names a binary that {artefact.package} does not build")
        if artefact.package in never_packaged:
            violations.append(
                f"packaging: {label} is built from {artefact.package}, a crate of never-packaged node "
                f"{never_packaged[artefact.package]} (D102)"
            )
        if artefact.binary in testbed:
            violations.append(f"packaging: {label} carries the name of testbed executable {artefact.binary} (D102)")
        for node in patterned:
            if fnmatch.fnmatchcase(artefact.binary, node.pattern):
                violations.append(
                    f"packaging: {label} matches {node.pattern}, the name pattern of never-packaged node {node.id} (D102)"
                )
        closure = cw.linked_closure(by_name[artefact.package], by_name)
        for reached, path in closure:
            if reached in never_packaged:
                violations.append(
                    f"packaging: {label} links {reached}, a crate of never-packaged node {never_packaged[reached]} "
                    f"({' -> '.join(path)}; D102)"
                )
        linked = [artefact.package, *(reached for reached, _ in closure)]
        violations.extend(test_feature_violations(label, linked, members))
    return violations


def test_feature_violations(label: str, linked: list[str], members: dict[str, dict]) -> list[str]:
    """The places where `linked`, an artefact's package and the crates it links, enable the test
    feature: a normal or build dependency that names it, or a feature of their own that does."""
    violations = []
    for name in linked:
        package = members[name]
        for dep in package.get("dependencies", []):
            if dep.get("kind") in (None, "build") and TEST_FEATURE in dep.get("features", []):
                violations.append(
                    f"packaging: {label} enables feature {TEST_FEATURE} of {dep['name']} through a "
                    f"{dep.get('kind') or 'normal'} dependency of {name} (Story 3.4)"
                )
        for feature, enabled in package.get("features", {}).items():
            if any(entry == TEST_FEATURE or entry.endswith(f"/{TEST_FEATURE}") for entry in enabled):
                violations.append(
                    f"packaging: {label} links {name}, whose feature {feature} enables {TEST_FEATURE} "
                    f"(Story 3.4)"
                )
    return violations


def check_contents(paths: list[str], names: set[str]) -> list[str]:
    """Paths of a release listing that name a never-packaged crate or target."""
    violations = []
    for path in paths:
        parts = PurePosixPath(path.strip()).parts
        found = sorted(name for name in names if any(name in part for part in parts))
        if found:
            violations.append(f"packaging: release file {path.strip()} names never-packaged {', '.join(found)} (D102)")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--metadata", type=Path, help="read cargo metadata JSON from this file instead of running cargo")
    parser.add_argument("--contents", type=Path, help="a listing of the files a release ships, one path per line")
    args = parser.parse_args(argv)

    metadata = json.loads(args.metadata.read_text(encoding="utf-8")) if args.metadata else cw.cargo_metadata(cw.REPO_ROOT)
    graph = cw.Graph.from_config(tomllib.loads(cw.GRAPH_FILE.read_text(encoding="utf-8")))
    config = tomllib.loads(ARTEFACTS_FILE.read_text(encoding="utf-8"))

    violations = check_artefacts(metadata, graph, config)
    if args.contents and not violations:
        listing = [line for line in args.contents.read_text(encoding="utf-8").splitlines() if line.strip()]
        violations = check_contents(listing, forbidden_names(metadata, graph, config))
    for violation in violations:
        print(violation)
    if violations:
        return 1
    never_packaged = never_packaged_crates(metadata, graph, config)
    print(
        f"packaging check passed: {len(load_artefacts(config))} release artefacts, none built from or "
        f"linking the {len(never_packaged)} never-packaged crates"
        + (f"; {len(listing)} release files clean" if args.contents else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
