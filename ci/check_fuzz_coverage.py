#!/usr/bin/env python3
"""Every public decoder of vilicus-proto has a fuzz target, from rustdoc's JSON (Story 2.7, AC1).

The authoritative form of fuzz/tests/coverage.rs, which scans the sources on stable: here the
compiler's own view of the public API, from `cargo +<nightly> rustdoc -p vilicus-proto --
-Z unstable-options --output-format json`, run in the `fuzz` job on its dated nightly.

Entry points:
- every public function, every public method of an inherent impl and every method of a public
  trait, with a parameter, a generic bound or a `where` predicate that holds bytes (`u8` inside a
  slice, an array or a generic argument: `&[u8]`, `Vec<u8>`, `Box<[u8]>`, `impl AsRef<[u8]>`) or
  a trait whose name ends in `Read` (`impl Read`, `R: Read`, `&mut dyn Read`, `BufRead`), named
  `module::function`, `module::method` (the module of the type) or `module::Trait::method`;
- every type with a public implementation of the trait `Wire`, by its name.

Each must be declared by a target, or listed with a reason in NOT_DECODERS (fuzz/src/lib.rs);
`fuzz-plan decoders` prints both. A declared name that is no entry point fails too.

Usage: check_fuzz_coverage.py --toolchain nightly-YYYY-MM-DD
       check_fuzz_coverage.py --rustdoc-json FILE --decoders FILE
Standard library only, Python 3.11 or later. Exits 1 and prints every violation when the check fails.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.exit(f"ci/check_fuzz_coverage.py needs Python 3.11 or later; this is {sys.version.split()[0]}")

import argparse
import json
import subprocess
from pathlib import Path

import check_workspace as cw
import fuzz as fz

CRATE = "vilicus-proto"
CRATE_ROOT = "vilicus_proto"
WIRE_TRAIT = "Wire"
# The format this script was written against (nightly-2026-10-01); another one fails loudly
# rather than being read wrongly.
FORMAT_VERSION = 61


def rustdoc_command(toolchain: str) -> list[str]:
    return [
        "cargo",
        f"+{toolchain}",
        "rustdoc",
        "--quiet",
        "--frozen",
        "--config",
        str(cw.VENDORED_CONFIG_FILE),
        "--package",
        CRATE,
        "--",
        "-Z",
        "unstable-options",
        "--output-format",
        "json",
    ]


def _holds_bytes(node: object, wrapped: bool = False) -> bool:
    """Whether a rustdoc type holds `u8` inside a slice, an array or generic arguments."""
    if isinstance(node, dict):
        if node.get("primitive") == "u8" and wrapped:
            return True
        return any(
            _holds_bytes(value, wrapped or key in ("slice", "array", "args", "angle_bracketed"))
            for key, value in node.items()
        )
    if isinstance(node, list):
        return any(_holds_bytes(item, wrapped) for item in node)
    return False


def _names_a_reader(node: object) -> bool:
    """Whether a rustdoc type or bound names a trait whose last path segment ends in `Read`."""
    if isinstance(node, dict):
        trait = node.get("trait")
        if isinstance(trait, dict) and str(trait.get("path", "")).split("::")[-1].endswith("Read"):
            return True
        path = node.get("path")
        if isinstance(path, str) and path.split("::")[-1].endswith("Read"):
            return True
        return any(_names_a_reader(value) for value in node.values())
    if isinstance(node, list):
        return any(_names_a_reader(item) for item in node)
    return False


def takes_bytes(function: dict) -> bool:
    """Whether a rustdoc function item takes bytes or a reader through its parameters, its
    generic parameters or its `where` predicates; its return type is not looked at."""
    inputs = [parameter_type for _, parameter_type in function["sig"]["inputs"]]
    looked_at = [inputs, function.get("generics", {})]
    return any(_holds_bytes(node) or _names_a_reader(node) for node in looked_at)


def _type_name(node: dict) -> str:
    if "resolved_path" in node:
        return node["resolved_path"]["path"].split("::")[-1]
    if "primitive" in node:
        return node["primitive"]
    raise ValueError(f"unexpected implementing type {node!r}")


def entry_points(doc: dict) -> tuple[set[str], set[str]]:
    """(byte-taking functions, Wire types) of a rustdoc JSON document."""
    if doc.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"rustdoc JSON format {doc.get('format_version')}, this script reads {FORMAT_VERSION}")
    index, paths = doc["index"], doc["paths"]

    def item(item_id: object) -> dict:
        return index[str(item_id)]

    def module_of(item_id: object) -> str:
        path = paths[str(item_id)]["path"]
        assert path[0] == CRATE_ROOT, path
        return "::".join(path[1:-1])

    def qualified(module: str, name: str) -> str:
        return f"{module}::{name}" if module else name

    functions: set[str] = set()
    wire_types: set[str] = set()
    for item_id, entry in index.items():
        if entry.get("crate_id") != 0:
            continue
        inner = entry["inner"]
        if "function" in inner and entry["visibility"] == "public" and item_id in paths:
            if takes_bytes(inner["function"]):
                functions.add(qualified(module_of(item_id), entry["name"]))
        elif "trait" in inner and entry["visibility"] == "public":
            for method_id in inner["trait"]["items"]:
                method = item(method_id)
                if "function" in method["inner"] and takes_bytes(method["inner"]["function"]):
                    functions.add(qualified(module_of(item_id), f"{entry['name']}::{method['name']}"))
            if entry["name"] == WIRE_TRAIT:
                for impl_id in inner["trait"]["implementations"]:
                    wire_types.add(_type_name(item(impl_id)["inner"]["impl"]["for"]))
        elif "impl" in inner and inner["impl"]["trait"] is None:
            implemented = inner["impl"]["for"].get("resolved_path", {})
            if str(implemented.get("id")) not in paths:
                continue
            for method_id in inner["impl"]["items"]:
                method = item(method_id)
                if (
                    "function" in method["inner"]
                    and method["visibility"] == "public"
                    and takes_bytes(method["inner"]["function"])
                ):
                    functions.add(qualified(module_of(implemented["id"]), method["name"]))
    return functions, wire_types


def check(functions: set[str], wire_types: set[str], decoders: dict) -> list[str]:
    declared = {name for names in decoders["targets"].values() for name in names}
    excused = decoders["not_decoders"]
    violations = [
        f"coverage: {name} of {CRATE} takes bytes or a reader and no fuzz target declares it"
        for name in sorted(functions - declared - excused.keys())
    ]
    violations += [
        f"coverage: {name} implements Wire and no fuzz target declares it" for name in sorted(wire_types - declared)
    ]
    violations += [
        f"coverage: a fuzz target declares {name}, which is no public decoder of {CRATE}"
        for name in sorted(declared - functions - wire_types)
    ]
    violations += [
        f"coverage: NOT_DECODERS lists {name}, which takes no bytes or reader" for name in sorted(excused.keys() - functions)
    ]
    violations += [f"coverage: NOT_DECODERS gives {name} no reason" for name, reason in sorted(excused.items()) if not reason.strip()]
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--toolchain", help="the dated nightly that builds the rustdoc JSON")
    parser.add_argument("--rustdoc-json", type=Path, help="read this rustdoc JSON instead of building it")
    parser.add_argument("--decoders", type=Path, help="read this `fuzz-plan decoders` output instead of running it")
    args = parser.parse_args(argv)
    if args.toolchain is None and (args.rustdoc_json is None or args.decoders is None):
        parser.error("give --toolchain, or both --rustdoc-json and --decoders")
    if args.toolchain is not None and not fz.DATED_NIGHTLY.match(args.toolchain):
        parser.error(f"--toolchain {args.toolchain!r} is not a dated nightly (nightly-YYYY-MM-DD)")

    if args.rustdoc_json is None:
        subprocess.run(rustdoc_command(args.toolchain), cwd=cw.REPO_ROOT, check=True)
        doc_path = cw.REPO_ROOT / "target" / "doc" / f"{CRATE_ROOT}.json"
    else:
        doc_path = args.rustdoc_json
    if args.decoders is None:
        decoders_text = subprocess.run(
            fz.plan_command(args.toolchain, "decoders"), cwd=cw.REPO_ROOT, check=True, stdout=subprocess.PIPE, text=True
        ).stdout
    else:
        decoders_text = args.decoders.read_text(encoding="utf-8")

    functions, wire_types = entry_points(json.loads(doc_path.read_text(encoding="utf-8")))
    violations = check(functions, wire_types, json.loads(decoders_text))
    for violation in violations:
        print(violation)
    if violations:
        return 1
    print(f"fuzz coverage passed: {len(functions)} byte-taking functions and {len(wire_types)} Wire types of {CRATE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
