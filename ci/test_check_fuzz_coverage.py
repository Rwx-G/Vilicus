"""Tests for ci/check_fuzz_coverage.py, over synthetic rustdoc JSON documents in the shape of
format 61 (nightly-2026-10-01). The `fuzz` job runs the script on the real document.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import check_fuzz_coverage as cc

U8 = {"primitive": "u8"}


def ref(inner: dict, mutable: bool = False) -> dict:
    return {"borrowed_ref": {"lifetime": None, "is_mutable": mutable, "type": inner}}


def path(name: str, *args: dict) -> dict:
    angle = {"angle_bracketed": {"args": [{"type": arg} for arg in args], "constraints": []}} if args else None
    return {"resolved_path": {"path": name, "id": 900, "args": angle}}


def bound(trait: str, *args: dict) -> dict:
    angle = {"angle_bracketed": {"args": [{"type": arg} for arg in args], "constraints": []}} if args else None
    return {"trait_bound": {"trait": {"path": trait, "id": 901, "args": angle}, "generic_params": [], "modifier": "none"}}


def function(inputs: list[dict], output: dict | None = None, generics: dict | None = None) -> dict:
    return {
        "function": {
            "sig": {"inputs": [[f"p{i}", t] for i, t in enumerate(inputs)], "output": output, "is_c_variadic": False},
            "generics": generics or {"params": [], "where_predicates": []},
        }
    }


class Doc:
    """A synthetic rustdoc JSON document of the crate vilicus_proto."""

    def __init__(self) -> None:
        self.index: dict[str, dict] = {}
        self.paths: dict[str, dict] = {}
        self.next_id = 1

    def add(self, name: str | None, inner: dict, visibility: str = "public", path: list[str] | None = None, crate_id: int = 0) -> int:
        item_id = self.next_id
        self.next_id += 1
        self.index[str(item_id)] = {"id": item_id, "crate_id": crate_id, "name": name, "visibility": visibility, "inner": inner}
        if path is not None:
            self.paths[str(item_id)] = {"crate_id": crate_id, "path": ["vilicus_proto", *path], "kind": "x"}
        return item_id

    def free(self, module: str, name: str, inner: dict, visibility: str = "public") -> int:
        return self.add(name, inner, visibility, [module, name] if visibility == "public" else None)

    def document(self) -> dict:
        return {"format_version": cc.FORMAT_VERSION, "index": self.index, "paths": self.paths}


class EntryPointTest(unittest.TestCase):
    def test_every_way_to_take_bytes_or_a_reader_is_an_entry_point(self) -> None:
        doc = Doc()
        cases = {
            "slice": function([ref({"slice": U8})]),
            "array": function([ref({"array": {"type": U8, "len": "4"}})]),
            "vec": function([path("Vec", U8)]),
            "boxed": function([path("Box", {"slice": U8})]),
            "as_ref": function([{"impl_trait": [bound("AsRef", {"slice": U8})]}]),
            "impl_read": function([ref({"impl_trait": [bound("Read")]}, True)]),
            "dyn_read": function([ref({"dyn_trait": {"traits": [{"trait": {"path": "std::io::Read", "id": 2, "args": None}}]}}, True)]),
            "buf_read": function([{"impl_trait": [bound("BufRead")]}]),
            "generic_read": function(
                [ref({"generic": "R"}, True)],
                generics={"params": [{"name": "R", "kind": {"type": {"bounds": [bound("Read")]}}}], "where_predicates": []},
            ),
            "where_read": function(
                [{"generic": "R"}],
                generics={"params": [], "where_predicates": [{"bound_predicate": {"type": {"generic": "R"}, "bounds": [bound("io::Read")]}}]},
            ),
        }
        for name, inner in cases.items():
            doc.free("frame", name, inner)
        functions, _ = cc.entry_points(doc.document())
        self.assertEqual(functions, {f"frame::{name}" for name in cases})

    def test_returning_bytes_a_bare_byte_or_a_private_function_is_no_entry_point(self) -> None:
        doc = Doc()
        doc.free("canonical", "as_bytes", function([ref({"generic": "Self"})], output=ref({"slice": U8})))
        doc.free("frame", "tag", function([U8]))
        doc.free("frame", "hidden", function([ref({"slice": U8})]), visibility="crate")
        doc.add("external", function([ref({"slice": U8})]), crate_id=1)
        functions, _ = cc.entry_points(doc.document())
        self.assertEqual(functions, set())

    def test_methods_are_named_by_the_module_of_their_type_and_trait_methods_by_their_trait(self) -> None:
        doc = Doc()
        method = doc.add("from_stored", function([path("Vec", U8)]))
        private_method = doc.add("helper", function([ref({"slice": U8})]), visibility="crate")
        struct = doc.add("CanonicalBytes", {"struct": {}}, path=["canonical", "CanonicalBytes"])
        doc.add(None, {"impl": {"trait": None, "for": {"resolved_path": {"path": "CanonicalBytes", "id": struct}}, "items": [method, private_method]}})
        provided = doc.add("from_bytes", function([ref({"slice": U8})]), visibility="default")
        doc.add("Wire", {"trait": {"items": [provided], "implementations": []}}, path=["wire", "Wire"])
        functions, _ = cc.entry_points(doc.document())
        self.assertEqual(functions, {"canonical::from_stored", "wire::Wire::from_bytes"})

    def test_every_implementation_of_wire_names_its_type(self) -> None:
        doc = Doc()
        impls = [
            doc.add(None, {"impl": {"trait": {"path": "Wire"}, "for": target, "items": []}})
            for target in (path("Hello"), path("vilicus_types::Source"), {"primitive": "bool"}, path("Vec", {"generic": "T"}))
        ]
        doc.add("Wire", {"trait": {"items": [], "implementations": impls}}, path=["wire", "Wire"])
        _, wire_types = cc.entry_points(doc.document())
        self.assertEqual(wire_types, {"Hello", "Source", "bool", "Vec"})

    def test_another_format_version_is_refused(self) -> None:
        document = Doc().document()
        document["format_version"] = cc.FORMAT_VERSION + 1
        with self.assertRaises(ValueError):
            cc.entry_points(document)


class CheckTest(unittest.TestCase):
    DECODERS = {"targets": {"frame": ["frame::read_frame", "Hello"]}, "not_decoders": {"frame::write_frame": "writes"}}

    def test_covered_entry_points_pass(self) -> None:
        self.assertEqual(cc.check({"frame::read_frame", "frame::write_frame"}, {"Hello"}, self.DECODERS), [])

    def test_each_gap_fails_naming_it(self) -> None:
        violations = cc.check({"frame::read_frame", "frame::read_any"}, {"Hello", "Extra"}, self.DECODERS)
        self.assertEqual(len(violations), 3, violations)
        self.assertIn("frame::read_any of vilicus-proto takes bytes", violations[0])
        self.assertIn("Extra implements Wire", violations[1])
        self.assertIn("NOT_DECODERS lists frame::write_frame, which takes no bytes", violations[2])

    def test_a_stale_declaration_or_an_empty_reason_fails(self) -> None:
        decoders = {"targets": {"frame": ["frame::gone"]}, "not_decoders": {"frame::write_frame": " "}}
        violations = "\n".join(cc.check({"frame::write_frame"}, set(), decoders))
        self.assertIn("declares frame::gone, which is no public decoder", violations)
        self.assertIn("NOT_DECODERS gives frame::write_frame no reason", violations)

    def test_the_script_reads_files_and_exits_1_on_a_gap(self) -> None:
        doc = Doc()
        doc.free("frame", "read_frame", function([ref({"slice": U8})]))
        with tempfile.TemporaryDirectory() as temp:
            doc_path, decoders_path = Path(temp) / "doc.json", Path(temp) / "decoders.json"
            doc_path.write_text(json.dumps(doc.document()), encoding="utf-8")
            for decoders, status in (({"targets": {"t": ["frame::read_frame"]}, "not_decoders": {}}, 0), ({"targets": {}, "not_decoders": {}}, 1)):
                with self.subTest(status=status):
                    decoders_path.write_text(json.dumps(decoders), encoding="utf-8")
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(cc.main(["--rustdoc-json", str(doc_path), "--decoders", str(decoders_path)]), status)

    def test_the_rustdoc_command_is_frozen_vendored_and_on_the_nightly(self) -> None:
        command = cc.rustdoc_command("nightly-2026-10-01")
        self.assertEqual(command[:3], ["cargo", "+nightly-2026-10-01", "rustdoc"])
        self.assertIn("--frozen", command)
        self.assertEqual(command[command.index("--config") + 1], "ci/cargo-vendored.toml")
        self.assertEqual(command[-4:], ["-Z", "unstable-options", "--output-format", "json"])


if __name__ == "__main__":
    unittest.main()
