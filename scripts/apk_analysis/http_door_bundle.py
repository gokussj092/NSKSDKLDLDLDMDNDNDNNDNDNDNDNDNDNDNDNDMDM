#!/usr/bin/env python3
"""Bundle HTTP Door and its canonical Java Properties parser for Termux."""
from __future__ import annotations
import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / "decoders/Python/apps/CREEB_INJECTOR/codec.py"
CODEC = ROOT / "decoders/Python/apps/HTTP_Door/codec.py"


def build() -> str:
    source = SHARED.read_text("utf-8")
    names = {"DecodeError", "_validate", "decode_properties", "render"}
    definitions = [ast.get_source_segment(source, node) for node in ast.parse(source).body
                   if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    if len(definitions) != len(names):
        raise ValueError("Canonical parser definitions changed")
    constants = [ast.get_source_segment(source, node) for node in ast.parse(source).body
                 if isinstance(node, ast.Assign) and len(node.targets) == 1
                 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {"MAX_BYTES", "MAX_DEPTH"}]
    if len(constants) != 2:
        raise ValueError("Canonical parser limits changed")
    shared = "import json\nimport math\nimport re\nimport xml.etree.ElementTree as ET\n" + "\n".join(constants) + "\n\n" + "\n\n".join(definitions)
    codec = CODEC.read_text("utf-8")
    before, rest = codec.split("# BEGIN_SHARED_IMPORTS\n")
    _, after = rest.split("# END_SHARED_IMPORTS")
    return before + "# Embedded canonical CREEB Java Properties parser.\n" + shared + "\n" + after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(build())


if __name__ == "__main__":
    main()
