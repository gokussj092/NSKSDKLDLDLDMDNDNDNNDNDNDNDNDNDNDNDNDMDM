#!/usr/bin/env python3
"""Bundle MTM with the canonical HX XXTEA implementation, no runtime imports."""
import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def build() -> str:
    source = (ROOT / "decoders/Python/apps/HX_Tunnel_VPN/HX_Tunnel_VPN.py").read_text("utf-8")
    names = {"DecodeError", "_text", "_base64", "_unique", "_nonfinite", "_validate",
             "_json", "_mx", "decrypt_catalog_bytes", "_catalog_json"}
    constants = {"MAX_BYTES", "MAX_DEPTH", "MAX_NODES", "MASK", "DELTA", "LIST_FIELDS"}
    definitions, values = [], []
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            definitions.append(ast.get_source_segment(source, node))
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants):
            values.append(ast.get_source_segment(source, node))
    if len(definitions) != len(names) or len(values) != len(constants):
        raise ValueError("Canonical HX definitions changed")
    shared = "import base64\nimport binascii\nimport math\nimport re\nimport struct\n"
    shared += "\n".join(values) + "\n\n" + "\n\n".join(definitions)
    codec = (ROOT / "decoders/Python/apps/MTM_Tunnel_Lite/codec.py").read_text("utf-8")
    before, rest = codec.split("# BEGIN_SHARED_IMPORTS\n")
    _, after = rest.split("# END_SHARED_IMPORTS")
    return before + "# Embedded canonical HX XXTEA implementation.\n" + shared + "\n" + after


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(build())
