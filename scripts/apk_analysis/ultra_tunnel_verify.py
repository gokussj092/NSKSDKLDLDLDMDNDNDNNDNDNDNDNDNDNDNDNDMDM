#!/usr/bin/env python3
"""Compare entire private Ultra catalog JSON with independent libsodium/JCA."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.golden.ultra_tunnel_reference import catalog_reference


def verify(path, expected=None):
    data = path.read_bytes()
    doc, counts = catalog_reference(data)
    if expected is not None and doc != json.loads(expected.read_text(encoding="utf-8")):
        raise ValueError("Full Ultra JSON differs from independent libsodium/JCA")
    return doc, {"source": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "version": doc["Version"], "servers": len(doc["Servers"]), "networks": len(doc["Networks"]),
                 **counts, "fullIndependentEqual": expected is not None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--expected", type=Path)
    args = parser.parse_args()
    _, report = verify(args.catalog, args.expected)
    print(json.dumps(report), flush=True)
