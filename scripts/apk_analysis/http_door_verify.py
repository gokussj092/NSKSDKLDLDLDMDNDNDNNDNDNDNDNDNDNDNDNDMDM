#!/usr/bin/env python3
"""Compare a private .kyz completely with JDK and optionally the Cloud worker."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.HTTP_Door import codec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    try:
        with args.file.open("rb") as stream:
            data = stream.read(codec.MAX_BYTES + 1)
        actual = codec.decode(data)
        result = subprocess.run(["java", str(ROOT / "tests/golden/http_door_oracle.java")],
            input="open\t" + base64.b64encode(data).decode() + "\n", text=True,
            capture_output=True, timeout=30)
        if result.returncode or len(result.stdout.splitlines()) != 1:
            raise ValueError("JDK rejected the input")
        xml, props = result.stdout.strip().split("\t")
        if base64.b64decode(xml) != actual["raw_xml"].encode("utf-8"):
            raise ValueError("Raw XML mismatch")
        if json.loads(base64.b64decode(props)) != actual["properties"]:
            raise ValueError("Properties mismatch")
        if args.worker:
            from cloud.workers.python.engine import decode_file
            worker = decode_file("kyz", data)
            if (worker.get("isPartial") is not False or worker["structuredJson"] != actual or
                    json.loads(worker["rawText"]) != actual):
                raise ValueError("Whole worker document mismatch")
        print(json.dumps({"jdkCompleteMatch": True, "workerCompleteMatch": bool(args.worker),
                          "entries": len(actual["entries"]), "properties": len(actual["properties"])}))
    except (OSError, ValueError, subprocess.SubprocessError, KeyError):
        print("No se pudo verificar el .kyz completo; no se muestran datos del perfil.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
