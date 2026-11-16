"""Compare an explicitly supplied HC reader with private samples, without logging secrets.

The external script must be reviewed before loading it. Inputs and decrypted
outputs stay outside Git; only counts, hashes, format names and errors are public.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shape(value):
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return {"type": "list", "count": len(value),
                "items": [shape(item) for item in value[:3]]}
    if isinstance(value, str):
        return {"type": "str", "length": len(value)}
    return {"type": type(value).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", type=Path)
    parser.add_argument("samples", type=Path)
    parser.add_argument("private_output", type=Path)
    args = parser.parse_args()
    auth = json.load(sys.stdin)
    if set(auth) - {"password", "hwid"}:
        raise ValueError("unexpected auth members")
    spec = importlib.util.spec_from_file_location("supplied_hc_reader", args.script)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    args.private_output.mkdir(parents=True, exist_ok=True, mode=0o700)
    results = []
    for path in sorted(args.samples.glob("*.hc")):
        raw = path.read_bytes()
        row = {"sample": path.name, "sha256": digest(raw), "size": len(raw),
               "outer_authenticated": False, "attempts": []}
        try:
            env = open_envelope(raw)
            row["outer_authenticated"] = True
            row["format"] = {key: env.get(key) for key in ("a", "b", "d", "e", "h", "k", "l", "m", "n")}
            row["envelope_shape"] = shape(env)
            if env.get("h") and not (type(env.get("l")) is int and 1 <= env["l"] <= 10
                                     and type(env.get("m")) is int and 8192 <= env["m"] <= 256 * 1024 * 1024):
                raise ValueError("unsafe/unknown password KDF limits")
        except Exception as exc:
            row["outer_error"] = str(exc)
            results.append(row)
            continue
        for method in ("decrypt_hc_v79", "decrypt_hc_v4"):
            try:
                result = getattr(reader, method)(raw, **auth)
                if not isinstance(result, dict) or not isinstance(result.get("config"), list):
                    raise ValueError("reader did not return its full configuration structure")
                encoded = json.dumps(result, ensure_ascii=False, indent=2).encode()
                output = args.private_output / (path.stem + ".json")
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(encoded)
                row["attempts"].append({"method": method, "returned_json": True,
                                        "profile_count": len(result["config"]),
                                        "other_section_count": len(result.get("other_sections", [])),
                                        "result_sha256": digest(encoded),
                                        "result_shape": shape(result)})
                break
            except Exception as exc:
                row["attempts"].append({"method": method, "returned_json": False,
                                        "error_type": type(exc).__name__, "error": str(exc)})
        results.append(row)
    print(json.dumps({"script_sha256": digest(args.script.read_bytes()), "samples": results},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
