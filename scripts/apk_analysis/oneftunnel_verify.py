#!/usr/bin/env python3
"""Compare complete .1ftnl JSON with JDK and optionally original ARM64 KDF.

No decoded values/keys are printed or written. --input accepts a private profile;
--credentials reads a JSON password object from stdin. Keep real inputs out of Git.
"""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.OneFTunnel.codec import decode, derive_key, unwrap


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path)
    p.add_argument("--library", type=Path)
    p.add_argument("--credentials", action="store_true")
    p.add_argument("--worker", action="store_true")
    args = p.parse_args()
    password = None
    if args.credentials:
        obj = json.loads(sys.stdin.buffer.read(32769))
        if not isinstance(obj, dict) or set(obj) != {"password"} or not isinstance(obj["password"], str):
            p.error("stdin must contain a password object")
        password = obj["password"]
    cases = [(x["wire"].encode(), x["password"] or None, x["expected"])
             for x in json.loads((ROOT / "tests/golden/oneftunnel_vectors.json").read_text())]
    if args.input:
        cases.append((args.input.read_bytes(), password, None))
    lines, actual = [], []
    native_count = 0
    for wire, password, expected in cases:
        result = decode(wire, password=password)
        if expected is not None and result != expected:
            raise ValueError("Complete golden JSON mismatch")
        actual.append(result)
        raw = unwrap(wire)
        lines.append(base64.b64encode(raw).decode() + "\t" + base64.b64encode((password or "").encode()).decode())
        if args.library:
            from oneftunnel_native_oracle import Native
            n = struct.unpack_from(">I", raw, 36)[0]
            aad = raw[44:44+n]
            pw = password if result["metadata"]["lockMode"] == 2 else None
            for slot in (0, 1):
                key = Native(args.library).kdf(raw[4], slot, raw[8:24], aad,
                                              (pw or "").encode("utf-16-be"))
                if key != derive_key(raw[4], raw[8:24], aad, pw):
                    raise ValueError("Native KDF mismatch")
                native_count += 1
        if args.worker:
            from cloud.workers.python.engine import decode_file, decode_text
            creds = {"password": password} if password else None
            for output in (decode_file("1ftnl", wire, credentials=creds),
                           decode_text(wire.decode(), credentials=creds)):
                if output["structuredJson"] != result or output["isPartial"]:
                    raise ValueError("Complete isolated worker mismatch")
    r = subprocess.run(["java", "-XX:-UsePerfData", str(ROOT / "tests/golden/oneftunnel_oracle.java"), "verify"],
                       input="\n".join(lines)+"\n", text=True, capture_output=True, timeout=45)
    if r.returncode:
        raise ValueError("JDK reference failed")
    references = [json.loads(line) for line in r.stdout.splitlines()]
    if references != actual:
        raise ValueError("Complete JDK JSON mismatch")
    print(json.dumps({"completeJdkJsonMatches": len(actual), "nativeKdfMatches": native_count,
                      "isolatedFileAndTextWorker": args.worker, "privateInput": bool(args.input)}))


if __name__ == "__main__":
    main()
