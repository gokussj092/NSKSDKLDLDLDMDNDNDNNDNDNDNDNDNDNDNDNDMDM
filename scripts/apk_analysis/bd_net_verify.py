#!/usr/bin/env python3
"""Whole BD NET catalogs/profiles vs independent JDK and isolated worker.

Only recurrences/counts are printed. Private documents never enter Git/logs.
"""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.BD_NET_VPN import codec

# Recovered independently from nm/S00 and observed catalog fields.
FIELDS = {"payload", "host", "sausage", "server_host", "HopPayload",
          "DualConnectPayload", "SSLPayload", "CustomCert"}


def java_batch(classpath, lines):
    done = subprocess.run(["java", str(Path(classpath)/"bd_net_oracle.java")],
                          input="\n".join(lines)+"\n", text=True, capture_output=True, timeout=60, check=True)
    result = []
    for line in done.stdout.splitlines():
        parts = line.split("\t")
        result.append((base64.b64decode(parts[1]).decode("utf-8"),
                       parts[2] if parts[0] == "B" else None))
    if len(result) != len(lines):
        raise ValueError("Incomplete JDK batch")
    return result


def independent(classpath, data, profile=False):
    mode = "X" if profile else "C"
    opened, binary = java_batch(classpath, [mode+"\t"+base64.b64encode(data).decode()])[0]
    if binary is not None:
        raise ValueError("Binary outer JSON")
    obj = json.loads(opened)
    found = {}
    def collect(value, key=""):
        if isinstance(value, dict):
            for name, item in value.items(): collect(item, name)
        elif isinstance(value, list):
            for item in value: collect(item)
        elif key in FIELDS and isinstance(value, str) and value and len(value)%2 == 0 and re.fullmatch("[0-9a-fA-F]+", value):
            found[value] = None
    collect(obj)
    if found:
        lines = ["X\t"+base64.b64encode(value.encode()).decode() for value in found]
        found.update(zip(found, java_batch(classpath, lines)))
    recovered = []
    def walk(value, path="", key=""):
        if isinstance(value, dict):
            return {name: walk(item, path+"/"+name.replace("~", "~0").replace("/", "~1"), name) for name, item in value.items()}
        if isinstance(value, list):
            return [walk(item, path+"/"+str(index)) for index, item in enumerate(value)]
        if key in FIELDS and isinstance(value, str) and value in found:
            text, raw = found[value]
            if raw is not None:
                recovered.append({"path": path, "reason": "NON_UTF8_AFTER_NUL", "encoding": "base64",
                                  "decodedBytesBase64": raw, "sourceHex": value})
            return text
        return value
    result = walk(obj)
    if recovered: result["_spdecodeBinaryFields"] = recovered
    return result, len(found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="store_true")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="spdecode-bd-jdk-") as tmp:
        # Source launcher supports hosts that expose java but not a javac binary.
        # Inline the existing reference class unchanged except its import lines.
        helper = (ROOT/"tests/golden/apna_oracle.java").read_text()
        helper = re.sub(r"^import[^\n]+;\n", "", helper, flags=re.MULTILINE)
        (Path(tmp)/"bd_net_oracle.java").write_text((ROOT/"tests/golden/bd_net_oracle.java").read_text()+"\n"+helper)
        for path in args.paths:
            data = path.read_bytes(); expected, count = independent(tmp, data, args.file)
            opened = codec.decode_profile_bytes(data) if args.file else codec.decode_json_bytes(data)
            assert json.loads(opened) == expected, "Complete Python/JDK document differs"
            if args.worker:
                from cloud.workers.python.engine import decode_file, decode_text, decode_provider_catalog
                result = decode_file("bdnet", data) if args.file else decode_provider_catalog("bd-net-vpn", data)
                assert result["structuredJson"] == expected and not result["isPartial"], "Worker differs"
                if args.file:
                    text = data.decode().strip()
                    if not text.lower().startswith("bdnet://"): text = "bdnet://"+text
                    assert decode_text(text)["structuredJson"] == expected, "Text worker differs"
            summary = {"profile": True} if args.file else codec.summary(opened)
            print(json.dumps({**summary, "jdkWholeDocumentEqual": True, "worker": args.worker,
                              "innerFields": count, "binaryFieldsPreserved": len(expected.get("_spdecodeBinaryFields", []))}))


if __name__ == "__main__":
    main()
