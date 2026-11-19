#!/usr/bin/env python3
"""Verify the 1FTunnel 0.7.3 dossier findings (analysis/com.oneftunnel.app/129).

Usage (from the repo root):
    python analysis/com.oneftunnel.app/129/tools/verify_073.py --file <path.1ftnl>
    python analysis/com.oneftunnel.app/129/tools/verify_073.py --file <path.1ftnl> --so071 <lib071.so> --so073 <lib073.so>

The password is NEVER read from a file or argument: it comes only from the
ONEFT_PW environment variable, and only for the positive check. The script
prints structure and error codes only, never profile values.

Checks:
  1. Envelope structure of the given .1ftnl (version, keySlot, minBuild,
     lockMode, configType, AAD length, ciphertext length).
  2. Positive: 1FTunnel.py (repo decoder, CFG1 v1-v6) opens the file with
     ONEFT_PW (structure only).
  3. Worker path: file_decoder.py -> codec.py (CFG1 v1-v6 after the fix)
     opens a v6 text file with the correct password (full JSON,
     authenticated, isPartial False).
  4. Optional: the native KDF labels in both .so files are the same set
     (v1/v2 only, no v3).
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
DECODER_DIR = REPO / "decoders" / "Python" / "apps" / "OneFTunnel"


def _load(name: str):
    # file_decoder.py imports `codec` as a top-level module when loaded
    # standalone, so its directory must be importable.
    sys.path.insert(0, str(DECODER_DIR))
    spec = importlib.util.spec_from_file_location(name, DECODER_DIR / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_envelope(text: str) -> dict:
    body = text.strip()[len("1FTnl."):]
    raw = b"1FT1" + base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    aad_len = struct.unpack(">I", raw[36:40])[0]
    ct_len = struct.unpack(">I", raw[40:44])[0]
    aad = raw[44:44 + aad_len]
    o = 1
    plen = struct.unpack(">H", aad[o:o + 2])[0]
    o += 2 + plen
    clen = struct.unpack(">H", aad[o:o + 2])[0]
    o += 2 + clen
    out = {
        "envelopeVersion": raw[4],
        "algo": raw[5],
        "kdf": raw[6],
        "aadLen": aad_len,
        "ciphertextLen": ct_len,
        "totalBytes": len(raw),
        "configVersion": struct.unpack(">I", aad[o:o + 4])[0],
    }
    o += 4
    out["keySlot"] = struct.unpack(">I", aad[o:o + 4])[0]
    o += 4
    out["minimumAppBuild"] = struct.unpack(">q", aad[o:o + 8])[0]
    o += 8
    out["createdAt"] = struct.unpack(">q", aad[o:o + 8])[0]
    o += 8
    out["expiredAt"] = struct.unpack(">q", aad[o:o + 8])[0]
    o += 8
    out["configTypeIndex"] = aad[o]
    o += 1
    out["lockMode"] = aad[o]
    o += 1
    out["blockRoot"] = aad[o]
    return out


def so_labels(path: Path) -> set:
    out = subprocess.run(["strings", "-a", str(path)],
                         capture_output=True, text=True, check=True).stdout
    return {line for line in out.splitlines()
            if line.startswith("1FT1 ") or line.startswith("1FT1 HKDF")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, help=".1ftnl text file")
    parser.add_argument("--so071", help="0.7.1 liboneftunnel-security.so")
    parser.add_argument("--so073", help="0.7.3 liboneftunnel-security.so")
    args = parser.parse_args()
    checks = []

    def check(name: str, ok: bool) -> None:
        checks.append(ok)
        print(("OK   " if ok else "FAIL ") + name)

    text = Path(args.file).read_text(encoding="utf-8")
    env = parse_envelope(text)
    print("envelope:", env)
    check("envelope is 1FT1 v3, algo 1, kdf 1",
          env["envelopeVersion"] == 3 and env["algo"] == 1 and env["kdf"] == 1)
    check("AAD + ciphertext lengths consume the file exactly",
          44 + env["aadLen"] + env["ciphertextLen"] == env["totalBytes"])

    password = os.environ.get("ONEFT_PW")
    ft = _load("1FTunnel")
    if password:
        result = ft.decode(text, password=password)
        meta = result["metadata"]
        cfg = result["config"]
        print("1FTunnel.py:", {
            "format": result["format"],
            "authenticated": meta["authenticated"],
            "configType": meta["configType"],
            "lockMode": meta["lockMode"],
            "keySlot": meta["keySlot"],
            "minimumAppBuild": meta["minimumAppBuild"],
            "payloadVersion": cfg["payloadVersion"],
            "sections": {k: (v is not None) for k, v in cfg.items()
                         if k in ("ssh", "inject", "dns", "xray", "slowDns")},
            "injectMode": (cfg["inject"] or {}).get("mode"),
        })
        check("1FTunnel.py opens the file (GCM authenticated)",
              meta["authenticated"] is True and result["isPartial"] is False)
    else:
        print("ONEFT_PW unset: positive check skipped")
        try:
            ft.decode(text)
            check("no password -> PASSWORD_REQUIRED", False)
        except ft.DecodeError as error:
            check("no password -> PASSWORD_REQUIRED",
                  error.code == "PASSWORD_REQUIRED")

    # Worker path: file_decoder.py -> codec.py (CFG1 v1-v6 after the fix).
    fd = _load("file_decoder")
    try:
        worker = json.loads(fd.run(text.encode("utf-8"), password=password))
        print("file_decoder path:", {
            "format": worker["format"],
            "authenticated": worker["metadata"]["authenticated"],
            "payloadVersion": worker["config"]["payloadVersion"],
            "injectMode": (worker["config"]["inject"] or {}).get("mode"),
        })
        check("worker path opens v6 text (codec.py fix)",
              worker["metadata"]["authenticated"] is True
              and worker["isPartial"] is False
              and worker["config"]["payloadVersion"] == 6)
    except Exception as error:
        code = getattr(error, "code", type(error).__name__)
        print("file_decoder path:", code)
        check("worker path opens v6 text (codec.py fix)", False)

    if args.so071 and args.so073:
        labels071 = so_labels(Path(args.so071))
        labels073 = so_labels(Path(args.so073))
        print("KDF labels 0.7.1:", sorted(labels071))
        print("KDF labels 0.7.3:", sorted(labels073))
        check("native KDF labels identical (v1/v2 only)",
              labels071 == labels073 and
              not any("v3" in label for label in labels073))

    print("VERIFY:", "ALL OK" if all(checks) else "FAILURES PRESENT")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
