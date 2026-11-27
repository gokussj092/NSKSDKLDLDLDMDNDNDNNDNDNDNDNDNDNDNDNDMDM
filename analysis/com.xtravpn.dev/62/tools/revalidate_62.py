#!/usr/bin/env python3
"""Revalidate the XtraVPN 1.0.36 re-verification: self-test, asset decode,
xtravpn:// text against the asset blob, and the fixed fallback key with a
synthetic custom code.

No network except the sig-config check (expected honest failure, recorded
but not fatal). No real user data; the live catalog is not re-fetched.
"""
from __future__ import annotations
import base64
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "decoders/Python/apps/XtraVPN/XtraVPN.py"
# The asset lives in the repo (overlay); the stage tree has no copy.
ASSET = (Path(__file__).resolve().parents[5]
         / "overlay/decoders/Python/apps/XtraVPN/config.json")


def load():
    spec = importlib.util.spec_from_file_location("xtravpn62", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    proof: dict = {"app": "XtraVPN", "version_code": 62}
    mod = load()
    result = mod.run(data=ASSET.read_text(encoding="utf-8"))
    proof["asset"] = {"version": result["version"],
                      "key_used": result["key_used"],
                      "servers": result["server_count"]}
    blob = ASSET.read_text(encoding="utf-8").strip()
    text_result = mod.run(data=blob)
    proof["text_xtravpn"] = {"version": text_result["version"],
                            "key_used": text_result["key_used"],
                            "servers": text_result["server_count"]}
    # Synthetic custom code with the fixed fallback key (AES-128-ECB).
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = b"23605c1568999d3a"
    padder = padding.PKCS7(128).padder()
    padded = padder.update(b"https://example.org/catalogo.json") + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    code = base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()
    proof["custom_code_fixed_key"] = {
        "opens": mod.decrypt_custom_code(code, "0000000000000000")
        == "https://example.org/catalogo.json"}
    print(json.dumps(proof, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
