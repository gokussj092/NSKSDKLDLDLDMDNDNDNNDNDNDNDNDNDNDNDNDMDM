#!/usr/bin/env python3
"""V2Box .v2box v2 — AAD/key hypothesis battery (dossier tool).

Usage:
    python3 verify_aad_candidates.py <archivo.v2box>

Tries the fixed 6.2.3 key and derived keys against AES-256-GCM with
several AAD candidates and prints ONLY OPEN/fail per hypothesis plus
envelope structure (magic, version, kdf, field sizes). It NEVER prints
decrypted plaintext, keys, or any file value.

Background (2026-11-19): the 6.2.3 decoder used the raw header JSON
bytes as GCM AAD (static DEX reading, never verified against a real
file) and every real v2 file failed with TAG_MISMATCH. The real file
opens with AAD = the Base64 header string exactly as it appears in
the envelope — the same AAD the legacy 6.1.2 decoder already used
(decoders/Python/v2box_export.py).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "v2box_archivos",
    ROOT / "decoders/Python/apps/V2Box/V2Box_archivos.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("Uso: verify_aad_candidates.py <archivo.v2box>",
              file=sys.stderr)
        return 2
    raw = Path(argv[0]).read_bytes()
    env = json.loads(raw.decode("utf-8"))
    header_b64 = env["header"]
    header_bytes = base64.b64decode(header_b64)
    header = json.loads(header_bytes)
    nonce = base64.b64decode(env["nonce"])
    tag = base64.b64decode(env["tag"])
    ct = base64.b64decode(env["ciphertext"])
    key = MOD.V2BOX_KEY
    print("envelope: magic=%s version=%s kdf=%s ct=%dB nonce=%dB tag=%dB"
          % (env.get("magic"), env.get("version"), header.get("kdf"),
             len(ct), len(nonce), len(tag)))
    print("header keys: %s" % sorted(header.keys()))

    def try_dec(candidate_key, aad, label):
        try:
            pt = MOD._aes_gcm_decrypt(candidate_key, nonce, ct, tag,
                                      aad=aad)
            json.loads(pt.decode("utf-8"))
            print("OPEN  %s  len=%dB json=True" % (label, len(pt)))
            return True
        except Exception:
            print("fail  %s" % label)
            return False

    try_dec(key, header_bytes, "key=fixed aad=header-raw-bytes")
    try_dec(key, b"", "key=fixed aad=empty")
    try_dec(key, header_b64.encode("ascii"), "key=fixed aad=header-b64-string")
    try_dec(key, json.dumps(header, sort_keys=True,
                            separators=(",", ":")).encode(),
            "key=fixed aad=header-json-sorted-compact")
    try_dec(key, json.dumps(header, separators=(",", ":")).encode(),
            "key=fixed aad=header-json-compact")
    try_dec(hashlib.sha256(key).digest(), header_bytes,
            "key=SHA256(fixed) aad=header-raw-bytes")
    try_dec(MOD._V2BOX_RAW_KEY, header_bytes,
            "key=raw-xor-bytes-as-is aad=header-raw-bytes")
    for info in (b"v2box/2", b"v2box/2 recipient"):
        prk = hmac.new(b"\x00" * 32, key, hashlib.sha256).digest()
        derived = hmac.new(prk, info + b"\x01",
                           hashlib.sha256).digest()
        try_dec(derived, header_bytes,
                "key=HKDF(fixed,info=%r) aad=header-raw-bytes" % info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
