#!/usr/bin/env python3
"""FMT VPN — synthetic round-trip verifier for this dossier.

Stdlib only (+ tools/crypto_pure.py in this directory). No network, no
secrets: every key below is a SYNTHETIC test key generated in this file.
It proves the implemented layers round-trip; it does NOT prove compatibility
with a real app file (that needs the operational script and a real sample).
Run: python3 tools/verify.py
"""
import base64
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_pure import (  # noqa: E402
    aes_cbc_decrypt, aes_cbc_encrypt, aes_gcm_decrypt, aes_gcm_encrypt,
    threefish256_decrypt_block, threefish256_encrypt_block,
    xxtea_decrypt, xxtea_encrypt,
)

TEST_KEY = hashlib.sha256(b"TEST-ONLY-SYNTHETIC-KEY -- never a real key").digest()
TEST_KEY16 = TEST_KEY[:16]
TEST_IV = b"TEST-IV-16-BYTES"


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)
    return cond


UNOBFUSCATE = {
    "\u4e8c": "e", "\u4e3b": "h", "\u4e3a": "n", "\u7684": "o",
    "\u756b": "p", "\u6ca1": "i", "\u5c31": "l", "\ub463": "a",
    "\ub528": "c", "\ub56c": "d", "\u5927": "1", "\u5973": "2",
    "\ub4e4": "7", "\u5929": "0", "\u5c71": "8", "\ub540": "9",
    "\u4e2d": "6", "\u56fd": "m", "\ub538": "b", "\u5c0f": "f",
    "\u5f53": "k", "\u4e0e": "g", "\ub4cc": "5", "\ub4fd": "3",
    "\u304f": "4",
}
KEY256 = hashlib.sha256(b"TEST-ONLY-SYNTHETIC-FMT-KEY").digest()
PT = json.dumps({"server": "{\"Name\": \"TEST SERVER\"}",
                 "network": "{\"Name\": \"TEST NETWORK\"}"},
                ensure_ascii=False).encode("utf-8")


def deobfuscate(text):
    return "".join(UNOBFUSCATE.get(ch, ch) for ch in text)


def dtk_seal(pt):
    return base64.b64encode(aes_cbc_encrypt(KEY256, bytes(16), pt)).decode()


def dtk_open(b64):
    raw = aes_cbc_decrypt(KEY256, bytes(16), base64.b64decode(b64))
    obj = json.loads(raw.decode("utf-8"))
    if set(obj) != {"server", "network"}:
        raise ValueError("bad .dtk JSON keys")
    return obj


def main():
    check("CJK substitution: obfuscated host decodes",
          deobfuscate("\u6ca1\u756b\u5927.\u56fd\u6ca1\u4e3a\u6ca1tu\u4e3a\u5973\u4e2d.xyz")
          == "ip1.minitun26.xyz")
    check("CJK substitution: unmapped char passes through (U+65E5)",
          deobfuscate("A\u65e5B") == "A\u65e5B")
    blob = dtk_seal(PT)
    check(".dtk round-trip (Base64 + AES-256-CBC, {server, network})",
          dtk_open(blob)["server"] == "{\"Name\": \"TEST SERVER\"}")
    try:
        dtk_open(base64.b64encode(b"short").decode())
        check("negative: short .dtk rejected", False)
    except Exception:
        check("negative: short .dtk rejected", True)
    try:
        bad = bytearray(base64.b64decode(blob))
        bad[-1] ^= 1
        dtk_open(base64.b64encode(bytes(bad)).decode())
        check("negative: corrupted .dtk rejected", False)
    except Exception:
        check("negative: corrupted .dtk rejected", True)
    print("VERIFY OK")


if __name__ == "__main__":
    main()
