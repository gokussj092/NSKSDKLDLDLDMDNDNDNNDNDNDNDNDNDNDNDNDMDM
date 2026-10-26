"""Aura build 19: independent libsodium Argon2id + JDK GCM reference.

No production decoder imports; synthetic data only in generated fixtures.
"""
from __future__ import annotations
import base64
import ctypes
from ctypes.util import find_library
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tests.golden.mm_tunnel_reference import aes_batch

EXPORT_PASSWORD = b"mcW2R5coCkQCDQWnM7iHIpSrs16ZeCaE"
FIELD_PASSWORD = b"0wwSloVh9DWgmXVNMBkwDRnjVJJgkAgo"


def kdf(password, salt):
    lib = ctypes.CDLL(find_library("sodium"))
    lib.sodium_init()
    fn = lib.crypto_pwhash
    fn.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_char_p,
                   ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_ulonglong,
                   ctypes.c_size_t, ctypes.c_int]
    fn.restype = ctypes.c_int
    output = ctypes.create_string_buffer(32)
    if len(salt) != 16 or fn(output, 32, password, len(password), salt, 3, 8*1024*1024, 2):
        raise ValueError("Independent Aura Argon2id failed")
    return output.raw


def seal(text, exported=False, counter=0):
    salt = bytes((i+counter) % 256 for i in range(16))
    nonce = bytes((i+counter+53) % 256 for i in range(12))
    plain = text.encode() if isinstance(text, str) else text
    line = "\t".join(["E", kdf(EXPORT_PASSWORD if exported else FIELD_PASSWORD, salt).hex(),
                      salt.hex(), nonce.hex(), base64.b64encode(plain).decode()])
    encoded = base64.b64encode(salt+nonce+aes_batch([line])[0]).decode()
    return encoded[:3]+"Q"+encoded[3:] if exported else encoded


def open_many(values):
    lines = []
    for text, exported in values:
        if exported:
            text = text[:3]+text[4:]
        raw = base64.b64decode(text.replace("\r", "").replace("\n", ""), validate=True)
        key = kdf(EXPORT_PASSWORD if exported else FIELD_PASSWORD, raw[:16])
        lines.append("\t".join(["D", key.hex(), raw[:16].hex(), raw[16:28].hex(),
                                base64.b64encode(raw[28:]).decode()]))
    return [raw.decode() for raw in aes_batch(lines)]


def generate():
    profile = {"Name": "Aura 日本語 🛠", "TunnelType": "SSH",
               "Payload": seal("GET / HTTP/1.1\r\nHost: example.invalid\r\n", counter=1),
               "SNI": "plain.example.invalid", "URI": False, "ProxyPort": "8080",
               "unknown": {"nested": [True, None, 3.5, "é"]},
               "restrictions": {"password": "synthetic lock", "HWID": "synthetic device", "expiry": "2030"}}
    expected = dict(profile, Payload="GET / HTTP/1.1\r\nHost: example.invalid\r\n")
    server = {"Name": "test server", "ServerIPHost": seal("vpn.example.invalid", counter=2),
              "H2pass": seal("synthetic h2", counter=3)}
    catalog = {"Version": "test.19", "Servers": [server], "Networks": [profile],
               "ReleaseNotes": "synthetic", "DefOVPNPass": seal("", counter=4),
               "isTimerOn": False, "future": {"preserve": [0, None]}}
    expected_catalog = dict(catalog, Servers=[dict(server, ServerIPHost="vpn.example.invalid", H2pass="synthetic h2")],
                            Networks=[expected], DefOVPNPass="")
    documents = []
    for kind, outer, clear in (("file", profile, expected), ("catalog", catalog, expected_catalog)):
        text = json.dumps(outer, ensure_ascii=False, separators=(",", ":"))
        for mode in ("export", "eo", "plain"):
            wire = text if mode == "plain" else seal(text, mode == "export", 10+len(documents))
            documents.append({"kind": kind, "mode": mode, "wire": wire, "outer": outer, "expected": clear})
    return {"documents": documents,
            "duplicate": seal('{"Name":"a","TunnelType":"SSH","Name":"b"}', True, 30),
            "invalidUtf8": seal(b"\xff\xfe", True, 31),
            "kdf": {"password": "synthetic key", "saltHex": bytes(range(16)).hex(),
                    "keyHex": kdf(b"synthetic key", bytes(range(16))).hex()}}


if __name__ == "__main__":
    print(json.dumps(generate(), ensure_ascii=False, indent=2))
