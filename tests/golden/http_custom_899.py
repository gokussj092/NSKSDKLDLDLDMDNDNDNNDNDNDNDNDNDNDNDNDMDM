"""Public synthetic HC899 files, using independently captured native KDF keys.

The four keys came from libruntime.so build 899, functions 0x1d63f0 and
0x1e6ab0, with a modeled certificate context and public synthetic inputs.
They are NOT computed by the Python decoder under test. These are not real
user files or an Android import/export certification.
"""
from __future__ import annotations
import json
import struct
from Crypto.Cipher import ChaCha20_Poly1305

from decoders.Python.apps.HTTP_Custom.codec import OUTER_AAD, OUTER_KEY

PASSWORD = "Synthetic-HC899!"
HWID = "A" * 32
NATIVE_KEYS = {
    (False, False): "de4dc7bbfd1c6f815dfd106b710b61391bd32cb7c48d983db99e3497ce48bbca",
    (False, True): "25c3522507e76b087d52555eb9083f129605f288f2c835c1077778262789ae4b",
    (True, False): "c055f0076c8b1523bb220fcf6b0b2315ac860ce6b1f18e3b83300e32f395d186",
    (True, True): "758115b15a4ebfd2e0c6c646cd8e490c7cdf83599e2a8fc2c6cfd4fb8069ebd5",
}
MAIN = {"s": 11, "t": 899, "c": ["s0"], "g": {"a": "locked", "m": False},
        "u": "", "extra": {"null": None, "bool": True, "nested": [1, {}, []]}}
OPTIONS = {"port": 8080, "sni": "example.org", "enabled": True, "none": None,
           "nested": [{"zero": 0, "empty": ""}, False]}
OPTIONS_TEXT = json.dumps(OPTIONS, ensure_ascii=False, indent=1)
PROFILE = dict(label="s0", name="Synthetic ñ 配置", protocol="ssh", host="example.org",
               port=443, username="demo", password="dummy", payload="GET / HTTP/1.1\r\n\r\n",
               options=OPTIONS, options_text=OPTIONS_TEXT, flags=0xffffffff,
               updated_at_ms=1700000000123, mode="ssh")


def aead(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return ciphertext + tag


def flip(data: bytes) -> bytes:
    return data[:-1] + bytes([data[-1] ^ 1])


def profile_bytes() -> bytes:
    def text(value):
        raw = value.encode()
        return struct.pack(">I", len(raw)) + raw
    return (b"HPC1" + struct.pack(">I", 11) + text(PROFILE["name"]) + text("ssh")
            + text("example.org") + struct.pack(">I", 443) + text("demo") + text("dummy")
            + text(PROFILE["payload"]) + text(OPTIONS_TEXT)
            + struct.pack(">IQ", 0xffffffff, 1700000000123) + text("ssh"))


def seal(envelope: dict, carrier: int = 0) -> bytes:
    nonce = bytes(range(48, 72))
    data = nonce + aead(OUTER_KEY, nonce, OUTER_AAD, json.dumps(envelope).encode())
    for _ in range(carrier):
        data = data.decode("latin1").encode("utf-8")
    return data


def make_file(*, locked=False, protected=False, tamper=None, carrier=0, sidecar=b"\xff\0\xfe"):
    envelope = {"a": "HCCFG", "b": 10, "c": "s1", "d": "h1",
                "e": "n12" if locked else "n11", "f": ["ssh", "profiles"],
                "g": bytes(range(32)).hex(), "h": int(protected), "n": 899,
                "z": {"preserve": [1, None, False, {}]}}
    if protected:
        envelope.update(k="a1", l=1, m=8192)
    protection = b"|1|ARGON2ID13|1|8192" if protected else b"|0"
    aad = (b"HCCFG|10|XCHACHA20P1305|NATIVE-HKDF-SHA256|" + envelope["e"].encode()
           + b"|xyz.easypro.httpcustom|1|ssh,profiles" + protection + b"|899")
    key = bytes.fromhex(NATIVE_KEYS[(locked, protected)])
    if locked:
        session = bytes(reversed(range(32)))
        nonce = bytes(range(72, 96))
        wrapped = aead(key, nonce, aad + b"\0w", session)
        envelope["o"] = [{"a": nonce.hex(), "b": flip(wrapped).hex()},
                         {"a": nonce.hex(), "b": (flip(wrapped) if tamper == "slot" else wrapped).hex()}]
        key = session
    def section(label, plain, nonce, mutate=False):
        encrypted = aead(key, nonce, aad + b"\0" + label.encode(), plain)
        return {"a": label, "b": nonce.hex(), "c": (flip(encrypted) if mutate else encrypted).hex()}
    envelope["i"] = section("m", json.dumps(MAIN).encode(), bytes(range(24)), tamper == "main")
    nonce = bytes(range(96, 120))
    inner = aead(key, nonce, aad + b"\0s0:r", profile_bytes())
    hpr = b"HPR1" + nonce + (flip(inner) if tamper == "hpr" else inner)
    profile = section("s0", hpr, bytes(range(24, 48)), tamper == "profile")
    nested = aead(key, nonce, aad + b"\0s0:x", sidecar)
    profile["d"] = {"a": nonce.hex(), "b": (flip(nested) if tamper == "sidecar" else nested).hex()}
    envelope["j"] = [profile, section("extra", b'{"preserved":[null,false,0]}', bytes(range(120, 144)))]
    output = seal(envelope, carrier)
    return flip(output) if tamper == "outer" else output
