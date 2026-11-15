#!/usr/bin/env python3
"""One synthetic standard-IV HTTP Injector vector, verified against bot Python.

No customer profile, new key, or unsupported-version claim. The original
decoder remains the reference implementation for expected text and field order.
"""
from __future__ import annotations

import argparse
import base64
import json
import struct
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad
from decoders.Python.HTTPINJECTOR import EHIConstants as C, EHIDecryptor, run
from tests.golden.a23_batch7 import _xxtea_encrypt


def _compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def encode_field(clear: str, salt: str) -> str:
    """Inverse of the source custom alphabet + XOR field encoder (ASCII salt)."""
    original = clear.encode("utf-8")
    encrypted = bytes(value ^ ord(salt[i % len(salt)]) for i, value in enumerate(original))
    standard = base64.b64encode(encrypted.hex().encode("ascii")).decode("ascii")
    return standard.translate(str.maketrans(C.STD_ALPHABET, C.CUSTOM_ALPHABET))[::-1]


def make(message: str = "Synthetic EHI standard variant") -> tuple[bytes, bytes]:
    salt = "EVZJNI"
    key = "EHIMSG"
    utf16 = message.encode("utf-16-be")
    units = [int.from_bytes(utf16[i:i+2], "big") for i in range(0, len(utf16), 2)]
    xored = b"".join((value ^ ord(key[i % len(key)])).to_bytes(2, "big")
                     for i, value in enumerate(units))
    msg = base64.b64encode(xored.decode("utf-16-be", "surrogatepass")
                            .encode("utf-8", "surrogatepass")).decode()
    inner = {
        "serverHost": encode_field("example.org", salt),
        "serverPort": 443,
        "configMessage": msg,
        "profileNote": encode_field("synthetic-parity-test", salt),
    }
    outer = {
        "configAesKey": "synthetic-key",
        "configIdentifier": "SPDECODE-TEST",
        "configSalt": salt,
        "configTimestamp": 1720000000,
        "configExpiryTimestamp": 1720003600,
        "lockModes": "",
        "lockModesHash": "",
        "configHwid": "",
        "configLockMobileOperatorId": "",
    }
    header = b"\x01" + struct.pack("<I", 2) + struct.pack("<I", 32) + b"\x01" + bytes(range(16)) + bytes(range(24))
    assert len(header) == 50
    kdf = hash_secret_raw(
        secret=EHIDecryptor._generate_master_key(outer),
        salt=header[10:26], time_cost=2, memory_cost=32,
        parallelism=1, hash_len=32, type=Type.ID,
    )
    cipher = ChaCha20_Poly1305.new(key=kdf, nonce=header[26:50])
    cipher.update(header[:26])
    encrypted, tag = cipher.encrypt_and_digest(_compact(inner))
    outer["configData"] = encode_field(base64.b64encode(header+encrypted+tag).decode(), salt)

    xxtea = _xxtea_encrypt(_compact(outer), C.EOO_MASTER_KEY)
    iv2 = bytes(range(16))
    second = AES.new(C.L2_KEY_STATIC, AES.MODE_CBC, iv2).encrypt(pad(xxtea,16))
    envelope = base64.b64encode(iv2).decode()+":synthetic:"+base64.b64encode(second).decode()
    first = AES.new(C.L1_KEY, AES.MODE_CBC, C.STANDARD_IVS[0]).encrypt(pad(envelope.encode(),16))
    def java_utf(value: bytes) -> bytes:
        return struct.pack(">H",len(value))+value
    payload = java_utf(b"ehi")+bytes(8)+java_utf(b"offline")+bytes(8)
    payload += struct.pack(">I",len(first))+bytes(8)+first
    expected = run(payload)
    if not expected or "serverHost: example.org" not in expected or message not in expected:
        raise AssertionError("Standard EHI fixture did not round-trip original Python decoder")
    # CLI stdout includes print(result), which appends one terminal newline.
    # Keep this byte-for-byte contract consistent with the frozen 60 goldens.
    return payload, (expected + "\n").encode("utf-8")


def write(out: Path) -> None:
    source, text = make()
    out.mkdir(parents=True, exist_ok=True)
    (out/"ehi-standard-id.ehi").write_bytes(source)
    (out/"ehi-standard-id.txt").write_bytes(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir",type=Path,required=True)
    args=parser.parse_args()
    write(args.output_dir)
    print("Verified synthetic standard-IV EHI against Python reference")


if __name__ == "__main__":
    main()
