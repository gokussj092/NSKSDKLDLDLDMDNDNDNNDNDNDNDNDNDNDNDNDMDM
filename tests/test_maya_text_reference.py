"""Maya reference's fetched .maya body must use the existing complete offline decoder."""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from decoders.Python._noobcrypt import KEYS, decrypt_profile
from decoders.Python import maya

KEY = KEYS["maya"]


def synthetic_maya_file() -> bytes:
    inner = AESGCM(KEY).encrypt(bytes(range(12)), b"verified-inner-field", None)
    document = {
        "Version": "synthetic",
        "Servers": [{"Name": "test", "Password": base64.b64encode(bytes(range(12)) + inner).decode()}],
        "Flags": {"enabled": True},
    }
    plaintext = b"MAYA TUN PRO\n" + json.dumps(document, separators=(",", ":")).encode()
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = bytes(range(16))
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    payload = iv + cipher.update(padded) + cipher.finalize()
    return base64.b64encode(payload)


def test_fetched_maya_base64_file_decodes_every_field():
    source = synthetic_maya_file()
    obj = decrypt_profile(source, "maya")
    assert obj["Version"] == "synthetic"
    assert obj["Servers"][0]["Name"] == "test"
    assert obj["Servers"][0]["Password"] == "verified-inner-field"
    assert obj["Flags"] == {"enabled": True}
    result = maya.run(source)
    assert "verified-inner-field" in result


def test_maya_file_rejects_corrupted_ciphertext():
    source = synthetic_maya_file()
    blob = bytearray(base64.b64decode(source))
    blob[-1] ^= 1
    damaged = base64.b64encode(blob)
    assert maya.run(damaged) is None
