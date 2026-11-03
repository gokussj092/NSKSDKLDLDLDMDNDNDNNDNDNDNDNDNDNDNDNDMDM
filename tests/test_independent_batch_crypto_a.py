"""Source-derived synthetic positive vectors: IZPH, FlexNet, N4 and CREV."""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import unittest
import zlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decoders.Python import crev, flex, izph, n4


def b64(data: bytes) -> bytes:
    return base64.b64encode(data)


def crev_encrypt(data: bytes, password: str = "DEV_CREEB") -> bytes:
    """Independent inverse of 66.py's custom CREV XXTEA decryption."""
    words = crev.crev_to_int_array(data, True)
    key = crev.crev_to_int_array(crev.crev_fix_key(password.encode()), False)
    n = len(words) - 1
    total = 0
    mask = 0xFFFFFFFF
    for _ in range(6 + 52 // (n + 1)):
        total = (total + crev.DELTA_CREV) & mask
        e = (total >> 2) & 3
        z = words[n]
        for p in range(n):
            y = words[p + 1]
            mx = crev.crev_mx(total, y, z, p, e, key)
            words[p] = (words[p] + mx) & mask
            z = words[p]
        words[n] = (words[n] + crev.crev_mx(
            total, words[0], z, n, e, key)) & mask
    return crev.crev_to_byte_array(words, False)


def flex_fixture(version: int, lock: int, profile: dict) -> bytes:
    """A valid FLXCFG PBKDF2-SHA512 AES-GCM zlib container."""
    inner = "<properties>" + "".join(
        f'<entry key="{key}">{value}</entry>' for key, value in profile.items()
    ) + "</properties>"
    salt = bytes(range(32))
    nonce = bytes(range(12))
    material = flex.flex_get_material(version, lock)
    password = material.decode("latin-1").encode("utf-8")
    key = hashlib.pbkdf2_hmac("sha512", password, salt, 10_000, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if version >= 3:
        cipher.update(b"FLXCFG" + bytes([version]) + struct.pack(">I", lock))
    encrypted, tag = cipher.encrypt_and_digest(zlib.compress(inner.encode("utf-8")))
    prefix = b"FLXCFG" + bytes([version])
    if version >= 3:
        prefix += struct.pack(">I", lock)
    return (prefix + struct.pack(">I", 10_000) + bytes([len(salt)]) + salt
            + bytes([len(nonce)]) + nonce
            + struct.pack(">I", len(encrypted) + len(tag)) + encrypted + tag)


def n4_ciphertext(value: str, table: str) -> str:
    key = hashlib.sha256("modmkk".encode("utf-8").hex().upper().encode("utf-8")).digest()
    iv = bytes(16)
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(value.encode(), 16))
    return "".join(table[byte >> 4] + table[byte & 15]
                   for byte in b64(encrypted))


def n4_fixture(profile: dict) -> bytes:
    key = hashlib.sha256(b"jdk").digest()
    plain = json.dumps(profile, ensure_ascii=False).encode("utf-8")
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pad(plain, 16))
    return b64(encrypted)


def izph_xxtea_encrypt(data: bytes, key: bytes) -> bytes:
    """Inverse of the proprietary IZPH XXTEA; distinct from standard DELTA."""
    v = crev.crev_to_int_array(data, True)
    k = crev.crev_to_int_array(crev.crev_fix_key(key), False)
    n = len(v) - 1
    total = 0
    mask = 0xFFFFFFFF
    for _ in range(6 + 52 // (n + 1)):
        total = (total + izph.IZPH_DELTA) & mask
        e = (total >> 2) & 3
        z = v[n]
        for p in range(n):
            y = v[p + 1]
            v[p] = (v[p] + crev.crev_mx(total, y, z, p, e, k)) & mask
            z = v[p]
        v[n] = (v[n] + crev.crev_mx(total, v[0], z, n, e, k)) & mask
    return crev.crev_to_byte_array(v, False)


def izph_threefish_encrypt(data: bytes, key: bytes) -> bytes:
    """Independent test-only inverse of IZPH pure-Python Threefish-256."""
    mask = 0xFFFFFFFFFFFFFFFF
    rotations = izph.IZPH_THREEFISH256_ROTATIONS
    key_words = list(struct.unpack("<4Q", key))
    output = bytearray()
    assert len(data) % 32 == 0
    for index in range(0, len(data), 32):
        words = list(struct.unpack("<4Q", data[index:index + 32]))
        block = index // 32
        subkeys = izph.izph_threefish256_subkeys(key_words, (block, block * 64))
        words = [(words[i] + subkeys[0][i]) & mask for i in range(4)]
        for group in range(18):
            for step in range(4):
                r0, r1 = rotations[(group * 4 + step) % 8]
                for i, rot in ((0, r0), (2, r1)):
                    y0 = (words[i] + words[i + 1]) & mask
                    y1 = (((words[i + 1] << rot) |
                           (words[i + 1] >> (64 - rot))) & mask) ^ y0
                    words[i:i + 2] = (y0, y1)
                words = [words[i] for i in izph.IZPH_THREEFISH256_PERMUTE]
            words = [(words[i] + subkeys[group + 1][i]) & mask
                     for i in range(4)]
        output.extend(struct.pack("<4Q", *words))
    return bytes(output)


class IndependentFirstFourTests(unittest.TestCase):
    def test_izph_type3_aes256_hkdf_and_text_schemes(self):
        document = {"ServerIPHost": "izph.example", "Port": 443}
        iv = bytes(range(16))
        key = izph.izph_get_hkdf_key()
        encrypted = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(
            pad(json.dumps(document).encode(), 16))
        for payload in (b64(encrypted),
                        b"izph://" + b64(encrypted),
                        b"izphvpnpro://" + b64(encrypted)):
            with self.subTest(payload_prefix=payload[:16]):
                decoded = izph.run(payload)
                self.assertIsNotNone(decoded)
                self.assertEqual(json.loads(decoded)["ServerIPHost"], "izph.example")
                self.assertEqual(json.loads(decoded)["Port"], 443)
        self.assertIsNone(izph.run(b"izph://invalid-not-a-file"))


    def test_izph_type0_custom_xxtea_aes_cbc(self):
        obj = {"Server": "izph-type0.example", "Enabled": False}
        source = json.dumps(obj).encode("utf-8")
        added = bytes((value + 2) & 255 for value in source)
        xxtea = izph_xxtea_encrypt(added, izph.IZPH_SHA256_KEY_16)
        cipher = AES.new(izph.IZPH_SHA256_KEY_16,
                         AES.MODE_CBC, izph.IZPH_FIXED_IV)
        token = b64(cipher.encrypt(pad(xxtea, 16)))
        result = izph.run(token)
        self.assertIsNotNone(result)
        self.assertEqual(json.loads(result), obj)

    def test_izph_type1_threefish_without_pyskein(self):
        obj = {"Server": "izph-type1.example", "Modes": ["SSH", "V2Ray"]}
        plain = json.dumps(obj).encode("utf-8")
        aes = AES.new(izph.izph_get_hkdf_key_16(),
                      AES.MODE_CBC, izph.IZPH_FIXED_IV)
        stage = aes.encrypt(pad(plain, 16))
        stage += bytes(-len(stage) % 32)
        encrypted = izph_threefish_encrypt(stage, izph.izph_get_hkdf_key())
        result = izph.run(b64(encrypted))
        self.assertIsNotNone(result)
        self.assertEqual(json.loads(result), obj)

    def test_flex_versions_1_and_3_and_complete_properties(self):
        profile = {"sshServer": "flex.example", "sshPort": "22",
                   "sshUser": "ghost", "customSni": "sni.example",
                   "file.msg": "Keep this user message"}
        for version, lock in ((1, 0), (2, 0), (3, 28), (4, 28)):
            with self.subTest(version=version, lock=lock):
                encrypted = flex_fixture(version, lock, profile)
                decoded = flex.run(encrypted)
                self.assertIsNotNone(decoded)
                obj = json.loads(decoded)
                self.assertEqual(obj["manualServer"]["host"], "flex.example")
                self.assertEqual(obj["tunnel"]["sni"], "sni.example")
                self.assertEqual(obj["rawProperties"], profile)
                damaged = bytearray(encrypted)
                damaged[-1] ^= 1
                self.assertIsNone(flex.run(bytes(damaged)))

    def test_n4_morse_and_two_table_encrypted_fields(self):
        port_morse = " ".join(n4.MORSE_MAP[digit] for digit in "443")
        profile = {"ServerPort": port_morse,
                   "N4User": n4_ciphertext("ghost", n4.TABLE2),
                   "ServerIP": n4_ciphertext("n4.example", n4.TABLE3),
                   "SNI": n4_ciphertext("sni.example", n4.TABLE4),
                   "isSSL": True}
        result = n4.run(n4_fixture(profile))
        self.assertIsNotNone(result)
        actual = json.loads(result)
        self.assertEqual(actual["ServerPort"], "443")
        self.assertEqual(actual["N4User"], "ghost")
        self.assertEqual(actual["ServerIP"], "n4.example")
        self.assertEqual(actual["SNI"], "sni.example")
        self.assertTrue(actual["isSSL"])

    def test_crev_all_three_extensions_and_recursive_tweak_fields(self):
        inner = b64(crev_encrypt(b"crev.example")).decode("ascii")
        document = {"Tweaks": [{"ServerHost": inner, "ServerPort": 22}],
                    "Enabled": False, "Name": "Profile 01"}
        encrypted = b64(crev_encrypt(
            json.dumps(document, ensure_ascii=False).encode("utf-8")))
        for suffix in crev.EXTENSIONS:
            with self.subTest(suffix=suffix):
                decoded = crev.run(encrypted)
                self.assertIsNotNone(decoded)
                config = json.loads(decoded)
                self.assertEqual(config["Tweaks"][0]["ServerHost"], "crev.example")
                self.assertFalse(config["Enabled"])


if __name__ == "__main__":
    unittest.main()
