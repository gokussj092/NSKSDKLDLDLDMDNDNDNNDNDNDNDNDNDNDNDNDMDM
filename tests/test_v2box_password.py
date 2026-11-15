"""Synthetic authenticated V2Box password and worker regressions."""
import base64
import hashlib
import json
import unittest
from Crypto.Cipher import AES
from cloud.workers.python.v2box_bridge import process


def export(payload, password=None):
    from decoders.Python.v2box_export import V2BOX_KEY
    key = hashlib.sha256(password.encode("utf-8")).digest() if password is not None else V2BOX_KEY
    cipher = AES.new(key, AES.MODE_GCM, nonce=b"0123456789ab")
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(payload, ensure_ascii=False).encode())
    return json.dumps({
        "magic": "v2box_export", "version": 1,
        "isPasswordProtected": password is not None,
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }).encode()


def export_v2(payload, password="passphrase", iterations=600_000):
    """Synthetic export v2: PBKDF2-SHA256 and header base64 as GCM AAD."""
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2
    header = {"createdAt": 1794506135, "expiresAt": 1794524399,
              "iterations": iterations, "kdf": "pbkdf2-sha256",
              "salt": base64.b64encode(b"0123456789ABCDEF").decode(), "v": 2}
    header_b64 = base64.b64encode(json.dumps(
        header, separators=(",", ":")).encode()).decode()
    key = PBKDF2(password.encode(), b"0123456789ABCDEF", dkLen=32,
                 count=iterations, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=b"0123456789ab")
    cipher.update(header_b64.encode("ascii"))
    ciphertext, tag = cipher.encrypt_and_digest(
        json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    return json.dumps({"magic": "v2box_export", "version": 2,
                       "header": header_b64,
                       "nonce": base64.b64encode(cipher.nonce).decode(),
                       "ciphertext": base64.b64encode(ciphertext).decode(),
                       "tag": base64.b64encode(tag).decode()}).encode()


class V2BoxPasswordTest(unittest.TestCase):
    def test_password_flow(self):
        result = {"configs": [{"remark": "éclair"}], "raws": [], "a": {}, "b": []}
        normal = export(result)
        protected = export(result, password="123 Test")
        self.assertEqual(process(normal, {}), ("OK", result))
        self.assertEqual(process(protected, {})[0], "PASSWORD_REQUIRED")
        self.assertEqual(process(protected, {"password": "123 Test"}), ("OK", result))
        self.assertEqual(process(protected, {"password": "wrong"})[0], "AUTH_FAILED")
        self.assertEqual(process(normal, {"password": "wrong"})[0], "INVALID_CREDENTIALS")

    def test_v2_password_pbkdf2_gcm_authenticated_header(self):
        payload = {"configs": [{"remark": "V2 ✅", "data": "synthetic example"}],
                   "lockMessage": "protected", "locked": True}
        raw = export_v2(payload, password="known_password")
        self.assertEqual(process(raw, {})[0], "PASSWORD_REQUIRED")
        self.assertEqual(process(raw, {"password": "not_the_password"})[0], "AUTH_FAILED")
        self.assertEqual(process(raw, {"password": "known_password"}), ("OK", payload))
        for mutated_field in ("tag", "ciphertext", "header"):
            data = json.loads(raw)
            altered = bytearray(base64.b64decode(data[mutated_field]))
            altered[-1] ^= 1
            data[mutated_field] = base64.b64encode(altered).decode()
            code, result = process(json.dumps(data).encode(),
                                   {"password": "known_password"})
            self.assertNotEqual(code, "OK", mutated_field)
            self.assertIsNone(result)

    def test_v2_refuses_invalid_kdf_and_excessive_iterations(self):
        payload = {"configs": []}
        original = json.loads(export_v2(payload))
        for mutation in ({"kdf": "pbkdf2-sha1"}, {"iterations": 2_000_000},
                         {"salt": base64.b64encode(b"short").decode()}):
            data = dict(original)
            header = json.loads(base64.b64decode(data["header"]))
            header.update(mutation)
            data["header"] = base64.b64encode(json.dumps(header).encode()).decode()
            self.assertEqual(process(json.dumps(data).encode(),
                                     {"password": "passphrase"})[0], "DECODE_FAILED")

    def test_v1_without_version_remains_compatible(self):
        payload = {"configs": []}
        raw = json.loads(export(payload))
        raw.pop("version")
        self.assertEqual(process(json.dumps(raw).encode(), {}), ("OK", payload))

    def test_integrity_and_schema(self):
        item = json.loads(export({"configs": []}, password="pw"))
        tag = bytearray(base64.b64decode(item["tag"]))
        tag[0] ^= 128
        item["tag"] = base64.b64encode(tag).decode()
        self.assertEqual(process(json.dumps(item).encode(), {"password": "pw"})[0], "AUTH_FAILED")
        self.assertEqual(process(b"not a file", {})[0], "DECODE_FAILED")
        self.assertEqual(process(export({}), {"hwid": "x"})[0], "INVALID_CREDENTIALS")


if __name__ == "__main__":
    unittest.main()
