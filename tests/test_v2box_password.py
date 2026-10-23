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
