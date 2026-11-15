#!/usr/bin/env python3
"""Standalone SP-DECODE Telegram bot file decoder, derived from authorized 66.py."""
from __future__ import annotations
import base64
import binascii
import gzip
import hashlib
import html
import json
import logging
import re
import struct
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger = logging.getLogger(__name__)


# ⚠️ المفتاح الجديد المستخرج من V2Box 6.1.2 - dg2.java
_V2BOX_RAW_KEY = [
    12, 104, 24, 53, 34, 31, 52, 57, 40, 35, 42, 46, 51, 53, 52, 17,
    63, 35, 104, 106, 104, 108, 5, 9, 63, 57, 40, 63, 46, 123, 121, 127
]

# المفتاح الفعلي (يُطبق عليه XOR 90)
# = b"V2BoxEncryptionKey2026_Secret!#%"
V2BOX_KEY = bytes(b ^ 90 for b in _V2BOX_RAW_KEY)

# احتياطي: SHA-256 من المفتاح (قد يُستخدم في إصدارات سابقة)
V2BOX_DERIVED_KEY = hashlib.sha256(V2BOX_KEY).digest()


def clean_v2box_input(text: str) -> str:
    """تنظيف النص من المسافات والبروتوكول"""
    if not text:
        return ""
    text = text.strip()
    # إزالة البروتوكولات
    for prefix in ["v2box://", "locked="]:
        if prefix in text:
            text = text.split(prefix, 1)[-1]
    # إزالة المسافات والأسطر الجديدة
    text = "".join(text.split())
    return text


def decode_v2box_base64(encoded: str) -> str:
    """فك Base64 مع إصلاح padding"""
    try:
        missing = len(encoded) % 4
        if missing:
            encoded += '=' * (4 - missing)
        return base64.b64decode(encoded).decode('utf-8')
    except Exception:
        return encoded


def is_v2box_data(text: str) -> bool:
    """التحقق مما إذا كان النص يحتوي على بيانات v2box"""
    try:
        cleaned = clean_v2box_input(text)

        # محاولة فك Base64 أولاً
        try:
            decoded = decode_v2box_base64(cleaned)
            if decoded.startswith('{'):
                data = json.loads(decoded)
                return data.get("magic") == "v2box_export"
        except Exception:
            pass

        # محاولة JSON مباشرة
        try:
            data = json.loads(cleaned)
            return data.get("magic") == "v2box_export"
        except Exception:
            pass

        return False
    except Exception:
        return False


def decrypt_v2box_data(encrypted_json: str, password: str = None) -> dict:
    """
    فك تشفير بيانات v2box

    Args:
        encrypted_json (str): النص المشفر (JSON أو Base64)
        password (str, optional): كلمة المرور إذا كان الملف محمياً

    Returns:
        dict: البيانات المفكوكة أو dict فيه "__need_password__" إذا كان محمياً
    """
    try:
        # 1. تنظيف الإدخال
        cleaned = clean_v2box_input(encrypted_json)

        # 2. محاولة فك Base64 أولاً
        try:
            decoded = decode_v2box_base64(cleaned)
            if decoded.startswith('{'):
                data = json.loads(decoded)
            else:
                data = json.loads(cleaned)
        except Exception:
            data = json.loads(cleaned)

        # 3. التحقق من التنسيق
        if data.get("magic") != "v2box_export":
            return None

        # 4. استخراج المكونات
        nonce_b64 = data.get("nonce", "")
        tag_b64 = data.get("tag", "")
        ciphertext_b64 = data.get("ciphertext", "")

        if not nonce_b64 or not tag_b64 or not ciphertext_b64:
            return None

        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Export v2 uses a per-file PBKDF2 key and authenticates its
        # base64-encoded header as GCM AAD. Never try the v1 fixed key here.
        if type(data.get("version")) is int and data["version"] == 2:
            encoded_header = data.get("header")
            if not isinstance(encoded_header, str) or not 0 < len(encoded_header) <= 4096:
                return None
            try:
                header_bytes = base64.b64decode(encoded_header, validate=True)
                header = json.loads(header_bytes.decode("utf-8"))
                if not isinstance(header, dict) or header.get("v") != 2 or (
                    header.get("kdf") != "pbkdf2-sha256"
                ):
                    return None
                iterations = header.get("iterations")
                if type(iterations) is not int or not 100_000 <= iterations <= 1_200_000:
                    return None
                salt_value = header.get("salt")
                if not isinstance(salt_value, str):
                    return None
                salt = base64.b64decode(salt_value, validate=True)
                if not 16 <= len(salt) <= 32:
                    return None
            except (UnicodeError, ValueError, TypeError, binascii.Error):
                return None
            if password is None:
                return {"__need_password__": True}
            key = PBKDF2(password.encode("utf-8"), salt, dkLen=32,
                         count=iterations, hmac_hash_module=SHA256)
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                cipher.update(encoded_header.encode("ascii"))
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                result = json.loads(plaintext.decode("utf-8"))
                return result if isinstance(result, dict) else None
            except (ValueError, TypeError, UnicodeError):
                return None

        # 5. تحديد المفاتيح المناسبة حسب الكود الأصلي في dg2.java
        keys_to_try = []

        if data.get("isPasswordProtected"):
            # 🔒 ملف محمي بكلمة مرور
            if password is None:
                # نحتاج إلى طلب كلمة المرور من المستخدم
                return {
                    "__need_password__": True,
                    "data": data,
                    "expiration": data.get("expirationTimestamp"),
                    "allowedDevices": data.get("allowedDeviceIDs")
                }
            # المفتاح = SHA-256(password)
            keys_to_try.append(hashlib.sha256(password.encode('utf-8')).digest())
        else:
            # ✅ ملف غير محمي - المفتاح الثابت
            keys_to_try.append(V2BOX_KEY)           # المفتاح المباشر (الصحيح)
            keys_to_try.append(V2BOX_DERIVED_KEY)   # احتياطي

        # 6. محاولة فك التشفير بكل مفتاح
        for key in keys_to_try:
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                result = json.loads(plaintext.decode('utf-8'))
                return result
            except Exception:
                continue

        return None

    except Exception as e:
        logger.error(f"V2Box decryption error: {e}")
        return None
def decode_file(data:bytes,password:str|None=None)->dict|None:
    if not data or len(data)>2*1024*1024:
        return None
    return decrypt_v2box_data(data.decode("utf-8",errors="replace"),password=password)

def run(data:bytes)->str|None:
    config=decode_file(data)
    if config is None:
        return None
    if isinstance(config,dict) and config.get("__need_password__"):
        return "V2Box: this export requires its user-defined password."
    return json.dumps(config,ensure_ascii=False,indent=2)

def main():
    if len(sys.argv) != 2:
        print("Usage: python v2box.py <config-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.name.lower().endswith(".v2box"):
        print("Unsupported extension", file=sys.stderr)
        return 2
    try:
        raw = path.read_bytes()
        output = run(raw)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if output is None:
        print("Unable to decode configuration", file=sys.stderr)
        return 1
    print(output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
