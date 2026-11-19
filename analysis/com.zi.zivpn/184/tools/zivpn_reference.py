#!/usr/bin/env python3
"""ZIVPN Tunnel (.ziv / zivpn://) - reference oracle for the OFFLINE dossier.

App: ZIVPN Tunnel (SSH/DNS/UDP) VPN, com.zi.zivpn, 2.2.5 (versionCode 184).

This module is a TEST-ONLY oracle for the offline native implementation in
android/app/src/main/cpp/spdecode_zivpn.cpp. It mirrors the server-side
reference decoders/Python/apps/ZIVPN/ZIVPN_archivos.py (LF1 + DES file
format) and decoders/Python/text_legacy_protocols.py::decode_zivpn
(zivpn:// text format) from the online branch, using PyCryptodome instead
of the reference's stdlib-only AES/DES. The crypto inputs/outputs are
identical; the online reference remains the authoritative description of
the app behaviour (including the export/import DES asymmetry).

Format recap (see analysis/com.zi.zivpn/184/ANALYSIS.md):
  .ziv file = Base64(salt) "." Base64(iv) "." Base64(ct+tag)
    salt 32 B, iv 12 B; key = PBKDF2-HMAC-SHA256(password, salt, 1000, 16 B);
    AES-128-GCM, no AAD; inner layer DES/ECB/PKCS5, DES key from the app
    (first 8 bytes used as the DES key). Interior = java.util.Properties
    XML ("Configuration File"). Import expects LF1 -> DES -> XML; the
    app's own export applies LF1 only, so open_ziv() retries without DES.
  zivpn:// link = "zivpn://" + Base64(AES-256-CBC(SHA256(text password),
    zero IV, PKCS7) of the Properties XML (or JSON) plaintext).

Method constants below are app-embedded format constants already present
in this repo (decoders/Python/ziv.py, embedded_kotlin_profiles.json and
the online reference). They are NOT user credentials, accounts or tokens.
Do NOT print them in reports, commit messages or chat text.
"""
import base64
import binascii
import hashlib
import json
import re
import xml.etree.ElementTree as ET

from Crypto.Cipher import AES, DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# App-embedded .ziv LF1 passwords (candidates, in order): the current
# fixed password first, then the legacy password kept by decoders/Python/ziv.py.
LF1_PASSWORDS = [
    "SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5",
    "fubvx788b46v",
]
# DES key spec from the reference; DESKeySpec uses the first 8 bytes.
DES_KEY = b"#ipt!2022/H"
SALT_LEN = 32
IV_LEN = 12
PBKDF2_ITERS = 1000
KEY_LEN = 16  # AES-128

# Text-link password (base64 of the password in text_legacy_protocols.py).
TEXT_PASSWORD_B64 = "dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ="


class DecodeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _b64decode(part):
    try:
        return base64.b64decode(part, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("ZIV_BASE64", "Part is not Base64.") from exc


def _lf1_key(password, salt):
    return PBKDF2(password.encode("utf-8"), salt, dkLen=KEY_LEN,
                  count=PBKDF2_ITERS, hmac_hash_module=SHA256)


def lf1_decrypt(text, passwords=LF1_PASSWORDS):
    """'b64(sal).b64(iv).b64(ct+tag)' -> inner bytes (tries each password)."""
    parts = text.strip().split(".")
    if len(parts) != 3:
        raise DecodeError("ZIV_ENVELOPE", "Not 3 dot-separated parts.")
    salt = _b64decode(parts[0])
    iv = _b64decode(parts[1])
    cttag = _b64decode(parts[2])
    if len(salt) != SALT_LEN or len(iv) != IV_LEN or len(cttag) < 17:
        raise DecodeError("ZIV_LENGTH", "Bad salt/iv/ciphertext lengths.")
    last = None
    for password in passwords:
        key = _lf1_key(password, salt)
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(cttag[:-16], cttag[-16:])
        except ValueError as exc:
            last = exc
    raise DecodeError("ZIV_AUTH_FAILED",
                      "GCM tag failed for every known password.") from last


def lf1_encrypt(data, password, salt, iv):
    key = _lf1_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    return ".".join((base64.b64encode(salt).decode("ascii"),
                     base64.b64encode(iv).decode("ascii"),
                     base64.b64encode(ct + tag).decode("ascii")))


def _des_decrypt(data):
    try:
        return unpad(DES.new(DES_KEY[:8], DES.MODE_ECB).decrypt(data), 8)
    except ValueError as exc:
        raise DecodeError("ZIV_DES", "DES layer did not decrypt/unpad.") from exc


def _des_encrypt(data):
    return DES.new(DES_KEY[:8], DES.MODE_ECB).encrypt(pad(data, 8))


_SURROGATE_PAIR_RE = re.compile(
    r"&#(x[0-9A-Fa-f]+|[0-9]+);&#(x[0-9A-Fa-f]+|[0-9]+);")


def _combine_surrogate_pairs(text):
    """Combine adjacent UTF-16 surrogate-pair character references.

    java.util.Properties writes astral characters (e.g. emoji) as a pair
    of numeric references to the UTF-16 surrogates ("&#55356;&#56808;"
    for U+1F608). Those references are invalid in strict XML 1.0, so
    ElementTree rejects them; combine each adjacent high+low pair into
    the single code point first. A lone surrogate is left untouched and
    still fails to parse, matching the native decoder.
    """
    def _num(token):
        return int(token[1:], 16) if token[:1] in "xX" else int(token)

    def _repl(match):
        hi = _num(match.group(1))
        lo = _num(match.group(2))
        if 0xD800 <= hi <= 0xDBFF and 0xDC00 <= lo <= 0xDFFF:
            return "&#%d;" % (0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
        return match.group(0)

    return _SURROGATE_PAIR_RE.sub(_repl, text)


def parse_properties_xml(xml_bytes):
    try:
        text = xml_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("ZIV_UTF8", "Interior is not UTF-8.") from exc
    try:
        root = ET.fromstring(_combine_surrogate_pairs(text))
    except ET.ParseError as exc:
        raise DecodeError("ZIV_XML", "Properties XML does not parse.") from exc
    props = {}
    for entry in root.findall("entry"):
        key = entry.get("key")
        if key is not None:
            props[key] = entry.text or ""
    if not props:
        raise DecodeError("ZIV_XML", "No <entry> properties found.")
    return props, text


def properties_xml(props):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">',
             '<properties>',
             '<comment>Configuration File</comment>']
    for key in sorted(props):
        val = props[key]
        esc = (val.replace("&", "&amp;").replace("<", "&lt;")
               .replace(">", "&gt;"))
        lines.append('<entry key="%s">%s</entry>' % (key, esc))
    lines.append('</properties>')
    return ("\n".join(lines) + "\n").encode("utf-8")


def open_ziv(data):
    """Open a .ziv (bytes/str) -> (props, xml_text, info)."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="strict")
    else:
        text = data
    inner = lf1_decrypt(text)
    try:
        xml_bytes = _des_decrypt(inner)
        des_layer = True
    except DecodeError:
        xml_bytes = inner
        des_layer = False
    props, xml_text = parse_properties_xml(xml_bytes)
    return props, xml_text, {"des_layer": des_layer}


def seal_ziv(props, password, salt, iv, legacy=True):
    """dict -> .ziv text. legacy=True: XML -> DES -> LF1 (import format);
    legacy=False: XML -> LF1 (as the app exports)."""
    xml_bytes = properties_xml(props)
    inner = _des_encrypt(xml_bytes) if legacy else xml_bytes
    return lf1_encrypt(inner, password, salt, iv)


def text_password():
    return base64.b64decode(TEXT_PASSWORD_B64).decode("utf-8")


def seal_zivpn_text(plain_text):
    """Plaintext (XML or JSON str) -> 'zivpn://<base64>' token."""
    key = hashlib.sha256(text_password().encode("utf-8")).digest()
    cipher = AES.new(key, AES.MODE_CBC, bytes(16))
    ct = cipher.encrypt(pad(plain_text.encode("utf-8"), 16))
    return "zivpn://" + base64.b64encode(ct).decode("ascii")


def decode_zivpn(text):
    """'zivpn://<base64>' -> plaintext str (mirrors decode_zivpn)."""
    if not isinstance(text, str):
        return None
    data = text.strip()
    if not data.lower().startswith("zivpn://"):
        return None
    token = "".join(data[len("zivpn://"):].split()).replace("-", "+").replace("_", "/")
    token += "=" * (-len(token) % 4)
    try:
        encrypted = base64.b64decode(token, validate=True)
        if not encrypted or len(encrypted) % 16:
            return None
        key = hashlib.sha256(text_password().encode("utf-8")).digest()
        plain = unpad(AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(encrypted), 16)
        result = plain.decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error):
        return None
    if not result.strip():
        return None
    try:
        item = json.loads(result)
        if isinstance(item, (dict, list)):
            return json.dumps(item, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        pass
    return result
