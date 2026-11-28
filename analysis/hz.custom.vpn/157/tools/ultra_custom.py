#!/usr/bin/env python3
# Dossier copy (CAT 103): SANITIZED. Format key material is NOT stored
# in this file; supply it via the environment variables documented
# below and in REPRODUCE.md. Never commit keys, tokens or passwords here.
"""Ultra Custom 15.7 (hz.custom.vpn) — .ua files, ua:// links, bundles, .ucs subscriptions.

Offline standalone reader. Password-protected UAP1 profiles require the
original password. No APK, native library, Android runtime or network needed
except for --url (fetch a UCS subscription document over HTTPS).

Reversed from Ultra_Custom_15.7_1_9qyw.apks (versionCode 157, versionName
15.7, package hz.custom.vpn — the same package as Ultra Custom 5.2):
  * classes.dex: com.ultra.custom.config.ConfigParser (import/export flow),
    ProfilePayloadCodec (EXA1/UAB1 raw-DEFLATE + dictionary), ProfilePasswordCodec
    (UAP1), ProfileBundleCodec (UA-BUNDLE-1), com.ultra.custom.profile
    .ConnectionProfileLinkCodec ("ua://"), com.ultra.custom.subscription
    .UcsCodec/UcsDownload/UcsDocument (CSS1 subscription documents).
  * libhysteria-v2.so (arm64 split): Java_com_ultra_custom_util_NativeProtection
    _decodeProfile (0x15e1c) / _encodeProfile (0x14770), helper 0x17834.
  * libx.so (arm64 split): Java_ooO0oo0_xdevz_o0oooo00 (0x641f8) /
    o0oooOoO (0x63e1c), shared transform 0x63ee0.

FILE FORMAT (ConfigParser.decodeInput — UAF2 first, legacy fallback)
-------------------------------------------------------------------
  .ua file / ua:// link text (after stripping an optional "ua://" prefix):
    1. NativeProtection.decodeProfile(text):
         - "!UAF2=:" + base64url(nonce[12] || AES-256-GCM ciphertext || tag[16])
           Key: 32 bytes derived in libhysteria-v2.so helper 0x17834 from 32
           obfuscated bytes at file offset 0xad3b and a 32-bit seed at 0xad5c
           (see _uaf2_key(); verified against the real sample below).
           AAD is the literal 7 bytes b"!UAF2=:" (libsodium
           crypto_aead_aes256gcm_decrypt, called with ad="!UAF2=:", adlen=7;
           if libsodium AES-GCM is unavailable the native code falls back to
           Java NativeProtection.platformGcm with the same key/nonce/AAD).
           Decoded length must be >= 28 (12 nonce + 16 tag).
         - anything else without ':' returns NULL -> legacy path below;
           anything else containing ':' throws "Formato de archivo de perfil
           incompatible" (the Java side then fails the import).
       If decodeProfile returns NULL:
    2. Legacy: Base64 URL_SAFE decode -> libx.so 0x63ee0 byte transform
       (decrypt flag 1). The transform is byte-identical to Ultra Custom 5.2:
       MASK_KEY <supplied via ULTRA_CUSTOM_MASK_KEY_HEX> (built byte-by-byte at 0x63f24-0x63f90),
       xorshift state seeded 0x91AC3F12 (0x63f28-0x63f2c).
  Then, in both cases (ConfigParser.decodeInput):
    3. UAP1 password layer (ProfilePasswordCodec): "UAP1" + salt[16] +
       nonce[12] + AES-256-GCM ciphertext+tag, key = PBKDF2-HMAC-SHA256
       (password, salt, 210000 iterations, 32 bytes), AAD = the 32-byte header.
    4. Payload layer (ProfilePayloadCodec): "EXA1"/"UAB1" + raw DEFLATE with
       the fixed dictionary (LINK_DICTIONARY_KEYS_V1), or plain XML.

  Export is the exact reverse (ConfigParser.convertDataToFile /
  convertDataToLink / writeBundleFile): XML -> UAP1 (if password) -> UAF2
  (files and bundles) or legacy Base64URL (links only). Bundles are a
  Properties XML with file.bundleFormat=UA-BUNDLE-1 and profile.<i> members
  (1..100); a password-protected member is wrapped as
  file.profilePasswordFormat=1 + file.passwordPayload (Base64 UAP1).

UCS SUBSCRIPTION CATALOG (UcsCodec / UcsDownload — no vendor catalog URL)
-------------------------------------------------------------------------
  Ultra Custom 15.7 has NO built-in catalog URL. A catalog is a subscription
  the user adds by pasting an HTTPS URL or importing a .ucs/.ultra/.ultraopen
  file (UcsProjectStore). The app downloads it with a plain GET
  (UcsDownload.fetch): User-Agent "UltraCustom-UCS/1",
  Accept "application/vnd.ultracustom.subscription, application/octet-stream,
  application/json", Cache-Control "no-cache, no-store, max-age=0",
  Pragma "no-cache", connect 15 s / read 20 s, up to 5 manual redirects,
  HTTPS only, max 16 MiB, 404/410 = gone, HTML bodies rejected.
  Outer JSON: {"format": "CSS1", "payload": base64(inner JSON),
  "public_key": base64(X.509 EC P-256), "signature": base64(ECDSA)}.
  Signature: SHA256withECDSA over b"CloudServers/CSS1\\n" + payload bytes.
  Inner JSON: {"id": UUID, "title": str, "note": str, "update_url": https,
  "status": "active"|"disabled", "revision": int, "refresh_minutes": 1..1440,
  "expires_at": int, "block_root"/"mobile_only"/"login_hwid": bool,
  "hwids": [str<=100], "servers": [{"id", "name",
  "profile_payload": "<.ua profile text>"}] (1..100)}.
  Each server's profile_payload decodes with the .ua decoder above.
  Use --url <https://...> to fetch, verify and decode a subscription.

VERIFIED (2026-11-28, real sample)
----------------------------------
  ~/workspace/user/files/Guatemala_Tigo__1__7_fy55.ua (6,287 bytes,
  "!UAF2=:" + base64url) decrypts to a 4,682-byte Java Properties XML:
  profile "Guatemala Tigo", file.appVersionCode 157, file.profileFormat 2,
  tunnelType 12, dnsForward 1. UAF2 encode->decode round-trip is byte-identical
  (fresh nonce), and a wrong AAD is rejected by the GCM tag.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import http.client
import json
import math
import os
import re
import secrets
import ssl
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES

MAX_BYTES = 16 * 1024 * 1024
MAX_TOTAL_XML_BYTES = 32 * 1024 * 1024
MAX_PROFILES = 100

# --- UAF2 (libhysteria-v2.so helper 0x17834) --------------------------------
UAF2_PREFIX = "!UAF2=:"
UAF2_AAD = b"!UAF2=:"
# Dossier copy (CAT 103): the UAF2 key and the legacy mask key are fixed
# format constants from the native libraries. They are NOT stored in this
# file; supply the DERIVED 32-byte UAF2 key and the mask key as hex via:
#   ULTRA_CUSTOM_UAF2_KEY_HEX  = 64 hex chars (derived AES-256-GCM key)
#   ULTRA_CUSTOM_MASK_KEY_HEX  = hex of the libx.so mask key
# (derivation documented in ANALYSIS.md; values only in the batch report).
# With ULTRA_CUSTOM_TEST_KEYS=1 the TEST-ONLY keys below are used
# (self-test and dossier tests only; they open no real file).
TEST_UAF2_KEY = bytes.fromhex("33" * 32)
TEST_MASK_KEY = b"TEST-MASK-KEY"


def _uaf2_key() -> bytes:
    raw = os.environ.get("ULTRA_CUSTOM_UAF2_KEY_HEX", "")
    if raw:
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = b""
        if len(key) == 32:
            return key
        raise DecodeError("KEYS_NOT_CONFIGURED",
                          "ULTRA_CUSTOM_UAF2_KEY_HEX must be 64 hex chars.")
    if os.environ.get("ULTRA_CUSTOM_TEST_KEYS") == "1":
        return TEST_UAF2_KEY
    raise DecodeError("KEYS_NOT_CONFIGURED",
                      "ULTRA_CUSTOM_UAF2_KEY_HEX is not set. The UAF2 key is "
                      "not stored in this dossier; supply it via the environment.")


def _mask_key() -> bytes:
    raw = os.environ.get("ULTRA_CUSTOM_MASK_KEY_HEX", "")
    if raw:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    if os.environ.get("ULTRA_CUSTOM_TEST_KEYS") == "1":
        return TEST_MASK_KEY
    raise DecodeError("KEYS_NOT_CONFIGURED",
                      "ULTRA_CUSTOM_MASK_KEY_HEX is not set. The legacy mask "
                      "key is not stored in this dossier; supply it via the "
                      "environment.")


# --- Legacy libx.so 0x63ee0 byte transform (identical to Ultra Custom 5.2) ---
DICTIONARY_KEYS = (
    "file.appVersionCode", "file.profileFormat", "file.profileName", "file.msg",
    "autorkey", "file.proteger", "bloquearRoot", "onlydata", "onlyPlayStore",
    "blockOperator", "operatorname", "blockHwid", "hwidstring", "loginHwid",
    "blockwifi", "file.validade", "file.pedirLogin", "sshServer", "sshPort",
    "configlineinput", "udplineinput", "proxy_input", "keyPath", "TLS_VERSION",
    "sshUser", "sshPass", "sshPortaLocal", "tunnelType", "dnsForward",
    "dnsResolver1", "dnsResolver2", "udpserver", "udpauth", "udpobfs", "udpport",
    "udpversion", "udpdown", "udpup", "udpbuffer", "v2rayjson", "bhttpUploadSlots",
    "bhttpDownloadSlots", "bhttpBatch", "udpForward", "udpResolver", "wakelock",
    "proxyRemoto", "proxyRemotoPorta", "usarProxyAutenticacao", "protegerConfig",
    "protegerPayload", "protegerSni", "protegerServer", "protegerPort",
    "protegerUser", "protegerPass", "protegerProxy", "psiserverentry", "psiproxy",
    "psiregion", "psitimeout", "psiauth", "currentpsiprotocol", "currentpsiregion",
    "usarDefaultPayload", "optimizedMode", "proxyPayload", "chaveKey",
    "serverNameKey", "dnsKey", "dnsversion", "customSNI",
)
LINK_DICTIONARY = (
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
    '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n'
    '<properties>\n<comment>Archivo de Configuracion</comment>\n'
    + "".join(f'<entry key="{key}"></entry>\n' for key in DICTIONARY_KEYS)
    + "</properties>\n"
).encode("utf-8")

# UCS download (UcsDownload.fetch) — exact request the app makes.
UCS_USER_AGENT = "UltraCustom-UCS/1"
UCS_ACCEPT = "application/vnd.ultracustom.subscription, application/octet-stream, application/json"
UCS_DOMAIN = b"CloudServers/CSS1\n"


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _base64(text: str, *, urlsafe: bool = False) -> bytes:
    text = re.sub(r"[ \t\r\n]", "", text)
    alphabet = r"[A-Za-z0-9_-]+={0,2}" if urlsafe else r"[A-Za-z0-9+/]+={0,2}"
    if not re.fullmatch(alphabet, text) or len(text) % 4 == 1:
        raise DecodeError("FORMAT_ERROR", "Invalid Base64 profile.")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4),
                                altchars=b"-_" if urlsafe else None, validate=True)
    except (ValueError, binascii.Error):
        raise DecodeError("FORMAT_ERROR", "Invalid Base64 profile.") from None


def unmask(data: bytes) -> bytes:
    """Inverse of libx.so's byte transform (0x63ee0, decrypt flag 1)."""
    state = 0x91AC3F12
    mask_key = _mask_key()
    for value in mask_key:
        state ^= value
    out = bytearray(len(data))
    for index, value in enumerate(data):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        key = mask_key[(index + (state & 255)) % len(mask_key)]
        swapped = ((value >> 4) | (value << 4)) & 255
        out[index] = ((swapped - state) & 255) ^ key
    return bytes(out)


def mask(data: bytes) -> bytes:
    """Forward libx.so transform (0x63ee0, encrypt flag 0): inverse of unmask()."""
    state = 0x91AC3F12
    mask_key = _mask_key()
    for value in mask_key:
        state ^= value
    out = bytearray(len(data))
    for index, value in enumerate(data):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        key = mask_key[(index + (state & 255)) % len(mask_key)]
        unswapped = ((value ^ key) + state) & 255
        out[index] = ((unswapped >> 4) | (unswapped << 4)) & 255
    return bytes(out)


def _uaf2_decrypt(blob: bytes) -> bytes:
    """AES-256-GCM open of a UAF2 body (nonce[12] || ct || tag[16]), AAD '!UAF2=: '."""
    if len(blob) < 28:
        raise DecodeError("FORMAT_ERROR", "UAF2 payload too short (needs nonce + tag).")
    nonce, rest = blob[:12], blob[12:]
    cipher = AES.new(_uaf2_key(), AES.MODE_GCM, nonce=nonce)
    cipher.update(UAF2_AAD)
    try:
        return cipher.decrypt_and_verify(rest[:-16], rest[-16:])
    except ValueError:
        raise DecodeError("AUTH_FAILED", "UAF2 authentication failed (wrong key or damaged file).") from None


def uaf2_encode(plain: bytes) -> str:
    """Encode bytes as a UAF2 profile string (fresh random 12-byte nonce)."""
    if len(plain) > MAX_BYTES - 28:
        raise DecodeError("SIZE_LIMIT", "Profile exceeds 16 MiB.")
    nonce = secrets.token_bytes(12)
    cipher = AES.new(_uaf2_key(), AES.MODE_GCM, nonce=nonce)
    cipher.update(UAF2_AAD)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return UAF2_PREFIX + base64.urlsafe_b64encode(nonce + ciphertext + tag).decode("ascii").rstrip("=")


def _outer_decode(text: str) -> bytes:
    """NativeProtection.decodeProfile + legacy fallback (ConfigParser.decodeInput)."""
    if text.startswith(UAF2_PREFIX):
        body = text[len(UAF2_PREFIX):]
        # The native decoder stops at the first '=' (padding) and validates
        # the base64url length (len % 4 != 1).
        body = body.split("=", 1)[0]
        if len(body) % 4 == 1:
            raise DecodeError("FORMAT_ERROR", "Invalid UAF2 Base64URL length.")
        try:
            blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        except (ValueError, binascii.Error):
            raise DecodeError("FORMAT_ERROR", "Invalid UAF2 Base64URL.") from None
        return _uaf2_decrypt(blob)
    if ":" in text:
        # The native decoder throws "Formato de archivo de perfil
        # incompatible" for any other ':'-containing input.
        raise DecodeError("FORMAT_ERROR", "Unsupported profile format (unexpected ':' in input).")
    return unmask(_base64(text, urlsafe=True))


def _decrypt_password(data: bytes, password: str | None) -> bytes:
    if not data.startswith(b"UAP1"):
        return data
    if len(data) < 48:
        raise DecodeError("TRUNCATED", "Incomplete UAP1 header or GCM tag.")
    if password is None or password == "":
        raise DecodeError("PASSWORD_REQUIRED", "This profile requires its original export password.")
    try:
        encoded = password.encode("utf-8")
        if len(encoded) > 16384:
            raise DecodeError("SIZE_LIMIT", "Password exceeds 16 KiB of UTF-8.")
    except (AttributeError, UnicodeError):
        raise DecodeError("FORMAT_ERROR", "Password must be valid Unicode text.") from None
    key = hashlib.pbkdf2_hmac("sha256", encoded, data[4:20], 210000, 32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=data[20:32])
    cipher.update(data[:32])
    try:
        return cipher.decrypt_and_verify(data[32:-16], data[-16:])
    except ValueError:
        raise DecodeError("AUTH_FAILED", "Wrong password or damaged UAP1 profile.") from None


def _payload(data: bytes) -> tuple[bytes, str]:
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "Profile exceeds 16 MiB.")
    if data[:4] in (b"EXA1", b"UAB1"):
        inflater = zlib.decompressobj(-15, zdict=LINK_DICTIONARY)
        try:
            xml = inflater.decompress(data[4:], MAX_BYTES + 1)
        except zlib.error:
            raise DecodeError("COMPRESSION_ERROR", "Invalid raw DEFLATE profile or dictionary.") from None
        if len(xml) > MAX_BYTES or inflater.unconsumed_tail:
            raise DecodeError("SIZE_LIMIT", "Decompressed profile exceeds 16 MiB.")
        if not inflater.eof or inflater.unused_data:
            raise DecodeError("COMPRESSION_ERROR", "Truncated DEFLATE profile or trailing data.")
        return xml, data[:4].decode("ascii")
    if data.lstrip().startswith((b"<?xml", b"<properties")):
        return data, "XML"
    raise DecodeError("FORMAT_ERROR", "Expected XML, EXA1 or UAB1 after decoding.")


def _normalize_java_surrogate_references(text: str) -> str:
    """Combine Java XML exports' adjacent UTF-16 surrogate character references."""
    matches = iter(re.finditer(r"&#(?:[0-9]+|[xX][0-9A-Fa-f]+);", text))
    current = next(matches, None)
    chunks: list[str] = []
    last = 0

    def codepoint(match: re.Match[str]) -> int:
        token = match.group()
        if len(token) > 20:
            raise DecodeError("INVALID_XML", "Invalid numeric XML reference.")
        return int(token[3:-1], 16) if token[2] in "xX" else int(token[2:-1])

    while current is not None:
        value = codepoint(current)
        if 0xD800 <= value <= 0xDBFF:
            following = next(matches, None)
            if following is None or following.start() != current.end():
                raise DecodeError("INVALID_XML", "Unpaired Java UTF-16 surrogate reference.")
            low = codepoint(following)
            if not 0xDC00 <= low <= 0xDFFF:
                raise DecodeError("INVALID_XML", "Invalid Java UTF-16 surrogate pair.")
            scalar = 0x10000 + ((value - 0xD800) << 10) + (low - 0xDC00)
            chunks.extend((text[last:current.start()], f"&#{scalar};"))
            last = following.end()
            current = next(matches, None)
            continue
        if 0xDC00 <= value <= 0xDFFF:
            raise DecodeError("INVALID_XML", "Unpaired Java UTF-16 surrogate reference.")
        current = next(matches, None)
    chunks.append(text[last:])
    return "".join(chunks)


def _properties(data: bytes, budget: list[int]) -> tuple[dict[str, str], list[str]]:
    budget[0] -= len(data)
    if len(data) > MAX_BYTES or budget[0] < 0:
        raise DecodeError("SIZE_LIMIT", "Decoded XML exceeds its per-profile or aggregate limit.")
    try:
        text = data.decode("utf-8")
        if re.search(r"<!\s*ENTITY", text, re.I):
            raise ValueError
        text = re.sub(r'<!DOCTYPE\s+properties\s+SYSTEM\s+[\'"]http://java\.sun\.com/dtd/properties\.dtd[\'"]\s*>', "", text)
        if re.search(r"<!\s*DOCTYPE", text, re.I):
            raise ValueError
        text = re.sub(r'^\s*<\?xml\s+[^?]*\?>', "", text).strip()
        root = ET.fromstring(_normalize_java_surrogate_references(text.replace("\r", "&#13;")))
        if root.tag != "properties" or root.attrib or (root.text or "").strip():
            raise ValueError
        properties: dict[str, str] = {}
        comments: list[str] = []
        for child in root:
            if len(child) or (child.tail or "").strip():
                raise ValueError
            if child.tag == "comment" and not child.attrib:
                comments.append(child.text or "")
            elif child.tag == "entry" and set(child.attrib) == {"key"}:
                key = child.attrib["key"]
                if key in properties or len(properties) >= 100000:
                    raise ValueError
                properties[key] = child.text or ""
            else:
                raise ValueError
        return properties, comments
    except (ValueError, UnicodeError, ET.ParseError, RecursionError):
        raise DecodeError("INVALID_XML", "Expected UTF-8 Java Properties XML without duplicate keys or custom entities.") from None


def _embedded_json(value: str) -> Any:
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    def invalid(value):
        raise ValueError

    try:
        obj = json.loads(value, object_pairs_hook=unique, parse_constant=invalid)
        if not isinstance(obj, (dict, list)):
            return None
        stack, count = [(obj, 0)], 0
        while stack:
            node, depth = stack.pop()
            count += 1
            if depth > 64 or count + len(stack) > 100000:
                return None
            if isinstance(node, dict):
                stack.extend((key, depth + 1) for key in node)
                stack.extend((item, depth + 1) for item in node.values())
            elif isinstance(node, list):
                stack.extend((item, depth + 1) for item in node)
            elif isinstance(node, float) and not math.isfinite(node):
                return None
            elif isinstance(node, str):
                node.encode("utf-8")
        return obj
    except (ValueError, RecursionError, UnicodeError):
        return None


def _decode_xml(xml: bytes, password: str | None, budget: list[int], *,
                allow_bundle: bool = True, allow_wrapper: bool = False) -> dict[str, Any]:
    properties, comments = _properties(xml, budget)
    if "file.profilePasswordFormat" in properties:
        expected = {"file.profilePasswordFormat", "file.profileName", "file.passwordPayload"}
        if (not allow_wrapper or set(properties) != expected
                or properties["file.profilePasswordFormat"] != "1"):
            raise DecodeError("FORMAT_ERROR", "Invalid or nested password wrapper.")
        blob = _base64(properties["file.passwordPayload"])
        if not blob.startswith(b"UAP1"):
            raise DecodeError("FORMAT_ERROR", "Password wrapper must contain UAP1.")
        inner, _ = _payload(_decrypt_password(blob, password))
        profile = _decode_xml(inner, password, budget, allow_bundle=False)
        if profile["properties"].get("file.proteger") != "1":
            raise DecodeError("FORMAT_ERROR", "Protected bundle member must have file.proteger=1.")
        profile["passwordEnvelope"] = {"properties": properties, "comments": comments}
        return profile
    result: dict[str, Any] = {"type": "profile", "properties": properties, "comments": comments}
    if "file.bundleFormat" in properties:
        if not allow_bundle or properties["file.bundleFormat"] != "UA-BUNDLE-1":
            raise DecodeError("UNSUPPORTED_BUNDLE", "Unsupported or nested bundle format.")
        count_text = properties.get("file.profileCount", "")
        if not re.fullmatch(r"[0-9]{1,3}", count_text):
            raise DecodeError("FORMAT_ERROR", "Invalid bundle profile count.")
        count = int(count_text)
        expected = {"file.bundleFormat", "file.profileCount"} | {f"profile.{i}" for i in range(count)}
        if not 1 <= count <= MAX_PROFILES or set(properties) != expected:
            raise DecodeError("FORMAT_ERROR", "Bundle must contain exactly 1 to 100 indexed profiles.")
        result["type"] = "bundle"
        result["profiles"] = []
        for i in range(count):
            raw = properties[f"profile.{i}"]
            if not raw.strip():
                raise DecodeError("FORMAT_ERROR", "Bundle contains an empty profile.")
            result["profiles"].append(_decode_xml(raw.encode("utf-8"), password, budget,
                                                    allow_bundle=False, allow_wrapper=True))
    elif "v2rayjson" in properties:
        parsed = _embedded_json(properties["v2rayjson"])
        if parsed is not None:
            result["embeddedJson"] = {"v2rayjson": parsed}
    return result


def decode(data: bytes | str, *, password: str | None = None) -> dict[str, Any]:
    """Decode a .ua file, a ua:// link, or a UAF2/legacy profile string.

    Mirrors ConfigParser.decodeInput: UAF2 (native AES-256-GCM) first, legacy
    libx unmask fallback, then UAP1 password layer, then EXA1/UAB1/XML payload.
    Failure in any bundle member aborts the whole result. Import-policy flags
    remain visible but are not executed. Unpassworded files are not authenticated.
    """
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Expected .ua bytes or ua:// text.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    except UnicodeError:
        raise DecodeError("FORMAT_ERROR", "Expected UTF-8 Base64URL input.") from None
    text = text.strip()
    if text.startswith("ua://"):
        text = text[5:].strip()
        if not text:
            raise DecodeError("FORMAT_ERROR", "Empty ua:// link.")
    outer = _outer_decode(text)
    protected = outer.startswith(b"UAP1")
    xml, payload_format = _payload(_decrypt_password(outer, password))
    result = _decode_xml(xml, password, [MAX_TOTAL_XML_BYTES])
    result["encoding"] = {"transport": "ua-base64url" if not text.startswith(UAF2_PREFIX) else "uaf2",
                          "payload": payload_format,
                          "passwordProtected": protected}
    return result


# --- UCS subscription catalog (UcsCodec / UcsDownload) ------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _https_url(url: str) -> str:
    """UcsDownload.https: HTTPS only, <= 2048 chars, no userinfo/fragment."""
    if url is None or len(url) > 2048:
        raise DecodeError("INVALID_URL", "Subscription URL must be an HTTPS URL up to 2048 chars.")
    try:
        parsed = urllib.parse.urlparse(url.strip())
    except ValueError:
        raise DecodeError("INVALID_URL", "Invalid subscription URL.") from None
    if (parsed.scheme.lower() != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or (parsed.port or 0) > 65535):
        raise DecodeError("INVALID_URL", "Subscription URL must be a direct HTTPS URL without credentials or fragment.")
    return parsed.geturl()


def fetch_ucs(url: str, *, ssl_context: ssl.SSLContext | None = None) -> bytes:
    """Fetch a UCS subscription document exactly like UcsDownload.fetch.

    Plain GET, no cookies/caches, up to 5 manual redirects, 15 s connect /
    20 s read timeouts, max 16 MiB. 404/410 is gone; HTML bodies are rejected.
    """
    current = _https_url(url)
    if ssl_context is None:
        ssl_context = ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl_context))
    for _hop in range(6):
        request = urllib.request.Request(current, method="GET")
        request.add_header("Cache-Control", "no-cache, no-store, max-age=0")
        request.add_header("Pragma", "no-cache")
        request.add_header("Accept", UCS_ACCEPT)
        request.add_header("User-Agent", UCS_USER_AGENT)
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            if error.code in (404, 410):
                raise DecodeError("GONE", "The subscription file is no longer available (HTTP %d)." % error.code) from None
            if error.code in (301, 302, 303, 307, 308):
                location = error.headers.get("Location")
                if location is None or _hop == 5:
                    raise DecodeError("FETCH_ERROR", "Too many redirects.") from None
                current = _https_url(urllib.parse.urljoin(current, location))
                continue
            raise DecodeError("FETCH_ERROR", "Could not download the subscription (HTTP %d)." % error.code) from None
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, http.client.HTTPException) as error:
            raise DecodeError("FETCH_ERROR", "Could not download the subscription: %s" % error) from None
        with response:
            if response.status != 200:
                raise DecodeError("FETCH_ERROR", "Could not download the subscription (HTTP %d)." % response.status)
            content_type = (response.headers.get("Content-Type") or "").lower()
            if "text/html" in content_type or "application/xhtml" in content_type:
                raise DecodeError("FETCH_ERROR", "The link shows a web page. Use the direct download URL of the subscription file.")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "Subscription file exceeds 16 MiB.")
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise DecodeError("SIZE_LIMIT", "Subscription file exceeds 16 MiB.")
            if body[:128].decode("utf-8", "ignore").strip().startswith("<"):
                raise DecodeError("FETCH_ERROR", "The link returns HTML. Use the direct download URL of the subscription file.")
            return body
    raise DecodeError("FETCH_ERROR", "Could not follow the subscription link.")


# --- Minimal DER + P-256 ECDSA verification (stdlib only) ---------------------

_P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256 - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _der_read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise DecodeError("INVALID_UCS", "Truncated DER value.")
    tag, first = data[offset], data[offset + 1]
    if first & 0x80:
        nbytes = first & 0x7F
        if nbytes == 0 or nbytes > 4 or offset + 2 + nbytes > len(data):
            raise DecodeError("INVALID_UCS", "Invalid DER length.")
        length = int.from_bytes(data[offset + 2:offset + 2 + nbytes], "big")
        start = offset + 2 + nbytes
    else:
        length, start = first, offset + 2
    if start + length > len(data):
        raise DecodeError("INVALID_UCS", "Truncated DER value.")
    return tag, data[start:start + length], start + length


def _der_children(data: bytes) -> list[tuple[int, bytes]]:
    children, offset = [], 0
    while offset < len(data):
        tag, value, offset = _der_read(data, offset)
        children.append((tag, value))
    return children


def _ec_point_add(p: tuple[int, int] | None, q: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P256 == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256) % _P256
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256) % _P256
    x3 = (lam * lam - x1 - x2) % _P256
    return x3, (lam * (x1 - x3) - y1) % _P256


def _ec_scalar_mul(k: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while k:
        if k & 1:
            result = _ec_point_add(result, addend)
        addend = _ec_point_add(addend, addend)
        k >>= 1
    return result


def _ecdsa_verify_p256(pub_x: int, pub_y: int, message: bytes, r: int, s: int) -> bool:
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    w = pow(s, -1, _P256_N)
    u1 = z * w % _P256_N
    u2 = r * w % _P256_N
    point = _ec_point_add(_ec_scalar_mul(u1, (_P256_GX, _P256_GY)),
                          _ec_scalar_mul(u2, (pub_x, pub_y)))
    return point is not None and point[0] % _P256_N == r


def _parse_spki_p256(der: bytes) -> tuple[int, int]:
    try:
        tag, value, _end = _der_read(der, 0)
        if tag != 0x30:
            raise ValueError
        outer = _der_children(value)
        if len(outer) != 2 or outer[0][0] != 0x30 or outer[1][0] != 0x03:
            raise ValueError
        bitstring = outer[1][1]
        if len(bitstring) != 66 or bitstring[0] != 0 or bitstring[1] != 0x04:
            raise ValueError
        x = int.from_bytes(bitstring[2:34], "big")
        y = int.from_bytes(bitstring[34:66], "big")
        if not (0 <= x < _P256 and 0 <= y < _P256):
            raise ValueError
        if (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256 != 0:
            raise ValueError
        return x, y
    except (ValueError, IndexError):
        raise DecodeError("INVALID_UCS", "Public key is not an EC P-256 key.") from None


def _parse_ecdsa_signature(der: bytes) -> tuple[int, int]:
    try:
        outer = _der_children(der)
        if len(outer) != 1 or outer[0][0] != 0x30:
            raise ValueError
        parts = _der_children(outer[0][1])
        if len(parts) != 2 or parts[0][0] != 0x02 or parts[1][0] != 0x02:
            raise ValueError
        return int.from_bytes(parts[0][1], "big"), int.from_bytes(parts[1][1], "big")
    except (ValueError, IndexError):
        raise DecodeError("INVALID_UCS", "Invalid ECDSA signature.") from None


def _ucs_base64(value: Any, max_decoded: int, name: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > ((max_decoded + 2) // 3) * 4:
        raise DecodeError("INVALID_UCS", "Invalid UCS size: %s." % name)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise DecodeError("INVALID_UCS", "Invalid UCS Base64: %s." % name) from None
    if len(decoded) > max_decoded:
        raise DecodeError("INVALID_UCS", "Invalid UCS size: %s." % name)
    return decoded


def _ucs_object(text: str) -> dict[str, Any]:
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        raise DecodeError("INVALID_UCS", "Invalid UCS JSON.") from None
    if not isinstance(obj, dict):
        raise DecodeError("INVALID_UCS", "Invalid UCS JSON.")
    return obj


def verify_ucs(data: bytes) -> dict[str, Any]:
    """Verify a CSS1 subscription document and return its decoded payload.

    Mirrors UcsCodec.decode: ECDSA P-256 (SHA256withECDSA) over
    b"CloudServers/CSS1\\n" + payload bytes, verified against the embedded
    public key. Returns {"payload": <inner JSON dict>, "public_key_b64": str,
    "payload_bytes": bytes}. Raises DecodeError on any mismatch.
    """
    if not data or len(data) > MAX_BYTES:
        raise DecodeError("INVALID_UCS", "Invalid UCS file size.")
    try:
        outer_text = data.decode("utf-8")
    except UnicodeError:
        raise DecodeError("INVALID_UCS", "Invalid UCS UTF-8.") from None
    outer = _ucs_object(outer_text)
    if outer.get("format") == "CSP1":
        raise DecodeError("INVALID_UCS", "This file is a provisional Placeholder. The creator must publish the final subscription.")
    if outer.get("format") != "CSS1":
        raise DecodeError("INVALID_UCS", "Unsupported Cloud Servers format.")
    payload = _ucs_base64(outer.get("payload"), MAX_BYTES, "payload")
    public_key_der = _ucs_base64(outer.get("public_key"), 512, "public key")
    signature_der = _ucs_base64(outer.get("signature"), 256, "signature")
    pub_x, pub_y = _parse_spki_p256(public_key_der)
    r, s = _parse_ecdsa_signature(signature_der)
    if not _ecdsa_verify_p256(pub_x, pub_y, UCS_DOMAIN + payload, r, s):
        raise DecodeError("INVALID_UCS", "Invalid UCS signature.")
    try:
        payload_text = payload.decode("utf-8")
    except UnicodeError:
        raise DecodeError("INVALID_UCS", "Invalid UCS payload UTF-8.") from None
    return {"payload": _ucs_object(payload_text),
            "public_key_b64": base64.b64encode(public_key_der).decode("ascii"),
            "payload_bytes": payload}


def _ucs_string(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise DecodeError("INVALID_UCS", "UCS text required: %s." % key)
    return value


def _ucs_bool(obj: dict[str, Any], key: str) -> bool:
    value = obj.get(key)
    if not isinstance(value, bool):
        raise DecodeError("INVALID_UCS", "UCS boolean required: %s." % key)
    return value


def _ucs_int(obj: dict[str, Any], key: str, low: int, high: int) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise DecodeError("INVALID_UCS", "UCS integer out of range: %s." % key)
    return value


def parse_ucs_document(payload: dict[str, Any], payload_text: str) -> dict[str, Any]:
    """Validate an inner UCS payload (UcsCodec.document) and return it as a dict."""
    import uuid as _uuid
    doc_id = _ucs_string(payload, "id")
    try:
        if len(doc_id) != 36 or str(_uuid.UUID(doc_id)) != doc_id.lower():
            raise ValueError
    except (ValueError, AttributeError):
        raise DecodeError("INVALID_UCS", "Invalid UCS identifier.") from None
    title = _ucs_string(payload, "title")
    if not title.strip() or len(title) > 120:
        raise DecodeError("INVALID_UCS", "Invalid UCS title length.")
    note = payload.get("note", "")
    if note is None:
        note = ""
    if not isinstance(note, str) or len(note) > 2000:
        raise DecodeError("INVALID_UCS", "Invalid UCS note.")
    update_url = _ucs_string(payload, "update_url")
    _https_url(update_url)
    status = _ucs_string(payload, "status")
    if status not in ("active", "disabled"):
        raise DecodeError("INVALID_UCS", "Invalid UCS status.")
    revision = _ucs_int(payload, "revision", 1, 1 << 63 - 1)
    refresh_minutes = _ucs_int(payload, "refresh_minutes", 1, 1440)
    expires_at = _ucs_int(payload, "expires_at", 0, 1 << 63 - 1)
    hwids = payload.get("hwids")
    if not isinstance(hwids, list) or len(hwids) > 100:
        raise DecodeError("INVALID_UCS", "Too many HWIDs.")
    seen_hwid: set[str] = set()
    for hwid in hwids:
        if not isinstance(hwid, str) or not hwid.strip() or len(hwid) > 256 or hwid in seen_hwid:
            raise DecodeError("INVALID_UCS", "Invalid HWID.")
        seen_hwid.add(hwid)
    servers = payload.get("servers")
    if not isinstance(servers, list) or len(servers) > 100 or (status == "active" and not servers):
        raise DecodeError("INVALID_UCS", "An active subscription requires 1 to 100 servers.")
    parsed_servers = []
    seen_id: set[str] = set()
    for server in servers:
        if not isinstance(server, dict):
            raise DecodeError("INVALID_UCS", "Invalid UCS server.")
        server_id = _ucs_string(server, "id")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", server_id) or server_id in seen_id:
            raise DecodeError("INVALID_UCS", "Invalid or duplicate server identifier.")
        seen_id.add(server_id)
        name = _ucs_string(server, "name")
        if not name.strip() or len(name) > 120:
            raise DecodeError("INVALID_UCS", "Invalid UCS server name length.")
        profile_payload = _ucs_string(server, "profile_payload")
        if not profile_payload.strip() or len(profile_payload) > MAX_BYTES:
            raise DecodeError("INVALID_UCS", "Empty or oversized UCS profile.")
        parsed_servers.append({"id": server_id, "name": name, "profile_payload": profile_payload})
    return {"id": doc_id, "title": title, "note": note, "update_url": update_url,
            "status": status, "revision": revision, "refresh_minutes": refresh_minutes,
            "expires_at": expires_at, "block_root": _ucs_bool(payload, "block_root"),
            "mobile_only": _ucs_bool(payload, "mobile_only"),
            "login_hwid": _ucs_bool(payload, "login_hwid"),
            "hwids": list(hwids), "servers": parsed_servers,
            "payload": payload_text}


def decode_ucs(data: bytes, *, password: str | None = None) -> dict[str, Any]:
    """Verify a UCS document and decode every server's profile_payload."""
    verified = verify_ucs(data)
    document = parse_ucs_document(verified["payload"], verified["payload_bytes"].decode("utf-8"))
    document["public_key"] = verified["public_key_b64"]
    servers = []
    for server in document["servers"]:
        entry: dict[str, Any] = {"id": server["id"], "name": server["name"]}
        try:
            entry["profile"] = decode(server["profile_payload"], password=password)
        except DecodeError as error:
            entry["profile_error"] = {"code": error.code, "message": str(error)}
        servers.append(entry)
    document["servers"] = servers
    return document


def fetch_and_decode_ucs(url: str, *, password: str | None = None,
                         ssl_context: ssl.SSLContext | None = None) -> dict[str, Any]:
    """Download a UCS subscription (exact app request) and decode it."""
    return decode_ucs(fetch_ucs(url, ssl_context=ssl_context), password=password)


def run(file_bytes: bytes | str, *, password: str | None = None) -> str | None:
    try:
        return json.dumps(decode(file_bytes, password=password), ensure_ascii=False, indent=2) + "\n"
    except DecodeError:
        return None


def _read_password(args: argparse.Namespace) -> str | None:
    if args.password_file is not None:
        with args.password_file.open("rb") as handle:
            raw_password = handle.read(16387)
        if raw_password.endswith(b"\r\n"):
            raw_password = raw_password[:-2]
        elif raw_password.endswith(b"\n"):
            raw_password = raw_password[:-1]
        if len(raw_password) > 16384:
            raise DecodeError("SIZE_LIMIT", "Password exceeds 16 KiB of UTF-8.")
        try:
            return raw_password.decode("utf-8")
        except UnicodeError:
            raise DecodeError("FORMAT_ERROR", "Password file must be UTF-8.") from None
    if args.ask_password:
        return getpass.getpass("Export password: ")
    return None


def _self_test() -> int:
    if not os.environ.get("ULTRA_CUSTOM_UAF2_KEY_HEX") and not os.environ.get("ULTRA_CUSTOM_MASK_KEY_HEX"):
        os.environ["ULTRA_CUSTOM_TEST_KEYS"] = "1"
    failures = []

    def check(name: str, fn) -> None:
        try:
            fn()
            print("ok: %s" % name)
        except Exception as error:  # noqa: BLE001 - self-test reports everything
            failures.append(name)
            print("FAIL: %s: %s" % (name, error))

    sample = Path(__file__).with_name("Guatemala_Tigo__1__7_fy55.ua")
    if sample.exists():
        def _sample() -> None:
            result = decode(sample.read_bytes())
            props = result["properties"]
            assert props["file.profileName"] == "Guatemala Tigo", props.get("file.profileName")
            assert props["file.appVersionCode"] == "157"
            assert result["encoding"]["payload"] == "XML"
        check("real sample Guatemala_Tigo decodes (UAF2)", _sample)
    else:
        print("skip: real sample not next to the script")

    def _uaf2_roundtrip() -> None:
        xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<properties>\n'
               '<entry key="file.profileName">Test</entry>\n'
               '<entry key="sshServer">example.invalid</entry>\n</properties>\n').encode()
        assert decode(uaf2_encode(xml))["properties"]["file.profileName"] == "Test"
        assert decode(uaf2_encode(xml))["properties"]["sshServer"] == "example.invalid"
    check("UAF2 encode -> decode round-trip", _uaf2_roundtrip)

    def _legacy_roundtrip() -> None:
        xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<properties>\n'
               '<entry key="file.profileName">Legacy</entry>\n</properties>\n').encode()
        inflater = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=LINK_DICTIONARY)
        blob = b"EXA1" + inflater.compress(xml) + inflater.flush()
        text = base64.urlsafe_b64encode(mask(blob)).decode().rstrip("=")
        assert decode(text)["properties"]["file.profileName"] == "Legacy"
        assert decode("ua://" + text)["properties"]["file.profileName"] == "Legacy"
    check("legacy unmask + EXA1 round-trip (+ ua://)", _legacy_roundtrip)

    def _uap1_roundtrip() -> None:
        xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<properties>\n'
               '<entry key="file.profileName">Locked</entry>\n</properties>\n').encode()
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = hashlib.pbkdf2_hmac("sha256", b"pw123", salt, 210000, 32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        header = b"UAP1" + salt + nonce
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(xml)
        blob = header + ciphertext + tag
        assert decode(uaf2_encode(blob), password="pw123")["properties"]["file.profileName"] == "Locked"
        try:
            decode(uaf2_encode(blob))
            raise AssertionError("password was not required")
        except DecodeError as error:
            assert error.code == "PASSWORD_REQUIRED", error.code
    check("UAP1 password round-trip inside UAF2", _uap1_roundtrip)

    def _ucs_roundtrip() -> None:
        # Synthetic signed subscription (fresh EC P-256 key, test-only): one
        # server carrying a UAF2 profile; verify + parse + decode end to end.
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        private = ec.generate_private_key(ec.SECP256R1())
        public_der = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        inner = {"id": "12345678-1234-4234-8234-123456789abc", "title": "Test sub",
                 "note": "", "update_url": "https://example.invalid/sub.ucs",
                 "status": "active", "revision": 3, "refresh_minutes": 60,
                 "expires_at": 0, "block_root": False, "mobile_only": False,
                 "login_hwid": False, "hwids": [],
                 "servers": [{"id": "srv1", "name": "Guatemala Tigo",
                              "profile_payload": uaf2_encode(
                                  ('<?xml version="1.0" encoding="UTF-8"?>\n<properties>\n'
                                   '<entry key="file.profileName">Guatemala Tigo</entry>\n'
                                   '</properties>\n').encode())}]}
        payload = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()
        signature = private.sign(UCS_DOMAIN + payload, ec.ECDSA(hashes.SHA256()))
        outer = {"format": "CSS1", "payload": base64.b64encode(payload).decode(),
                 "public_key": base64.b64encode(public_der).decode(),
                 "signature": base64.b64encode(signature).decode()}
        doc = decode_ucs(json.dumps(outer).encode())
        assert doc["title"] == "Test sub" and doc["revision"] == 3
        assert doc["servers"][0]["profile"]["properties"]["file.profileName"] == "Guatemala Tigo"
        tampered = dict(outer)
        tampered["payload"] = base64.b64encode(payload[:-1] + b" ").decode()
        try:
            decode_ucs(json.dumps(tampered).encode())
            raise AssertionError("tampered payload was accepted")
        except DecodeError as error:
            assert error.code == "INVALID_UCS", error.code
    check("UCS sign -> verify -> decode round-trip (synthetic)", _ucs_roundtrip)

    print("%d self-test(s) failed" % len(failures) if failures else "all self-tests passed")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode Ultra Custom 15.7 .ua files, ua:// links, bundles and .ucs subscriptions offline.")
    parser.add_argument("file", nargs="?", type=Path,
                        help=".ua file, .ucs subscription file, or text file containing ua://...")
    parser.add_argument("--url", help="Fetch, verify and decode a UCS subscription URL (HTTPS)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ask-password", action="store_true", help="Prompt privately for the original export password")
    group.add_argument("--password-file", type=Path, help="UTF-8 password file; removes one final LF or CRLF")
    parser.add_argument("-o", "--output", type=Path, help="Save complete JSON instead of printing it")
    parser.add_argument("--self-test", action="store_true", help="Run the built-in round-trip tests")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            return _self_test()
        password = _read_password(args)
        if args.url is not None:
            result = fetch_and_decode_ucs(args.url, password=password)
        elif args.file is not None:
            with args.file.open("rb") as handle:
                raw = handle.read(MAX_BYTES + 1)
            text = raw.decode("utf-8-sig", "replace")
            if text.lstrip().startswith("{"):
                result = decode_ucs(raw, password=password)
            else:
                result = decode(raw, password=password)
        else:
            parser.error("a file or --url is required")
        output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output is not None:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0
    except DecodeError as error:
        print(json.dumps({"error": error.code, "message": str(error)}), file=sys.stderr)
        return 1
    except (OSError, EOFError):
        print(json.dumps({"error": "IO_ERROR", "message": "Cannot read input/password or write output."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
