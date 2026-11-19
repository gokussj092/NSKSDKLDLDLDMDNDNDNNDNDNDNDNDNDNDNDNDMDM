"""SSC Custom (.ssc / ssc://) oracle: independent re-implementation.

Mirrors the algorithm of the server decoder decoders/Python/SSCCUSTOM.py
(three fixed ChaCha20 keys, original 64-bit nonce / 64-bit counter,
counter starting at 1) WITHOUT importing it, so it can serve as an
independent cross-check. verify.py runs both this oracle and the real
server decoder on the same fixtures and requires them to agree.

Format (observed from SSCCUSTOM.py + the A23 golden generator):
  file bytes = UTF-8 text, optionally prefixed with "ssc://" (in which
  case the remainder is reversed), otherwise a hex string (whitespace
  is ignored) of the L1 ciphertext.
  L1: ChaCha20(key=L1_KEY, nonce=FIXED_NONCE, counter=1) -> JSON text.
  Single layer: L1 JSON has "a" = list of config objects.
  Two layers:  L1 JSON has "a" = 16 hex chars (L2 nonce, 8 bytes) and
               "c" = hex of the L2 ciphertext; L2 is ChaCha20(L2_KEY,
               that nonce, counter=1) -> JSON text with "a" = configs.
  Inner fields: in a config object, "b" is a 32-char hex user key.
               inner nonce = hex-decode(reverse(user_key[16:32]) + "68"
               + user_key[0:16])[:8]; fields g,h,l,o,p,v,x,i,w that are
               hex strings longer than 16 chars are ChaCha20(L3_KEY,
               inner nonce, counter=1) decrypted, cut at the first NUL.
  Key map: single letters -> readable names (see KEY_MAP).

All constants below are app-embedded format constants already present
in this repo (SSCCUSTOM.py, SscPort.kt). They are NOT user credentials,
accounts or tokens. Fixtures use only RFC 2606 example.org and dummy
values; no real server, user or password appears anywhere here.
"""
from __future__ import annotations

import json
import re
import struct
from typing import Any, Dict, Optional

from Crypto.Cipher import ChaCha20

FIXED_NONCE: bytes = struct.pack("<Q", 0xF7479D9F87F3D074)
L1_KEY: bytes = bytes.fromhex(
    "c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b")
L2_KEY: bytes = bytes.fromhex(
    "7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e")
L3_KEY: bytes = bytes.fromhex(
    "d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e")

KEY_MAP: Dict[str, str] = {
    "a": "CONFIGS", "b": "NOTE", "c": "EXPIRY DATE", "e": "CONFIGNAME",
    "f": "PAYLOAD ENABLED", "g": "PAYLOAD", "h": "PROXY", "i": "PROXY PORT",
    "j": "TYPE", "k": "PROXY ENABLED", "l": "ADDRESS", "m": "PORT",
    "n": "IS PREMIUM", "o": "USERNAME", "p": "PASSWORD", "q": "TIMEOUT",
    "r": "PROTOCOL", "s": "VERSION", "t": "ENCRYPTION", "u": "COMPRESSIONLEVEL",
    "v": "DNS", "w": "NSSERVER", "x": "PUBKEY", "y": "ISDEFAULT",
    "z": "LOCALPORT",
}

ENCRYPTED_FIELDS = {"g", "h", "l", "o", "p", "v", "x", "i", "w"}

_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?")
_USERPASS_RE = re.compile(r"^[a-zA-Z0-9!@#$%^&*()._-]+")


def chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20, original 64-bit nonce, block counter starting at 1."""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(64)  # one 64-byte block -> counter = 1
    return cipher.decrypt(data)


def encrypt_layer1(plain_json: bytes) -> bytes:
    """Forward encryption: returns the hex text of a single-layer .ssc."""
    return chacha20(L1_KEY, FIXED_NONCE, plain_json).hex().encode("ascii")


def encrypt_layer2(plain_json: bytes, nonce_hex16: str) -> str:
    """Forward encryption of the L2 payload; returns hex ciphertext."""
    nonce = bytes.fromhex(nonce_hex16)
    assert len(nonce) == 8
    return chacha20(L2_KEY, nonce, plain_json).hex()


def encrypt_inner_field(user_key: str, plaintext: str) -> str:
    """Forward encryption of one L3 inner field; returns hex ciphertext."""
    nonce = derive_inner_nonce(user_key)
    assert nonce is not None
    return chacha20(L3_KEY, nonce, plaintext.encode("utf-8")).hex()


def derive_inner_nonce(user_key: str) -> Optional[bytes]:
    if not user_key or len(user_key) != 32:
        return None
    return bytes.fromhex(f"{user_key[16:32][::-1]}68{user_key[0:16]}")[:8]


def _decode_cstring(b: bytes) -> str:
    if not b:
        return ""
    b = b.split(b"\x00")[0]
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError as e:
        return b[:e.start].decode("utf-8", errors="ignore")


def _sanitize_field(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    value = "".join(c for c in value if ord(c) >= 32)
    if key in {"ADDRESS", "DNS", "H", "NSSERVER"}:
        if match := _IP_RE.search(value):
            return match.group(0)
        return "".join(c for c in value if c.isalnum() or c in ".-_")
    if key in {"USERNAME", "PASSWORD"}:
        if value.isalnum():
            return value
        if match := _USERPASS_RE.match(value):
            return match.group(0)
    if key == "PAYLOAD":
        return value.split("\x00")[0] if "[crlf]" in value else value.strip()
    return value.strip()


def _clean_json(text_bytes: bytes) -> Optional[Dict]:
    if not text_bytes:
        return None
    try:
        text = text_bytes.decode("utf-8", errors="ignore").split("\x00")[0]
        if (start := text.find("{")) != -1 and (end := text.rfind("}")) != -1:
            candidate = text[start:end + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError as e:
                if e.msg.startswith("Extra data"):
                    return json.loads(candidate[:e.pos])
    except Exception:
        return None
    return None


def _process_configs(json_obj: Dict) -> Dict:
    if isinstance(configs := json_obj.get("a"), list):
        processed = []
        for item in configs:
            if user_key := item.get("b"):
                if inner_nonce := derive_inner_nonce(user_key):
                    for field in ENCRYPTED_FIELDS.intersection(item.keys()):
                        enc_val = item[field]
                        if isinstance(enc_val, str) and len(enc_val) > 16:
                            try:
                                dec_bytes = chacha20(
                                    L3_KEY, inner_nonce,
                                    bytes.fromhex(enc_val))
                                plain = _decode_cstring(dec_bytes)
                                item[field] = (
                                    "".join(c for c in plain
                                            if c.isalnum() or c in ".-:_")
                                    if field in {"l", "v", "w", "h"}
                                    else plain)
                            except Exception:
                                pass
            new_item = {}
            for k, v in item.items():
                new_key = KEY_MAP.get(k, k)
                new_val = _sanitize_field(new_key, v)
                if new_val == "" and k in ENCRYPTED_FIELDS:
                    continue
                new_item[new_key] = new_val
            processed.append(new_item)
        json_obj["a"] = processed
    return json_obj


def decode_mapped(file_bytes: bytes) -> Optional[Dict]:
    """Decode to the mapped JSON object (no SP-DECODE banner)."""
    try:
        content = file_bytes.decode("utf-8-sig", errors="ignore").strip()
        if content.startswith("ssc://"):
            content = content[6:][::-1]
        if len(cipher_hex := "".join(content.split())) % 2 != 0:
            return None
        l1_data = chacha20(L1_KEY, FIXED_NONCE, bytes.fromhex(cipher_hex))
        if not (l1_json := _clean_json(l1_data)):
            return None
        target_json = None
        if "c" in l1_json and isinstance(l1_json.get("a"), str):
            l2_nonce = bytes.fromhex(l1_json["a"][:16])
            l2_data = chacha20(L2_KEY, l2_nonce, bytes.fromhex(l1_json["c"]))
            if l2_json := _clean_json(l2_data):
                target_json = {
                    KEY_MAP.get(k, k):
                        _sanitize_field(KEY_MAP.get(k, k), v)
                        if k != "a" else v
                    for k, v in l2_json.items()
                }
        elif "a" in l1_json and isinstance(l1_json["a"], list):
            target_json = l1_json
        if target_json:
            final_struct = _process_configs(target_json)
            return {
                KEY_MAP.get(k, k):
                    v if k in {"a", "CONFIGS"} and isinstance(v, list)
                    else _sanitize_field(KEY_MAP.get(k, k), v)
                for k, v in final_struct.items()
            }
    except Exception:
        return None
    return None
