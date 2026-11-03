#!/usr/bin/env python3
"""Standalone SP-DECODE Telegram bot decoder, adapted from authorized 66.py.

No Telegram handlers, network access, or third-party requests are performed.
This engine is imported on demand by the bot's central extension registry.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import logging
import re
import struct
import zlib
from pathlib import Path
import sys
from typing import Any
from xml.etree import ElementTree as ET
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger = logging.getLogger(__name__)
MAX_INPUT_BYTES = 2 * 1024 * 1024

IZPH_BASE_MATERIAL = bytes([
    0x89, 0x68, 0xCB, 0x6E, 0x89, 0x51, 0x05, 0xBE,
    0x62, 0x58, 0x39, 0xAD, 0x9B, 0x9B, 0xA6, 0xAC,
    0xE8, 0xDC, 0xD4, 0x41, 0x3D, 0x7C, 0x5E, 0xCF,
    0xAA, 0x10, 0x69, 0x41, 0x3F, 0xFE, 0xB0, 0x44
])

IZPH_FIXED_IV = bytes([
    0x49, 0xE5, 0x9F, 0xDF, 0x67, 0xEB, 0x47, 0x9C,
    0xE8, 0xB9, 0x6C, 0x24, 0xD2, 0x49, 0x5B, 0xD1
])

IZPH_FIXED_SALT = bytes([
    0xC2, 0x7F, 0xD7, 0xBE, 0xE1, 0x71, 0x96, 0xD6, 0x50,
    0x53, 0x08, 0x86, 0xCF, 0x4C, 0x24, 0xF5, 0x2C, 0xAC,
    0x5A, 0xBB, 0x8B, 0xFF, 0x6A, 0xD3, 0xA4, 0x8E, 0xBB,
    0x10, 0xF4, 0xB1, 0xF6, 0x32
])

# Derived keys
IZPH_SHA256_KEY_16 = hashlib.sha256(IZPH_BASE_MATERIAL).digest()[:16]
IZPH_HKDF_KEY_16 = None
IZPH_HKDF_KEY_32 = None
IZPH_PBKDF2_KEY_32 = None

# Algorithm constants (XXTEA, Threefish)
IZPH_MASK64 = 0xFFFFFFFFFFFFFFFF
IZPH_DELTA = 0x7A56D3E1
IZPH_THREEFISH_C240 = 0x1BD11BDAA9FC1A22
IZPH_THREEFISH256_ROTATIONS = ((14,16),(52,57),(23,40),(5,37),(25,33),(46,12),(58,22),(32,32))
IZPH_THREEFISH256_PERMUTE = (0,3,2,1)
IZPH_THREEFISH256_INV_PERMUTE = (0,3,2,1)

IZPH_SKEIN_OK = True  # self-contained Threefish-256 from source

class IZPHError(Exception):
    pass

# ----- Helper functions (XXTEA, Threefish, AES) -----
def izph_pkcs7_unpad(data: bytes) -> bytes:
    if not data: raise IZPHError("empty")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad])*pad:
        raise IZPHError("bad padding")
    return data[:-pad]

def izph_hkdf_sha256(ikm: bytes, salt: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    prev = b""
    c = 1
    while len(out) < length:
        prev = hmac.new(prk, prev + bytes([c]), hashlib.sha256).digest()
        out += prev
        c += 1
    return out[:length]

def izph_pbkdf2_sha256(pwd: bytes, salt: bytes, it: int = 100000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pwd, salt, it, dklen)

def izph_get_hkdf_key() -> bytes:
    global IZPH_HKDF_KEY_32
    if IZPH_HKDF_KEY_32 is None:
        IZPH_HKDF_KEY_32 = izph_hkdf_sha256(IZPH_BASE_MATERIAL, IZPH_FIXED_SALT, 32)
    return IZPH_HKDF_KEY_32

def izph_get_hkdf_key_16() -> bytes:
    global IZPH_HKDF_KEY_16
    if IZPH_HKDF_KEY_16 is None:
        IZPH_HKDF_KEY_16 = izph_hkdf_sha256(IZPH_BASE_MATERIAL, IZPH_FIXED_SALT[:16], 16)
    return IZPH_HKDF_KEY_16

def izph_get_pbkdf2_key() -> bytes:
    global IZPH_PBKDF2_KEY_32
    if IZPH_PBKDF2_KEY_32 is None:
        IZPH_PBKDF2_KEY_32 = izph_pbkdf2_sha256(IZPH_BASE_MATERIAL, IZPH_FIXED_SALT, 100000, 32)
    return IZPH_PBKDF2_KEY_32

def izph_clean_base64(text: str) -> str:
    cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    if len(cleaned) % 4:
        cleaned += '=' * (4 - len(cleaned) % 4)
    return cleaned

def izph_base64_decode_android(text: str) -> bytes:
    s = izph_clean_base64(text)
    if not s:
        return b""
    try:
        return base64.b64decode(s, validate=False)
    except Exception as e:
        raise IZPHError(f"b64 fail: {e}")

def izph_bytes_to_text(b: bytes) -> str | None:
    try:
        return b.decode("utf-8")
    except:
        return None

def izph_strip_scheme(text: str) -> str:
    return text.strip().rsplit("://", 1)[-1]

def izph_ror64(v: int, c: int) -> int:
    return ((v >> c) | (v << (64 - c))) & IZPH_MASK64

# XXTEA
def izph_xxtea_to_uint32(data: bytes, incl_len: bool) -> list:
    wc = (len(data) + 3) // 4
    res = [0] * (wc + (1 if incl_len else 0))
    for i, b in enumerate(data):
        res[i >> 2] |= b << ((i & 3) << 3)
    if incl_len:
        res[wc] = len(data)
    return res

def izph_xxtea_to_bytes(words: list, incl_len: bool) -> bytes:
    sz = len(words) * 4
    if incl_len:
        real = words[-1]
        if real < sz - 7 or real > sz - 4:
            raise IZPHError("bad xxtea len")
        sz = real
    out = bytearray(sz)
    for i in range(sz):
        out[i] = (words[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)

def izph_xxtea_decrypt(data: bytes, key_mat: bytes) -> bytes:
    if not data:
        return b""
    v = izph_xxtea_to_uint32(data, False)
    k = izph_xxtea_to_uint32(key_mat[:16].ljust(16, b'\x00'), False)
    n = len(v)
    if n < 2:
        return data
    rounds = 6 + 52 // n
    total = (rounds * IZPH_DELTA) & 0xFFFFFFFF
    while total:
        e = (total >> 2) & 3
        y = v[0]
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z)))
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        mx = ((((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ ((total ^ y) + (k[e] ^ z)))
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        total = (total - IZPH_DELTA) & 0xFFFFFFFF
    return izph_xxtea_to_bytes(v, True)

# Threefish
def izph_threefish256_subkeys(kw: list, tw: tuple) -> list:
    keys = kw + [IZPH_THREEFISH_C240 ^ kw[0] ^ kw[1] ^ kw[2] ^ kw[3]]
    tws = [tw[0], tw[1], tw[0] ^ tw[1]]
    sub = []
    for i in range(19):
        sub.append([
            keys[i % 5],
            (keys[(i + 1) % 5] + tws[i % 3]) & IZPH_MASK64,
            (keys[(i + 2) % 5] + tws[(i + 1) % 3]) & IZPH_MASK64,
            (keys[(i + 3) % 5] + i) & IZPH_MASK64
        ])
    return sub

def izph_threefish256_mix_inv(y0, y1, rot):
    x1 = izph_ror64(y0 ^ y1, rot)
    x0 = (y0 - x1) & IZPH_MASK64
    return x0, x1

def izph_threefish256_decrypt_block(block, key, tweak):
    state = block[:]
    sub = izph_threefish256_subkeys(key, tweak)
    for grp in range(17, -1, -1):
        ak = sub[grp + 1]
        for i in range(4):
            state[i] = (state[i] - ak[i]) & IZPH_MASK64
        for step in range(3, -1, -1):
            rot = IZPH_THREEFISH256_ROTATIONS[(grp * 4 + step) % 8]
            # Undo the round permutation before undoing its two MIX pairs.
            state = [state[IZPH_THREEFISH256_INV_PERMUTE[i]] for i in range(4)]
            state[0], state[1] = izph_threefish256_mix_inv(state[0], state[1], rot[0])
            state[2], state[3] = izph_threefish256_mix_inv(state[2], state[3], rot[1])
    ak = sub[0]
    for i in range(4):
        state[i] = (state[i] - ak[i]) & IZPH_MASK64
    return state

def izph_threefish256_decrypt(data: bytes, key_mat: bytes) -> bytes:
    """Pure-Python Threefish-256; no optional pyskein dependency."""
    if len(key_mat) != 32 or not data or len(data) % 32:
        raise IZPHError("invalid Threefish-256 block/key size")
    key_words = list(struct.unpack("<4Q", key_mat))
    out = bytearray()
    for idx in range(0, len(data), 32):
        block_index = idx // 32
        tweak = (block_index, block_index * 64)
        encrypted = list(struct.unpack("<4Q", data[idx:idx + 32]))
        decrypted = izph_threefish256_decrypt_block(encrypted, key_words, tweak)
        out.extend(struct.pack("<4Q", *decrypted))
    return bytes(out)

# AES
def izph_aes128_cbc_fixed(ct: bytes, key16: bytes) -> bytes:
    if len(ct) % 16 != 0:
        raise IZPHError("bad aes len")
    cipher = AES.new(key16, AES.MODE_CBC, IZPH_FIXED_IV)
    return izph_pkcs7_unpad(cipher.decrypt(ct))

def izph_aes256_cbc_prefixed_iv(ct: bytes, key32: bytes) -> bytes:
    if len(ct) < 16:
        raise IZPHError("no iv")
    iv, body = ct[:16], ct[16:]
    if len(body) % 16 != 0:
        raise IZPHError("bad body len")
    cipher = AES.new(key32, AES.MODE_CBC, iv)
    return izph_pkcs7_unpad(cipher.decrypt(body))

# ----- Decryption types (0-3) -----
def izph_decrypt_type0(payload: bytes) -> bytes:
    s1 = izph_aes128_cbc_fixed(payload, IZPH_SHA256_KEY_16)
    s2 = izph_xxtea_decrypt(s1, IZPH_SHA256_KEY_16)
    return bytes((b - 2) & 0xFF for b in s2)

def izph_decrypt_type1(payload: bytes) -> bytes:
    key16 = izph_get_hkdf_key_16()
    key32 = izph_get_hkdf_key()
    try:
        text = payload.decode('utf-8')
        b64 = izph_base64_decode_android(text)
    except:
        raise IZPHError("type1 decode fail")
    s2 = izph_threefish256_decrypt(b64, key32)
    # Zero fill follows AES ciphertext, whose last byte can itself be zero.
    size = ((len(s2.rstrip(b'\x00')) + 15) // 16) * 16
    if not size:
        raise IZPHError("empty Threefish body")
    return izph_aes128_cbc_fixed(s2[:size], key16)

def izph_decrypt_type2(payload: bytes) -> bytes:
    key32 = izph_get_pbkdf2_key()
    try:
        text = payload.decode('utf-8')
        b64 = izph_base64_decode_android(text)
    except:
        raise IZPHError("type2 decode fail")
    s2 = izph_xxtea_decrypt(b64, key32[:16])
    return izph_aes256_cbc_prefixed_iv(s2, key32)

def izph_decrypt_type3(payload: bytes) -> bytes:
    return izph_aes256_cbc_prefixed_iv(payload, izph_get_hkdf_key())

def izph_try_candidates(kind: int, candidates: list) -> bytes:
    for label, cand in candidates:
        try:
            if kind == 0:
                return izph_decrypt_type0(cand)
            elif kind == 1:
                return izph_decrypt_type1(cand)
            elif kind == 2:
                return izph_decrypt_type2(cand)
            elif kind == 3:
                return izph_decrypt_type3(cand)
        except Exception:
            continue
    raise IZPHError(f"kind {kind} failed on all candidates")
def izph_decode_payload(payload: str | bytes, kind: int, mode: str = "auto") -> bytes:
    raw_txt = payload.strip() if isinstance(payload, str) else None
    raw_bytes = payload if isinstance(payload, bytes) else payload.encode()
    candidates = []
    if mode in ("base64", "auto"):
        if raw_txt is None:
            raw_txt = izph_bytes_to_text(raw_bytes)
        if raw_txt:
            try:
                b64_decoded = izph_base64_decode_android(raw_txt)
                candidates.append(("base64", b64_decoded))
            except Exception:
                pass
    if mode in ("raw", "auto"):
        candidates.append(("raw", raw_bytes))
    if not candidates:
        raise IZPHError("no candidates")
    return izph_try_candidates(kind, candidates)

def izph_decode_text_payload(payload: str | bytes, kind: int, mode: str = "auto") -> str:
    dec = izph_decode_payload(payload, kind, mode)
    try:
        return dec.decode("utf-8")
    except:
        raise IZPHError("not utf8")

def try_direct_base64_decode(value: str) -> str | None:
    cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', value)
    if not cleaned or len(cleaned) % 4:
        return None
    try:
        raw = base64.b64decode(cleaned)
    except:
        return None
    # Try UTF-8
    try:
        text = raw.decode('utf-8')
        if text and (text.startswith('GET') or text.startswith('CONNECT') or 'Host:' in text or text.startswith('vless://')):
            return text
    except:
        pass
    # Try zlib
    try:
        text = zlib.decompress(raw).decode('utf-8')
        return text
    except:
        pass
    # Try gzip
    try:
        text = gzip.decompress(raw).decode('utf-8')
        return text
    except:
        pass
    return None

def izph_decode_nested_text(value: str, hint_kind: int, path: str, issues: list, strict: bool) -> str:
    order = [hint_kind] + [k for k in range(4) if k != hint_kind]
    for kind in order:
        try:
            return izph_decode_text_payload(value, kind, mode="auto")
        except Exception:
            continue
    direct = try_direct_base64_decode(value)
    if direct:
        return direct
    if strict:
        raise IZPHError(f"{path}: all decryption methods failed")
    issues.append(f"{path}: all Sevnet types failed and direct base64 failed")
    return value

# ----- Object decoders (Network, Server) -----
def izph_decode_network_object(obj: dict, index: int, issues: list, strict: bool) -> dict:
    path = f"Networks[{index}]"
    keys = ("Name", "SNIHost", "Payload", "Info", "DNSServerHost", "DNSResolver", "TLSVersion", "SSCommand")
    for key in keys:
        value = obj.get(key)
        if not isinstance(value, str) or not value:
            continue
        decrypt_type = 1 if key in {"SNIHost", "Payload"} else 0
        obj[key] = izph_decode_nested_text(value, decrypt_type, f"{path}.{key}", issues, strict)
    proxy = obj.get("ProxySettings")
    if isinstance(proxy, dict):
        for k in ("Squid", "Port"):
            v = proxy.get(k)
            if isinstance(v, str) and v:
                proxy[k] = izph_decode_nested_text(v, 0, f"{path}.ProxySettings.{k}", issues, strict)
    v2ray = obj.get("V2Ray")
    if isinstance(v2ray, dict):
        for k in ("SNIHost", "CustomV2RAY", "CustomV2RAYConfig", "Config"):
            v = v2ray.get(k)
            if not isinstance(v, str) or not v:
                continue
            dt = 1 if k in {"CustomV2RAYConfig", "SNIHost"} else 0
            v2ray[k] = izph_decode_nested_text(v, dt, f"{path}.V2Ray.{k}", issues, strict)
    return obj

def izph_decode_server_object(obj: dict, index: int, issues: list, strict: bool) -> dict:
    path = f"Servers[{index}]"
    keys = ("Name", "ServerIPHost", "Subname", "OpenVPNTCPPort", "OpenVPNSSLPort",
            "flag", "CustomCert", "Username", "Password", "CloudfrontDNS", "ServerHTTP", "Obfs")
    for key in keys:
        value = obj.get(key)
        if not isinstance(value, str) or not value:
            continue
        if key in {"Username", "Password"}:
            dt = 2
        elif key == "ServerIPHost":
            dt = 1
        else:
            dt = 0
        obj[key] = izph_decode_nested_text(value, dt, f"{path}.{key}", issues, strict)
    v2ray = obj.get("V2Ray")
    if isinstance(v2ray, dict):
        for k in ("V2RayConfig", "V2RayHost", "UUID", "PATH"):
            v = v2ray.get(k)
            if not isinstance(v, str) or not v:
                continue
            dt = 1 if k in {"V2RayHost", "PATH"} else 0
            v2ray[k] = izph_decode_nested_text(v, dt, f"{path}.V2Ray.{k}", issues, strict)
    slow_dns = obj.get("SlowDNS")
    if isinstance(slow_dns, dict):
        for k in ("NSNameServer", "PubKey"):
            v = slow_dns.get(k)
            if isinstance(v, str) and v:
                slow_dns[k] = izph_decode_nested_text(v, 0, f"{path}.SlowDNS.{k}", issues, strict)
    return obj

def izph_full_decode(payload: str | bytes, strict: bool = False) -> tuple[dict, list]:
    if isinstance(payload, str):
        payload = izph_strip_scheme(payload)
    else:
        txt = izph_bytes_to_text(payload)
        if txt:
            payload = izph_strip_scheme(txt)
    top = None
    for kind in range(4):
        try:
            top = izph_decode_text_payload(payload, kind, mode="auto")
            if top:
                break
        except Exception:
            continue
    if not top:
        raise IZPHError("Failed to decrypt outer layer")
    data = json.loads(top)
    issues = []

    if isinstance(data.get("Username"), str) and data["Username"]:
        data["Username"] = izph_decode_nested_text(data["Username"], 2, "Username", issues, strict)
    if isinstance(data.get("Password"), str) and data["Password"]:
        data["Password"] = izph_decode_nested_text(data["Password"], 2, "Password", issues, strict)

    servers = data.get("Servers")
    if isinstance(servers, list):
        for idx, srv in enumerate(servers):
            if isinstance(srv, dict):
                servers[idx] = izph_decode_server_object(srv, idx, issues, strict)
    networks = data.get("Networks")
    if isinstance(networks, list):
        for idx, net in enumerate(networks):
            if isinstance(net, dict):
                networks[idx] = izph_decode_network_object(net, idx, issues, strict)

    if servers is None and networks is None:
        network_keys = {"SNIHost", "Payload", "DNSServerHost", "DNSResolver", "TLSVersion"}
        server_keys = {"ServerIPHost", "OpenVPNTCPPort", "OpenVPNSSLPort"}
        if network_keys & data.keys():
            data = izph_decode_network_object(data, 0, issues, strict)
        elif server_keys & data.keys():
            data = izph_decode_server_object(data, 0, issues, strict)

    return data, issues

def izph_full_decode_text(payload: str | bytes, strict: bool = False) -> tuple[str, list]:
    data, issues = izph_full_decode(payload, strict)
    return json.dumps(data, ensure_ascii=False, indent=2), issues
def run(file_bytes: bytes) -> str | None:
    if not isinstance(file_bytes, bytes) or not file_bytes or len(file_bytes) > MAX_INPUT_BYTES:
        return None
    try:
        text = file_bytes.decode("utf-8").strip()
        for prefix in ("izph://", "izphvpnpro://"):
            if text.lower().startswith(prefix):
                text = text[len(prefix):].strip()
                break
        if not text:
            return None
        if text.startswith("{"):
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return json.dumps(parsed, ensure_ascii=False, indent=2)
        try:
            decoded, _issues = izph_full_decode_text(text, strict=False)
            result = json.loads(decoded)
            if isinstance(result, dict):
                return json.dumps(result, ensure_ascii=False, indent=2)
        except (ValueError, TypeError, KeyError, IZPHError):
            pass
        for kind in range(4):
            try:
                plaintext = izph_decode_text_payload(text, kind, mode="auto")
                result = json.loads(plaintext)
                if isinstance(result, dict):
                    return json.dumps(result, ensure_ascii=False, indent=2)
            except (ValueError, TypeError, KeyError, IZPHError):
                continue
    except UnicodeDecodeError:
        return None
    return None

EXTENSIONS = (".izph",)

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python izph.py <configuration-file>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if path.suffix.lower() not in EXTENSIONS:
        print("Unsupported izph extension", file=sys.stderr)
        return 2
    try:
        result = run(path.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Unable to read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt izph configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
