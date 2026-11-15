#!/usr/bin/env python3
"""1FTunnel 0.7.1 (build 127) — lector offline de perfiles y enlaces para SP-DECODE.

Formatos verificados en ESTE APK (com.oneftunnel.app, 0.7.1/127):

* Contenedor binario ``1FT1`` v1-v3 + textos ``1FTnl.`` / ``1FT1.`` /
  ``1ftunnel://1FTnl/`` / ``1ftunnel://1FT1/``: AES-256-GCM + HKDF-SHA256.
  La KDF nativa de 0.7.1 se verifico por emulacion Unicorn de
  liboneftunnel-security.so: es byte a byte la misma que la del repo
  (mismo ROOT_KEY, mismas etiquetas v1/v2, slots 0 y 1). El repo ya cubria
  0.6.99 (125); este script anade el documento CFG1 v6.
* Documento ``CFG1`` v1-v6. Novedad de 0.7.1: v6 anade la seccion SlowDns
  (hasSlowDns + resolver/nameserver/publicKey + recordType). Los enums no
  cambiaron de orden (InjectMode anade SLOWDNS=5 al final; los demas
  identicos a 0.6.99, confirmados por el <clinit> de cada enum).
* ``1ftunnel://locked-v2/``: PBKDF2-HmacSHA1 (150.000 iters, 256 bits) +
  AES-256-GCM; el plaintext es el JSON de un TunnelConfig.
* ``1ftunnel://locked/`` (v1): AES-256-GCM con clave en Android Keystore
  del dispositivo que lo genero (no exportable). NO se puede abrir offline:
  el script lo reporta como DEVICE_KEY_REQUIRED.
* ``1FTlb.`` / ``1ftunnel://1FTlb/``: grupo de balanceo de carga, JSON
  {"format": "1ftunnel-load-balance", "version": 1, "name": ...,
  "strategy": ..., "primary": "<texto 1FT1>", "secondary": "<texto 1FT1>"}.
* Backup ``1FTunnel-backup-*.json``: {"format": "1ftunnel-config-backup",
  "version": 1, "createdAt": ms, "entries": ["1FTnl....", ...]} (max 2000).
* ``1ftunnel://<base64url(JSON de TunnelConfig)>``: enlace JSON en claro.

SIN CATALOGO: la app no descarga ninguna lista de servidores. Las unicas
URLs en el APK son https://api.ipify.org (comprobador de IP publica),
https://t.me/OneFTunnel y https://www.1forcrkuota.com (tienda del autor).
No hay endpoint de catalogo que replicar; --url sirve para descargar un
enlace/texto 1FT1 publicado por el usuario, o acepta un enlace 1ftunnel://
directo. Nunca se inventan servidores.

Uso:
    python 1FTunnel.py --file perfil.1ftnl
    python 1FTunnel.py --file perfil.1ftnl --password Ghost
    cat perfil.1ftnl | python 1FTunnel.py --stdin
    python 1FTunnel.py --url "1ftunnel://locked-v2/...." --password Ghost
    python 1FTunnel.py --url https://ejemplo.test/perfil.txt
    python 1FTunnel.py --self-test

Solo stdlib de Python 3.10+. Sin red salvo --url explicito.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import struct
import sys
import urllib.request

PREFIXES_1FT1 = ("1FTnl.", "1FT1.", "1ftunnel://1FTnl/", "1ftunnel://1FT1/")
PREFIX_LB = ("1FTlb.", "1ftunnel://1FTlb/")
PREFIX_LOCKED_V2 = "1ftunnel://locked-v2/"
PREFIX_LOCKED_V1 = "1ftunnel://locked/"
PREFIX_JSON_LINK = "1ftunnel://"

ROOT_KEY = bytes.fromhex(
    "9e4f569a0a6cfd2da000b9de35ffe74a4e605c3eaecbdf477a13d709da233971")
PACKAGE = "com.oneftunnel.app"
SIGNATURES = frozenset({
    "d5d6665868244981a7ce3e9ea543610af83ed3b9c00322f0a7ffed88d327d589",
    "0c7718166c0b60cb09229dfc5f8c02f2567ea41fb75f7c7b792111c65dfaf937",
})
TYPES = ("SSH", "VMESS", "VLESS", "TROJAN")
INJECT_MODES = ("DIRECT", "SSH_PAYLOAD", "PROXY", "PROXY_SNI", "WILDCARD",
                "SLOWDNS")
SLOWDNS_RECORD_TYPES = ("AUTO", "TXT", "NULL", "NS", "CNAME", "MX", "SRV",
                        "A", "AAAA")
LB_FORMAT = "1ftunnel-load-balance"
BACKUP_FORMAT = "1ftunnel-config-backup"


class DecodeError(ValueError):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


def require(condition: bool, code: str = "INVALID_FORMAT") -> None:
    if not condition:
        raise DecodeError(code)


# ------------------------------------------------------------- AES-256-GCM
# Implementacion pura en stdlib (misma construccion que otros proveedores).
def _make_sbox():
    sbox = []
    for i in range(256):
        if i == 0:
            inv = 0
        else:
            inv = None
            for y in range(1, 256):
                p = 0
                aa, bb = i, y
                while bb:
                    if bb & 1:
                        p ^= aa
                    aa = ((aa << 1) ^ (0x1b if aa & 0x80 else 0)) & 0xff
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xff)
    return sbox


_SBOX = _make_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
_GCM_R = 0xe1000000000000000000000000000000


def _aes_key_expand(key):
    w = [x for grp in (struct.unpack(">4I", key[i:i + 16])
                       for i in range(0, 32, 16)) for x in grp]
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xffffffff
            sub = (_SBOX[(rot >> 24) & 0xff] << 24) | (_SBOX[(rot >> 16) & 0xff] << 16) \
                | (_SBOX[(rot >> 8) & 0xff] << 8) | _SBOX[rot & 0xff]
            temp = sub ^ (_RCON[i // 8 - 1] << 24)
        elif i % 8 == 4:
            temp = (_SBOX[(temp >> 24) & 0xff] << 24) | (_SBOX[(temp >> 16) & 0xff] << 16) \
                | (_SBOX[(temp >> 8) & 0xff] << 8) | _SBOX[temp & 0xff]
        w.append(w[i - 8] ^ temp)
    return w


def _aes_encrypt_block(key_words, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, 14):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]

        def xtime(x):
            return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)) << 8 \
                | ((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3))
        s = out
        for i in range(4):
            s[i] ^= rk[4 * rnd + i]
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[56 + i]
    return struct.pack(">4I", *s)


def _gf_mul(x, y):
    z = 0
    v = y
    for _ in range(128):
        if (x >> 127) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
        x = (x << 1) & ((1 << 128) - 1)
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    """AES-256-GCM decrypt (pure stdlib). nonce: 12 bytes."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = 1
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, ctr)
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ciphertext)
               + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    ej0 = _aes_encrypt_block(kw, j0)
    calc_tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if calc_tag != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


# ------------------------------------------------------------- 1FT1 envelope
class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        require(0 <= size <= len(self.data) - self.pos)
        out = self.data[self.pos:self.pos + size]
        self.pos += size
        return out

    def number(self, fmt: str) -> int:
        return struct.unpack(">" + fmt, self.take(struct.calcsize(fmt)))[0]

    def boolean(self) -> bool:
        n = self.number("B")
        require(n in (0, 1))
        return bool(n)

    def choice(self, names) -> str:
        n = self.number("B")
        require(n < len(names))
        return names[n]

    def string(self, *, nullable: bool = False, short: bool = False):
        size = self.number("H" if short else "i")
        if nullable and size == -1:
            return None
        require(0 <= size <= 2 * 1024 * 1024)
        try:
            return self.take(size).decode("utf-8")
        except UnicodeError as error:
            raise DecodeError("INVALID_FORMAT") from error

    def end(self) -> None:
        require(self.pos == len(self.data))


def _b64url_decode(text: str) -> bytes:
    text = text.strip()
    require(0 < len(text) <= 393216, "INVALID_FORMAT")
    require(re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", text) is not None,
            "INVALID_FORMAT")
    if "=" in text:
        require(len(text) % 4 == 0, "INVALID_FORMAT")
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4),
                               altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise DecodeError("INVALID_FORMAT") from error
    require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
            == text.rstrip("="), "INVALID_FORMAT")
    return raw


def unwrap(data) -> bytes:
    """Texto 1FT1 o bytes binarios -> envelope crudo con magic 1FT1."""
    if isinstance(data, bytes) and data.startswith(b"1FT1") \
            and not data.startswith(b"1FT1."):
        require(len(data) <= 5 * 1024 * 1024, "INVALID_FORMAT")
        return data
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        require(isinstance(text, str), "INVALID_FORMAT")
        text = text.strip()
        prefix = next((p for p in PREFIXES_1FT1 if text.startswith(p)), None)
        require(prefix is not None, "INVALID_FORMAT")
        return b"1FT1" + _b64url_decode(text[len(prefix):])
    except UnicodeError as error:
        raise DecodeError("INVALID_FORMAT") from error


def parse_aad(data: bytes, outer_version: int) -> dict:
    r = Reader(data)
    version = r.number("B")
    require(version == outer_version and version in (1, 2, 3),
            "UNSUPPORTED_VERSION")
    out = {"version": version, "package": r.string(short=True),
           "signatureSha256": r.string(short=True),
           "configVersion": r.number("I")}
    require(out["configVersion"] > 0, "INVALID_FORMAT")
    out.update(keySlot=0, minimumAppBuild=None, createdAt=None)
    if version >= 2:
        out.update(keySlot=r.number("I"), minimumAppBuild=r.number("q"),
                   createdAt=r.number("q"))
        require(out["keySlot"] in (0, 1) and out["minimumAppBuild"] >= 0
                and out["createdAt"] >= 0, "INVALID_FORMAT")
    out["expiredAt"] = r.number("q")
    require(out["expiredAt"] >= -1, "INVALID_FORMAT")
    out["configType"] = r.choice(TYPES)
    out["lockMode"] = r.number("B")
    require(out["lockMode"] in (0, 1, 2), "INVALID_FORMAT")
    out["blockRoot"] = r.boolean() if version >= 3 else False
    r.end()
    require(out["package"] == PACKAGE
            and out["signatureSha256"] in SIGNATURES, "UNSUPPORTED_IDENTITY")
    return out


def derive_key(version: int, salt: bytes, aad: bytes,
               password: str | None = None) -> bytes:
    require(version in (1, 2, 3) and len(salt) == 16, "INVALID_FORMAT")
    label = b"v1" if version == 1 else b"v2"
    ikm = ROOT_KEY
    if password:
        require(isinstance(password, str), "INVALID_PASSWORD")
        encoded = password.encode("utf-16-be", errors="surrogatepass")
        require(len(encoded) <= 8192, "INVALID_PASSWORD")
        ikm = hmac.digest(ikm, b"1FT1 password " + label + encoded, "sha256")
    prk = hmac.digest(salt, ikm, "sha256")
    return hmac.digest(prk, b"1FT1 HKDF AES-256-GCM " + label + aad + b"\x01",
                       "sha256")


def parse_config(data: bytes) -> dict:
    r = Reader(data)
    require(r.take(4) == b"CFG1", "INVALID_FORMAT")
    version = r.number("B")
    require(version in range(1, 7), "UNSUPPORTED_PAYLOAD_VERSION")
    out = {"payloadVersion": version, "id": r.string(), "name": r.string(),
           "createdAt": r.number("q"), "message": r.string(nullable=True)}
    require(bool(out["id"]) and bool(out["name"]), "INVALID_FORMAT")
    mask = r.number("i") if version >= 2 else -1
    require(-1 <= mask <= 511, "INVALID_FORMAT")
    out["fieldLockMask"] = None if mask == -1 else mask
    out["ssh"] = ({"host": r.string(), "port": r.number("i"),
                   "username": r.string(), "password": r.string()}
                  if r.boolean() else None)
    out["inject"] = ({"mode": r.choice(INJECT_MODES),
                      "payload": r.string(nullable=True),
                      "proxyHost": r.string(nullable=True),
                      "proxyPort": r.number("i"),
                      "sni": r.string(nullable=True),
                      "wildcardHost": r.string(nullable=True)}
                     if r.boolean() else None)
    if out["inject"] is not None and out["inject"]["proxyPort"] == -1:
        out["inject"]["proxyPort"] = None
    out["dns"] = ({"primary": r.string(), "secondary": r.string()}
                  if r.boolean() else None)
    xray = None
    if r.boolean():
        xray = {"protocol": r.choice(TYPES[1:]), "host": r.string(),
                "port": r.number("i"),
                "uuid": r.string(nullable=True),
                "password": r.string(nullable=True),
                "security": r.choice(("TLS", "NONE", "REALITY")),
                "network": r.choice(("WS", "GRPC", "RAW", "XHTTP",
                                     "HTTPUPGRADE"))}
        for key in ("path", "serviceName", "sni", "hostHeader",
                    "wildcardHost"):
            xray[key] = r.string(nullable=True)
        xray["allowInsecure"] = r.boolean() if version >= 3 else False
        xray["alpn"] = r.string(nullable=True) if version >= 3 else None
        for key in ("flow", "fingerprint", "realityPublicKey", "shortId",
                    "spiderX"):
            xray[key] = r.string(nullable=True) if version >= 4 else None
        xray["mode"] = r.string(nullable=True) if version >= 5 else None
    out["xray"] = xray
    slow_dns = None
    if version >= 6:
        if r.boolean():
            slow_dns = {"resolver": r.string(), "nameserver": r.string(),
                        "publicKey": r.string(),
                        "recordType": r.choice(SLOWDNS_RECORD_TYPES)}
    out["slowDns"] = slow_dns
    r.end()
    return out


def decode_1ft1(data, *, password: str | None = None) -> dict:
    require(password is None or isinstance(password, str),
            "INVALID_PASSWORD")
    raw = unwrap(data)
    r = Reader(raw)
    require(r.take(4) == b"1FT1", "INVALID_FORMAT")
    version = r.number("B")
    require(version in (1, 2, 3), "UNSUPPORTED_VERSION")
    require(r.take(3) == b"\x01\x01\x00", "INVALID_FORMAT")
    salt, nonce = r.take(16), r.take(12)
    aad_len, cipher_len = r.number("I"), r.number("I")
    require(aad_len <= 1024 and 16 <= cipher_len <= 4 * 1024 * 1024 + 16,
            "INVALID_FORMAT")
    aad, ciphertext = r.take(aad_len), r.take(cipher_len)
    r.end()
    metadata = parse_aad(aad, version)
    if metadata["lockMode"] == 2 and not password:
        raise DecodeError("PASSWORD_REQUIRED")
    key = derive_key(version, salt, aad,
                     password if metadata["lockMode"] == 2 else None)
    try:
        plaintext = _aes_gcm_decrypt(key, nonce, ciphertext[:-16],
                                     ciphertext[-16:], aad)
    except ValueError as error:
        raise DecodeError("AUTH_FAILED") from error
    config = parse_config(plaintext)
    require(metadata["createdAt"] is None
            or metadata["createdAt"] == config["createdAt"],
            "INVALID_FORMAT")
    section = config["ssh"] if metadata["configType"] == "SSH" \
        else config["xray"]
    require(section is not None, "INVALID_FORMAT")
    if metadata["configType"] != "SSH":
        require(section["protocol"] == metadata["configType"],
                "INVALID_FORMAT")
    metadata.update(authenticated=True, algorithm="AES-256-GCM",
                    kdf="HKDF-SHA256")
    return {"application": "1FTunnel", "format": "1FT1", "metadata": metadata,
            "config": config, "isPartial": False}


def lock_mode(data) -> int:
    """Devuelve el lockMode (0/1/2) de un envelope 1FT1 sin descifrarlo."""
    raw = unwrap(data)
    r = Reader(raw)
    require(r.take(4) == b"1FT1", "INVALID_FORMAT")
    version = r.number("B")
    require(version in (1, 2, 3), "UNSUPPORTED_VERSION")
    require(r.take(3) == b"\x01\x01\x00", "INVALID_FORMAT")
    r.take(16)
    r.take(12)
    aad_len, cipher_len = r.number("I"), r.number("I")
    require(aad_len <= 1024 and 16 <= cipher_len <= 4 * 1024 * 1024 + 16,
            "INVALID_FORMAT")
    aad = r.take(aad_len)
    return parse_aad(aad, version)["lockMode"]


# ------------------------------------------------------------- locked-v2 / v1
def decode_locked_v2(data, *, password: str | None = None) -> dict:
    """``1ftunnel://locked-v2/<b64url>``: PBKDF2-HmacSHA1 + AES-256-GCM.

    Cuerpo: version(1) || salt(16) || nonce(12) || ct || tag(16).
    Clave: PBKDF2-HmacSHA1(password UTF-16BE, salt, 150.000 iters, 32 B).
    El plaintext es el JSON de un TunnelConfig.
    """
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    require(isinstance(text, str) and text.startswith(PREFIX_LOCKED_V2),
            "INVALID_FORMAT")
    body = _b64url_decode(text[len(PREFIX_LOCKED_V2):])
    require(len(body) >= 1 + 16 + 12 + 16, "INVALID_FORMAT")
    require(body[0] == 2, "UNSUPPORTED_VERSION")
    salt, nonce = body[1:17], body[17:29]
    ciphertext, tag = body[29:-16], body[-16:]
    if not password:
        raise DecodeError("PASSWORD_REQUIRED")
    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-16-be"),
                              salt, 150000, 32)
    try:
        plaintext = _aes_gcm_decrypt(key, nonce, ciphertext, tag)
    except ValueError as error:
        raise DecodeError("AUTH_FAILED") from error
    try:
        config = json.loads(plaintext.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DecodeError("INVALID_FORMAT") from error
    require(isinstance(config, dict) and config.get("type") in TYPES,
            "INVALID_FORMAT")
    return {"application": "1FTunnel", "format": "1ftunnel-locked-v2",
            "config": config, "isPartial": False}


def decode_locked_v1(data) -> dict:
    """``1ftunnel://locked/<...>`` (v1): clave en Android Keystore.

    La clave vive en el Keystore del dispositivo que genero el enlace y no
    es exportable: NO se puede abrir offline. Se detecta por prefijo y se
    reporta como DEVICE_KEY_REQUIRED sin intentar descifrar.
    """
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    require(isinstance(text, str) and text.startswith(PREFIX_LOCKED_V1),
            "INVALID_FORMAT")
    raise DecodeError("DEVICE_KEY_REQUIRED")


# ------------------------------------------------------------- LB / backup / JSON
def decode_lb(data, *, password: str | None = None) -> dict:
    """``1FTlb.`` / ``1ftunnel://1FTlb/``: grupo de balanceo de carga."""
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    require(isinstance(text, str), "INVALID_FORMAT")
    text = text.strip()
    prefix = next((p for p in PREFIX_LB if text.startswith(p)), None)
    require(prefix is not None, "INVALID_FORMAT")
    try:
        group = json.loads(_b64url_decode(text[len(prefix):]).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DecodeError("INVALID_FORMAT") from error
    require(isinstance(group, dict) and group.get("format") == LB_FORMAT
            and group.get("version") == 1
            and isinstance(group.get("primary"), str)
            and isinstance(group.get("secondary"), str), "INVALID_FORMAT")
    return {"application": "1FTunnel", "format": LB_FORMAT,
            "name": group.get("name"), "strategy": group.get("strategy"),
            "primary": decode(group["primary"], password=password),
            "secondary": decode(group["secondary"], password=password),
            "isPartial": False}


def decode_backup(data, *, password: str | None = None) -> dict:
    """Backup JSON ``1FTunnel-backup-*.json``: lista de entradas 1FT1."""
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    require(isinstance(text, str), "INVALID_FORMAT")
    try:
        backup = json.loads(text.strip())
    except json.JSONDecodeError as error:
        raise DecodeError("INVALID_FORMAT") from error
    require(isinstance(backup, dict)
            and backup.get("format") == BACKUP_FORMAT
            and backup.get("version") == 1
            and isinstance(backup.get("entries"), list)
            and 0 < len(backup["entries"]) <= 2000, "INVALID_FORMAT")
    return {"application": "1FTunnel", "format": BACKUP_FORMAT,
            "createdAt": backup.get("createdAt"),
            "entries": [decode(entry, password=password)
                        for entry in backup["entries"]],
            "isPartial": False}


def decode_json_link(data, *, password: str | None = None) -> dict:
    """``1ftunnel://<base64url(JSON de TunnelConfig)>`` en claro."""
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    require(isinstance(text, str) and text.startswith(PREFIX_JSON_LINK),
            "INVALID_FORMAT")
    try:
        config = json.loads(_b64url_decode(
            text[len(PREFIX_JSON_LINK):]).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DecodeError("INVALID_FORMAT") from error
    require(isinstance(config, dict) and config.get("type") in TYPES,
            "INVALID_FORMAT")
    return {"application": "1FTunnel", "format": "1ftunnel-json",
            "config": config, "isPartial": False}


def decode(data, *, password: str | None = None) -> dict:
    """Despachador unico: binario 1FT1, textos 1FT1, locked, LB, backup, JSON."""
    if isinstance(data, bytes) and data.startswith(b"1FT1"):
        return decode_1ft1(data, password=password)
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
    except UnicodeError as error:
        raise DecodeError("INVALID_FORMAT") from error
    require(isinstance(text, str), "INVALID_FORMAT")
    stripped = text.strip()
    if stripped.startswith(PREFIX_LOCKED_V2):
        return decode_locked_v2(stripped, password=password)
    if stripped.startswith(PREFIX_LOCKED_V1):
        return decode_locked_v1(stripped)
    if any(stripped.startswith(p) for p in PREFIX_LB):
        return decode_lb(stripped, password=password)
    if any(stripped.startswith(p) for p in PREFIXES_1FT1):
        return decode_1ft1(stripped, password=password)
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as error:
            raise DecodeError("INVALID_FORMAT") from error
        if isinstance(obj, dict) and obj.get("format") == BACKUP_FORMAT:
            return decode_backup(stripped, password=password)
        if isinstance(obj, dict) and obj.get("type") in TYPES:
            return {"application": "1FTunnel", "format": "1ftunnel-json",
                    "config": obj, "isPartial": False}
        raise DecodeError("INVALID_FORMAT")
    if stripped.startswith(PREFIX_JSON_LINK):
        return decode_json_link(stripped, password=password)
    raise DecodeError("INVALID_FORMAT")


# ------------------------------------------------------------- CLI
def _fetch_url(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(5 * 1024 * 1024 + 1)
    require(len(body) <= 5 * 1024 * 1024, "INVALID_FORMAT")
    return body


def run(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="1FTunnel 0.7.1 — lector offline de perfiles y enlaces.")
    parser.add_argument("--file", help="archivo .1ftnl, binario 1FT1, "
                        "texto 1FT1, LB, backup JSON o enlace")
    parser.add_argument("--stdin", action="store_true",
                        help="leer el perfil de stdin")
    parser.add_argument("--url", help="enlace 1ftunnel:// o URL http(s) "
                        "con un texto 1FT1 publicado")
    parser.add_argument("--password", default=None,
                        help="contraseña (solo lockMode 2 / locked-v2)")
    parser.add_argument("-o", "--out", default=None,
                        help="escribir el JSON de salida en este archivo")
    parser.add_argument("--self-test", action="store_true",
                        help="vectores de prueba y salir")
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if _self_test() else 1
    try:
        if args.url:
            data = args.url.encode("utf-8") \
                if args.url.startswith("1ftunnel://") else _fetch_url(args.url)
        elif args.file:
            with open(args.file, "rb") as stream:
                data = stream.read(5 * 1024 * 1024 + 1)
            require(len(data) <= 5 * 1024 * 1024, "INVALID_FORMAT")
        elif args.stdin:
            data = sys.stdin.buffer.read(5 * 1024 * 1024 + 1)
            require(len(data) <= 5 * 1024 * 1024, "INVALID_FORMAT")
        else:
            parser.error("usa --file, --stdin, --url o --self-test")
        result = decode(data, password=args.password)
    except DecodeError as error:
        print(error.code, file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError) as error:
        print("INVALID_INPUT", file=sys.stderr)
        return 2
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as stream:
            stream.write(output + "\n")
    else:
        print(output)
    return 0


# ------------------------------------------------------------- self-test
_V6_1FTNL = ("1FTnl.AwEBAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhsAAAB6AAABMQMAEmNvbS5vbmVmdHVubmVsLmFwcABAZDVkNjY2NTg2ODI0NDk4MWE3Y2UzZTllYTU0MzYxMGFmODNlZDNiOWMwMDMyMmYwYTdmZmVkODhkMzI3ZDU4OQAAAAEAAAAAAAAAAAAAAAAAAAGhO4YAAP__________AgAAb-fgx65TEra8yyw2YoVzC9h9X-l3tSeIIAObVlF9kgwxMY9w7on5vQWmAwUJB6VJCXUhwtYAImcX5fMSxLKKyxXcQZYHn42wnioYt0KUQckn3yIDIxHR9G1yXR0OIPvV-gDFKSjGMrMduMrhRvmli870Fkr3hJryLvFK8_GrNZSGpRAICU4tU_YpDhWCM-v0o799iOLvTWr25eYAL6CBjY6oOV5w5kWdVqQz6Xhce-uHC62CBku-r9BRfsZgimxNTeJasjqjxltfVcn1K3sjBUWGjQfFqVAPddu0MnmBZMkjmCUtrsKfDGjK0tHHB-PMGnupui5lrCxv6IZ0TuNefoBobZVCvdm9rWRUNsoB1nxCBSojn1Vn_3OqP3c3RmSxKa45EFhV2SR6nPlPhJpbxnc")
_V3_1FTNL = ("1FTnl.AwEBAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhsAAAB6AAAArQMAEmNvbS5vbmVmdHVubmVsLmFwcABAZDVkNjY2NTg2ODI0NDk4MWE3Y2UzZTllYTU0MzYxMGFmODNlZDNiOWMwMDMyMmYwYTdmZmVkODhkMzI3ZDU4OQAAAAEAAAAAAAAAAAAAAAAAAAGhO4YAAP__________AgAAb-fgx6tTEra8yyw2YoVzC9h9X-l0tSeIOwOYVUkZihNUBrlQnvot4-HHAwUIppqnZhm_PSn-TGcX5fISwbKK2WvARZwY3om-xLiXJNJFylOrVN383VUuC5JXPHxvRquaqk_ZZXukUJ5544e6RaXv16vYcy-S7Zr9Lvlf-vvgvg4KLhAI9wrSrAnywNtM_SU6bXGvRS8igLjFKSrM_agzkV0bpFs2qjk6RYDRl40")
_LOCKED_V2 = ("1ftunnel://locked-v2/AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhvTH2-nTMXzMMV3ayljM0XE_Yh8dA-4LeblhQaB25dSx7vIEzQItqoAy72nz6Jq6lvZGAg4mqtfKqINQuuoZXJQ8eSds3P6c89w7JhzqDigriD58J4--9FvhBriIyTsM7ROBr5gHN-cLds1cT51vCHZjS19_FRlcwV6XOuhkU_QR67d6LkBqx0kYKvw3CmwfD2Slmzs4Mb5cVemeg0Puax2QbIod5UdxicTXFv3IZrk_qmsKB6sIR9_w4H0CagL12nuBElHYNzbh9jNhiV7fi3LuK-22bDsotwZPXtDW1g-FsVUhmeUvyyS3DUdoxljHb9VAA3sQ0XpDADjvb1jziJ1aQXzbNeup7FJrbMzalWsAIzAPB6KpHPwo2fAZBSoL7o-xUG-9f_QF-C5YIAQU8OAOU35sCinEFGuf2S5UNy_5rgCpIhzLaqofF02AL6ixZfWHJuhRd6ONfgxXQRKKf4Lvi2QA4LCNmdSo_NbkRAEljv-iJ361Fcxn_DdHC_705tvBEeEfzL7lb9hEuqaXpAsltYg5XMVJ3YXL7_8177WOT7VauGEg9HlmrSEi0pYDqBYQFNo2i5AvKTigrcznYZ74NtBft2Y5s8hGMsoZvjQ2UGoUYI4xlvtdyxW_I012H5vBOMDBGTBkuOy7ZZd8JlWKb8KgpWupeLqko3etkLMT_P-mdDuLHWsqm2FjcofNvPxB7QdtgaNMaXsHSaunL368CVSAn5JMb-1j8nkH5144hvS1Q3gQNn4M9Hx2Q2bHkm53bQP9zPW-ZoUXsqx10np83I2xcqm8AwI7-QT0xdT2idlx-glhPRgSPH_w6TQesyMmNYnsyImKa2htyR4nqN5D87kGVhZfosDsIRZVbIaFeFK009JXN-cobnF_ldKOQYY4TboYsOvV6jU7P_4xkk8RUDwGhcSLybdxFbLHAFyNyTzXQ")
_LB_1FTLB = ('1FTlb.eyJmb3JtYXQiOiAiMWZ0dW5uZWwtbG9hZC1iYWxhbmNlIiwgInZlcnNpb24iOiAxLCAibmFtZSI6ICJMQiBwcnVlYmEiLCAic3RyYXRlZ3kiOiAiUk9VTkRfUk9CSU4iLCAicHJpbWFyeSI6ICIxRlRubC5Bd0VCQUFBQkFnTUVCUVlIQ0FrS0N3d05EZzhRRVJJVEZCVVdGeGdaR2hzQUFBQjZBQUFCTVFNQUVtTnZiUzV2Ym1WbWRIVnVibVZzTG1Gd2NBQkFaRFZrTmpZMk5UZzJPREkwTkRrNE1XRTNZMlV6WlRsbFlUVTBNell4TUdGbU9ETmxaRE5pT1dNd01ETXlNbVl3WVRkbVptVmtPRGhrTXpJM1pEVTRPUUFBQUFFQUFBQUFBQUFBQUFBQUFBQUFBQUdoTzRZQUFQX19fX19fX19fX0FnQUFiLWZneDY1VEVyYTh5eXcyWW9WekM5aDlYLWwzdFNlSUlBT2JWbEY5a2d3eE1ZOXc3b241dlFXbUF3VUpCNlZKQ1hVaHd0WUFJbWNYNWZNU3hMS0t5eFhjUVpZSG40MnduaW9ZdDBLVVFja24zeUlESXhIUjlHMXlYUjBPSVB2Vi1nREZLU2pHTXJNZHVNcmhSdm1saTg3MEZrcjNoSnJ5THZGSzhfR3JOWlNHcFJBSUNVNHRVX1lwRGhXQ00tdjBvNzk5aU9MdlRXcjI1ZVlBTDZDQmpZNm9PVjV3NWtXZFZxUXo2WGhjZS11SEM2MkNCa3UtcjlCUmZzWmdpbXhOVGVKYXNqcWp4bHRmVmNuMUszc2pCVVdHalFmRnFWQVBkZHUwTW5tQlpNa2ptQ1V0cnNLZkRHakswdEhIQi1QTUdudXB1aTVsckN4djZJWjBUdU5lZm9Cb2JaVkN2ZG05cldSVU5zb0IxbnhDQlNvam4xVm5fM09xUDNjM1JtU3hLYTQ1RUZoVjJTUjZuUGxQaEpwYnhuYyIsICJzZWNvbmRhcnkiOiAiMUZUbmwuQXdFQkFBQUJBZ01FQlFZSENBa0tDd3dORGc4UUVSSVRGQlVXRnhnWkdoc0FBQUI2QUFBQXJRTUFFbU52YlM1dmJtVm1kSFZ1Ym1Wc0xtRndjQUJBWkRWa05qWTJOVGcyT0RJME5EazRNV0UzWTJVelpUbGxZVFUwTXpZeE1HRm1PRE5sWkROaU9XTXdNRE15TW1Zd1lUZG1abVZrT0Roa016STNaRFU0T1FBQUFBRUFBQUFBQUFBQUFBQUFBQUFBQUFHaE80WUFBUF9fX19fX19fX19BZ0FBYi1mZ3g2dFRFcmE4eXl3MllvVnpDOWg5WC1sMHRTZUlPd09ZVlVrWmloTlVCcmxRbnZvdDQtSEhBd1VJcHBxblpobV9QU24tVEdjWDVmSVN3YktLMld2QVJad1kzb20teExpWEpOSkZ5bE9yVk4zODNWVXVDNUpYUEh4dlJxdWFxa19aWlh1a1VKNTU0NGU2UmFYdjE2dlljeS1TN1pyOUx2bGYtdnZndmc0S0xoQUk5d3JTckFueXdOdE1fU1U2YlhHdlJTOGlnTGpGS1NyTV9hZ3prVjBicEZzMnFqazZSWURSbDQwIn0')
_BACKUP_JSON = ('{"format": "1ftunnel-config-backup", "version": 1, "createdAt": 1792000000000, "entries": ["' + _V6_1FTNL + '", "' + _V3_1FTNL + '"]}')


def _self_test() -> bool:
    checks = []

    def check(name: str, ok: bool) -> None:
        checks.append(ok)
        print(("OK   " if ok else "FAIL ") + name)

    try:
        v6 = decode(_V6_1FTNL)
        check("1FT1 v6 CFG1 (SlowDNS)", v6["config"]["payloadVersion"] == 6
              and v6["config"]["name"] == "SlowDNS de prueba"
              and v6["config"]["slowDns"]["resolver"] == "ns.ejemplo.test"
              and v6["config"]["slowDns"]["recordType"] == "A"
              and v6["config"]["inject"]["mode"] == "SLOWDNS"
              and v6["metadata"]["authenticated"] is True)
        check("lockMode v6 = 0", lock_mode(_V6_1FTNL) == 0)
        v3 = decode(_V3_1FTNL)
        check("1FT1 v3 CFG1 (sin SlowDNS)", v3["config"]["payloadVersion"] == 3
              and v3["config"]["name"] == "Solo VLESS"
              and v3["config"]["slowDns"] is None)
        locked = decode(_LOCKED_V2, password="Ghost")
        check("locked-v2 con contraseña", locked["format"] == "1ftunnel-locked-v2"
              and locked["config"]["name"] == "Bloqueado v2"
              and locked["config"]["xray"]["host"] == "bloqueado.ejemplo.test")
        lb = decode(_LB_1FTLB)
        check("LB 1FTlb (2 entradas)", lb["format"] == LB_FORMAT
              and lb["name"] == "LB prueba"
              and lb["primary"]["config"]["name"] == "SlowDNS de prueba"
              and lb["secondary"]["config"]["name"] == "Solo VLESS")
        backup = decode(_BACKUP_JSON)
        check("backup JSON (2 entradas)", backup["format"] == BACKUP_FORMAT
              and len(backup["entries"]) == 2
              and backup["entries"][0]["config"]["id"] == "test-id-0001")
        json_link = decode("1ftunnel://" + base64.urlsafe_b64encode(
            json.dumps({"type": "VLESS", "name": "JSON"}, ensure_ascii=False
                       ).encode()).rstrip(b"=").decode())
        check("enlace JSON en claro", json_link["format"] == "1ftunnel-json"
              and json_link["config"]["name"] == "JSON")
    except DecodeError as error:
        check("vectores válidos (" + error.code + ")", False)
    try:
        decode(_LOCKED_V2)
        check("locked-v2 sin contraseña -> PASSWORD_REQUIRED", False)
    except DecodeError as error:
        check("locked-v2 sin contraseña -> PASSWORD_REQUIRED",
              error.code == "PASSWORD_REQUIRED")
    try:
        decode(_LOCKED_V2, password="mala")
        check("locked-v2 contraseña mala -> AUTH_FAILED", False)
    except DecodeError as error:
        check("locked-v2 contraseña mala -> AUTH_FAILED",
              error.code == "AUTH_FAILED")
    try:
        decode("1ftunnel://locked/" + "AAAA")
        check("locked v1 -> DEVICE_KEY_REQUIRED", False)
    except DecodeError as error:
        check("locked v1 -> DEVICE_KEY_REQUIRED",
              error.code == "DEVICE_KEY_REQUIRED")
    try:
        decode(_V6_1FTNL[:-4] + "AAAA")
        check("1FT1 alterado -> AUTH_FAILED", False)
    except DecodeError as error:
        check("1FT1 alterado -> AUTH_FAILED", error.code == "AUTH_FAILED")
    try:
        decode("basura")
        check("texto inválido -> INVALID_FORMAT", False)
    except DecodeError as error:
        check("texto inválido -> INVALID_FORMAT",
              error.code == "INVALID_FORMAT")
    ok = all(checks)
    print("SELF-TEST: " + ("TODO OK" if ok else "FALLOS"))
    return ok


if __name__ == "__main__":
    sys.exit(run())

