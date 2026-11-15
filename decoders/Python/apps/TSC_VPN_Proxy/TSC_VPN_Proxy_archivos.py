#!/usr/bin/env python3
"""TSC VPN Proxy 6.4.3 (xyz.tscvpnproxy.app, versionCode 6) — archivos locales.

Formatos que la app guarda en disco (sin formato propio exportable):
  * cached_cloud_bundle.json — caché local del catálogo Cloud en filesDir
    (la app lo escribe tras cada descarga y lo lee VpnConnectionManager para
    los certProfiles). Misma estructura que la respuesta del worker:
    {meta, servers, tweaks, settings} con valores "enc:<base64url>".
  * settings.json — copia local del asset settings.json en filesDir (mismo
    formato; si no existe, la app lee el asset).
  * Los assets del APK (assets/servers.json, assets/tweaks.json,
    assets/settings.json) tienen la misma estructura enc:.

Cada valor "enc:<base64url>" se abre con:
  AES-256-GCM, clave fija de formato (32 B ASCII, en libisvcrypto.so),
  nonce = primeros 12 B, tag = últimos 16 B, sin AAD.
  Sobre: base64url( nonce[12] || ct || tag[16] ).

La app NO tiene formato propio de perfil exportable (no hay extensión, ni
ACTION_VIEW/CREATE_DOCUMENT de exportar, ni deep link): los perfiles viven
en una base Room interna y el intercambio entre usuarios es por la nube
(api/v1/config/share, con registro de dispositivo + créditos, no verificado
aquí). La importación de enlaces es por pegado en la app (ProtocolSetupSheet,
placeholder "vmess://..., ss://..., wg://..."): enlaces V2Ray estándar del
núcleo v2rayNG (vmess://, vless://, trojan://, ss://, socks://, hy2://,
hysteria2://, tuic://, wireguard://), sin esquema propio de TSC y sin
intent-filter en el manifest.

Uso:
  TSC_VPN_Proxy_archivos.py cached_cloud_bundle.json [-o salida.json]
  TSC_VPN_Proxy_archivos.py servers.json tweaks.json settings.json
  TSC_VPN_Proxy_archivos.py --enc "enc:..."     (un solo valor)
  TSC_VPN_Proxy_archivos.py --self-test

Python 3.10+, solo biblioteca estándar. AES-256-GCM en Python puro
(reutilizado del script SP-DECODE de RNV Tunnel VPN, mismo algoritmo).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import struct
import sys
from pathlib import Path

# Clave fija de formato (libisvcrypto.so; misma que el catálogo).
FORMAT_KEY = bytes.fromhex(
    "4b7030536a374565696f626749314f737648346246764f544747324a44494678")
MAX_BYTES = 8 * 1024 * 1024


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256-GCM
# Python puro (mismo código que el script SP-DECODE de RNV Tunnel VPN).
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
    w = [x for grp in (struct.unpack(">4I", key[i:i + 16]) for i in range(0, 32, 16)) for x in grp]
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


def _aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    """AES-256-GCM encrypt (pure stdlib). Returns (ciphertext, tag)."""
    kw = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, ctr)
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct))
               + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    ej0 = _aes_encrypt_block(kw, j0)
    tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    return bytes(ct), tag


# ------------------------------------------------------------ formato enc:
def _b64url_decode(text: str) -> bytes:
    raw = text.strip()
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def decrypt_enc(value: str) -> str:
    """Abre un valor 'enc:<base64url>' -> texto plano UTF-8."""
    if not isinstance(value, str) or not value.startswith("enc:"):
        raise DecodeError("NOT_ENC", "El valor no empieza por 'enc:'.")
    try:
        blob = _b64url_decode(value[4:])
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("BAD_BASE64", "Base64url inválido en valor enc:.") from exc
    if len(blob) < 28:
        raise DecodeError("TOO_SHORT", "Sobre enc: demasiado corto (< 28 B).")
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    try:
        pt = _aes_gcm_decrypt(FORMAT_KEY, nonce, ct, tag)
    except ValueError as exc:
        raise DecodeError("DECRYPT_FAILED",
                          "El tag GCM no verifica con la clave de formato.") from exc
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("BAD_UTF8", "El plaintext no es UTF-8.") from exc


def encrypt_enc(plaintext: str) -> str:
    """Inverso de decrypt_enc (para pruebas round-trip)."""
    nonce = os.urandom(12)
    ct, tag = _aes_gcm_encrypt(FORMAT_KEY, nonce, plaintext.encode("utf-8"))
    blob = nonce + ct + tag
    return "enc:" + base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")


def decrypt_value(value):
    """Descifra recursivamente todos los valores 'enc:' de un documento."""
    if isinstance(value, dict):
        return {k: decrypt_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decrypt_value(v) for v in value]
    if isinstance(value, str) and value.startswith("enc:"):
        return decrypt_enc(value)
    return value


def decode_file(data: bytes | str) -> dict | str:
    """Decodifica un archivo local de TSC: JSON con valores enc:, o un
    único valor 'enc:...'. Devuelve el documento descifrado."""
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError("BAD_UTF8", "El archivo no es UTF-8.") from exc
    else:
        text = data
    text = text.strip()
    if text.startswith("enc:"):
        return decrypt_enc(text)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DecodeError("BAD_JSON", "El archivo no es JSON ni un valor enc:.") from exc
    return decrypt_value(doc)


def run(file_bytes: bytes | str):
    """Offline API: documento descifrado, o None si no abre."""
    try:
        return decode_file(file_bytes)
    except DecodeError:
        return None


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _summarize(doc) -> dict:
    if isinstance(doc, str):
        return {"value": doc}
    if isinstance(doc, dict):
        out = {}
        if "servers" in doc:
            out["servers"] = len(doc["servers"])
        if "tweaks" in doc:
            out["tweaks"] = len(doc["tweaks"])
        if "meta" in doc and isinstance(doc["meta"], dict):
            out["version"] = (doc["meta"].get("serverVersion")
                              or doc["meta"].get("version"))
        if "settings" in doc:
            out["settings"] = True
        return out or {"keys": sorted(doc.keys())[:10]}
    return {"type": type(doc).__name__}


# -------------------------------------------------------------------- tests
_SELF_TEST_VECTORS = [
    ("enc:yfIY2o11fn2KvUwEVczH0CdpJtDkncwirKP6qE6i8YS2_VcPVQqQ",
     "c.tenor.com"),
    ("enc:vRP-XRW7AjVW3p_PSXsiCokfwrqmgJN7DYa_SwuwhpJGWPVU_SkaWytVOYT3TUUi",
     "atrgroup.atrtdev.xyz"),
    ("enc:6wLBn6TMd5WnpIAzYM3vGSndwmKbpRohtvmTjI4BB2uyTws9_OBP3x4",
     "m.youtube.com"),
]


def self_test() -> dict:
    """Auto-prueba sin red: vectores enc:, round-trip y mini-bundle."""
    checks = 0
    for enc, want in _SELF_TEST_VECTORS:
        got = decrypt_enc(enc)
        if got != want:
            raise DecodeError("SELF_TEST_FAIL",
                              f"decrypt_enc falló: {enc[:24]} -> {got!r} != {want!r}")
        checks += 1
    for plain in ("hello.example.com", "c.tenor.com", "GET / HTTP/1.1[crlf]"):
        if decrypt_enc(encrypt_enc(plain)) != plain:
            raise DecodeError("SELF_TEST_FAIL", f"round-trip falló: {plain!r}")
        checks += 1
    blob = bytearray(_b64url_decode(encrypt_enc("x")[4:]))
    blob[-1] ^= 1
    bad = "enc:" + base64.urlsafe_b64encode(bytes(blob)).decode("ascii").rstrip("=")
    try:
        decrypt_enc(bad)
    except DecodeError as exc:
        if exc.code != "DECRYPT_FAILED":
            raise
        checks += 1
    else:
        raise DecodeError("SELF_TEST_FAIL", "tag alterado aceptado (no debería).")
    # Mini cached_cloud_bundle.json sintético con valores enc: reales.
    mini = json.dumps({
        "meta": {"serverVersion": "9.9-test"},
        "servers": [{"id": 1, "name": "T",
                     "host": _SELF_TEST_VECTORS[0][0], "isOnline": True}],
        "tweaks": [{"id": 1, "name": "T",
                    "sni": _SELF_TEST_VECTORS[2][0]}],
        "settings": {}})
    doc = decode_file(mini)
    assert doc["servers"][0]["host"] == "c.tenor.com"
    assert doc["tweaks"][0]["sni"] == "m.youtube.com"
    checks += 1
    return {"self_test": "OK", "checks": checks}


# ---------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path,
                        help="cached_cloud_bundle.json, servers.json, tweaks.json, "
                             "settings.json o un archivo con un valor enc:")
    parser.add_argument("--enc", help="Decodificar un único valor 'enc:...'")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON descifrado; por defecto stdout "
                             "(con varios archivos, se añade .dec.json a cada uno)")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica vectores enc: y round-trip (sin red)")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            print(json.dumps(self_test(), ensure_ascii=False))
            return 0
        if args.enc is not None:
            print(decrypt_enc(args.enc))
            return 0
        if not args.files:
            parser.error("se requiere un archivo, --enc o --self-test")
        for path in args.files:
            doc = decode_file(_read(path))
            rendered = (doc if isinstance(doc, str) else
                        json.dumps(doc, ensure_ascii=False, indent=2,
                                   allow_nan=False) + "\n")
            if args.output and len(args.files) == 1:
                args.output.write_text(rendered if isinstance(rendered, str)
                                       else rendered, encoding="utf-8")
            elif args.output:
                out = path.with_suffix(path.suffix + ".dec.json")
                out.write_text(rendered, encoding="utf-8")
            else:
                sys.stdout.write(rendered if rendered.endswith("\n")
                                 else rendered + "\n")
            print(json.dumps({"file": str(path), **_summarize(doc)},
                             ensure_ascii=False), file=sys.stderr)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR",
                          "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
