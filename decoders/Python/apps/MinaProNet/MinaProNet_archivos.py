#!/usr/bin/env python3
"""MinaProNet - AIO Tunnel VPN 88.0.0: archivos .mina (exportar / importar).

Python 3.10+, solo biblioteca estandar. El AES-256-CBC y el PBKDF2 se
implementan en Python puro en este archivo (mismo nucleo que
MinaProNet.py; el AES fue verificado byte a byte contra PyCryptodome
con el catalogo real de la familia).
Package vpn.minapronet.com.eg, versionCode 88, versionName 88.0.0.

Formato propio de la app: .mina (ExportActivity / Manager.exportTest
e importTest). La app exporta el perfil activo como
  MinaProNetVPN_yyyyMMddHHmmss.mina
en Download/MinaProNetVPN/ (MIME application/octet-stream). El contenido
es una sola linea de texto:

  exportTest(ConfigCustom JSON):
    1. ecr(json, "u"): AES-256-CBC con PBKDF2-HmacSHA1("u", salt, 10000
       iteraciones, 256 bits), salt[16] e IV[16] aleatorios ->
       Base64(salt || IV || ct).
    2. xec(...): ROT+6 sobre letras, invertir bytes, Base64.
    3. Base64 del texto anterior.
    4. Insertar los MISMOS 3 caracteres aleatorios ([A-Z][0-9][a-z]) en
       las posiciones 20-22 y de nuevo en las posiciones 5-7.

  importTest(texto):
    1. Quitar los caracteres de las posiciones 5-7 y 20-22.
    2. Base64-decodificar -> xde (Base64, reverse, ROT+20) -> dc("u")
       -> ConfigCustom JSON.
    3. Caducidad: valido ("i") si ahora < t (milisegundos) o t == "0" o
       t vacio; si no, caducado ("e"). El campo t es la fecha de
       caducidad elegida al exportar (0 = sin caducidad).

  La importacion en la app es por selector de archivos (SAF) o pegando
  el texto en el portapapeles (MainActivity). No hay intent-filter de
  archivo ni esquema URI propio en el manifiesto.

  El JSON ConfigCustom (68 campos) describe el perfil completo: SSH
  (DIRECT/PAYLOAD/SSL/PROXY), SlowDNS, UDP, Hysteria, OpenVPN, Psiphon,
  ZIVPN, SNI, proxy ascendente, y las protecciones opcionales:
  pw (contrasena), hwid (HWID del dispositivo) y t (caducidad). La
  contrasena y el HWID NO forman parte de la clave AES: son campos del
  JSON que la app comprueba despues de descifrar.

ESTADO: el cifrado se reimplemento a partir del codigo descompilado de
esta version (Manager.java: exportTest/importTest/ecr/dc) y se verifica
con ida y vuelta (sellar -> abrir) en --self-test. NO existe ninguna
muestra .mina real exportada por la app: el extremo a extremo con un
archivo real del telefono sigue PENDIENTE.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import random
import struct
import sys
import time
from pathlib import Path

MINA_PASSWORD = "u"
class DecodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-256-CBC (puro stdlib)
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
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


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


def _aes_decrypt_block(kw, block):
    s = list(struct.unpack(">4I", block))
    for i in range(4):
        s[i] ^= kw[56 + i]
    for rnd in range(13, 0, -1):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = (s[j] >> (24 - 8 * i)) & 0xff
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
        sb = bytearray(_INV_SBOX[x] for x in sb)
        s = list(struct.unpack(">4I", bytes(sb)))
        for i in range(4):
            s[i] ^= kw[4 * rnd + i]
        out = [0] * 4
        for c in range(4):
            s0 = (s[c] >> 24) & 0xff
            s1 = (s[c] >> 16) & 0xff
            s2 = (s[c] >> 8) & 0xff
            s3 = s[c] & 0xff
            out[c] = (_gmul(s0, 14) ^ _gmul(s1, 11) ^ _gmul(s2, 13) ^ _gmul(s3, 9)) << 24 \
                | (_gmul(s0, 9) ^ _gmul(s1, 14) ^ _gmul(s2, 11) ^ _gmul(s3, 13)) << 16 \
                | (_gmul(s0, 13) ^ _gmul(s1, 9) ^ _gmul(s2, 14) ^ _gmul(s3, 11)) << 8 \
                | (_gmul(s0, 11) ^ _gmul(s1, 13) ^ _gmul(s2, 9) ^ _gmul(s3, 14))
        s = out
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = (s[j] >> (24 - 8 * i)) & 0xff
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
    sb = bytearray(_INV_SBOX[x] for x in sb)
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= kw[i]
    return struct.pack(">4I", *s)


def _aes_cbc_decrypt(key, iv, ct):
    if len(ct) == 0 or len(ct) % 16:
        raise DecodeError("BAD_CIPHERTEXT", "El cifrado no es multiplo de 16 bytes.")
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        blk = _aes_decrypt_block(kw, ct[i:i + 16])
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = ct[i:i + 16]
    return bytes(out)


def _aes_encrypt_block(kw, block):
    s = list(struct.unpack(">4I", block))
    for i in range(4):
        s[i] ^= kw[i]
    for rnd in range(1, 14):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (_xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)) << 8 \
                | ((_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3))
        s = out
        for i in range(4):
            s[i] ^= kw[4 * rnd + i]
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
        s[i] ^= kw[56 + i]
    return struct.pack(">4I", *s)


def _aes_cbc_encrypt(key, iv, padded):
    kw = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        blk = bytes(a ^ b for a, b in zip(padded[i:i + 16], prev))
        enc = _aes_encrypt_block(kw, blk)
        out += enc
        prev = enc
    return bytes(out)


# ------------------------------------------------------------- xde / xec (nativo libchzcore.so)
def _rot_letters(data: bytes, shift: int) -> bytes:
    out = bytearray()
    for c in data:
        if 65 <= c <= 90:
            out.append(65 + (c - 65 + shift) % 26)
        elif 97 <= c <= 122:
            out.append(97 + (c - 97 + shift) % 26)
        else:
            out.append(c)
    return bytes(out)


def xde(inp: str) -> str:
    """CHZCORE.ii() / nativo xde(str, 0): Base64 -> reverse -> ROT+20 (letras)."""
    raw = base64.b64decode(inp.encode("ascii"))
    return _rot_letters(raw[::-1], 20).decode("utf-8")


def xec(inp: str) -> str:
    """Nativo xec(str, 0), inversa de xde: ROT+6 -> reverse -> Base64."""
    raw = _rot_letters(inp.encode("utf-8"), 6)[::-1]
    return base64.b64encode(raw).decode("ascii")


# ------------------------------------------------------------- dc / ecr (Manager.java)
def _a_decrypt(inp_b64: str, password: str) -> str:
    """Manager.dc: Base64 -> salt|IV|ct -> PBKDF2-HmacSHA1 -> AES-256-CBC."""
    try:
        raw = base64.b64decode(inp_b64.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("BAD_BASE64", "El sobre no es Base64 valido.") from exc
    if len(raw) < 32:
        raise DecodeError("SHORT_ENVELOPE", "El sobre es demasiado corto (sin salt/IV).")
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 10000, dklen=32)
    pt = _aes_cbc_decrypt(key, iv, ct)
    if not pt:
        raise DecodeError("BAD_PADDING", "El descifrado quedo vacio.")
    pad = pt[-1]
    if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
        raise DecodeError("BAD_PADDING", "El relleno PKCS7 no es valido (clave incorrecta).")
    try:
        return pt[:-pad].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("BAD_UTF8", "El descifrado no es texto UTF-8.") from exc


def _a_encrypt(plaintext: str, password: str) -> str:
    """Manager.ecr: salt/IV aleatorios -> PBKDF2-HmacSHA1 -> AES-256-CBC -> Base64(salt||IV||ct)."""
    salt = random.randbytes(16)
    iv = random.randbytes(16)
    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 10000, dklen=32)
    data = plaintext.encode("utf-8")
    pad = 16 - (len(data) % 16)
    pt = data + bytes([pad]) * pad
    ct = _aes_cbc_encrypt(key, iv, pt)
    return base64.b64encode(salt + iv + ct).decode("ascii")


def k_decrypt(inp: str, password: str) -> str:
    """Manager.getter: quitar basura -> Base64 -> xde -> dc(password)."""
    if len(inp) < 26:
        raise DecodeError("SHORT_INPUT", "La entrada es demasiado corta para el formato k().")
    concat = inp[0:5] + inp[8:]
    stripped = concat[0:20] + concat[23:]
    try:
        stage1 = base64.b64decode(stripped.encode("ascii")).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("BAD_BASE64", "La primera capa Base64 no es valida.") from exc
    try:
        stage3 = xde(stage1)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("BAD_XDE", "La capa xde no es valida.") from exc
    return _a_decrypt(stage3, password)


def k_encrypt(plaintext: str, password: str) -> str:
    """Inversa de k_decrypt (para pruebas): dc -> xec -> Base64 -> insertar basura."""
    stage3 = _a_encrypt(plaintext, password)
    stage1 = xec(stage3)
    stripped = base64.b64encode(stage1.encode("utf-8")).decode("ascii")
    garbage = (random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
               + random.choice("0123456789")
               + random.choice("abcdefghijklmnopqrstuvwxyz"))
    concat = stripped[:20] + garbage + stripped[20:]
    return concat[:5] + garbage + concat[5:]


# ------------------------------------------------------------- .mina
def _strip_garbage(text: str) -> str:
    """Quitar los 3 caracteres basura de las posiciones 5-7 y 20-22."""
    if len(text) < 26:
        raise DecodeError("SHORT_INPUT", "El .mina es demasiado corto.")
    concat = text[0:5] + text[8:]
    return concat[0:20] + concat[23:]


def _insert_garbage(stripped: str, garbage: str | None = None) -> str:
    """Insertar los mismos 3 caracteres en 20-22 y de nuevo en 5-7."""
    if garbage is None:
        garbage = (random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                   + random.choice("0123456789")
                   + random.choice("abcdefghijklmnopqrstuvwxyz"))
    concat = stripped[:20] + garbage + stripped[20:]
    return concat[:5] + garbage + concat[5:]


def open_mina(text: str) -> dict:
    """Abre un .mina (texto) y devuelve el ConfigCustom JSON.

    Devuelve {"status": "OK"|"EXPIRED", "config": {...}, "expired": bool}.
    status OK = valido ("i" en la app); EXPIRED = caducado ("e").
    """
    text = text.strip()
    try:
        stage1 = base64.b64decode(_strip_garbage(text).encode("ascii")).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("BAD_BASE64", "La primera capa Base64 no es valida.") from exc
    try:
        stage3 = xde(stage1)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecodeError("BAD_XDE", "La capa xde no es valida.") from exc
    plain = _a_decrypt(stage3, MINA_PASSWORD)
    try:
        config = json.loads(plain)
    except json.JSONDecodeError as exc:
        raise DecodeError("BAD_JSON", "El .mina descifrado no es JSON: %s" % exc) from exc
    if not isinstance(config, dict):
        raise DecodeError("BAD_JSON", "El .mina descifrado no es un objeto JSON.")
    t = str(config.get("t") or "")
    expired = False
    if t and t != "0":
        try:
            expired = int(time.time() * 1000) >= int(t)
        except ValueError:
            expired = False
    return {"status": "EXPIRED" if expired else "OK",
            "expired": expired, "config": config}


def seal_mina(config: dict | str, garbage: str | None = None) -> str:
    """Sella un ConfigCustom JSON como texto .mina (igual que exportTest)."""
    if isinstance(config, dict):
        config = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    stage3 = _a_encrypt(config, MINA_PASSWORD)
    stage1 = xec(stage3)
    stripped = base64.b64encode(stage1.encode("utf-8")).decode("ascii")
    return _insert_garbage(stripped, garbage)


def summarize_config(config: dict) -> dict:
    """Resumen legible del ConfigCustom (sin contrasenas)."""
    modes = [k for k in ("isSsh", "isPayload", "isSni", "isProxy", "isSlowDns",
                         "isSlowUdp", "isUdp", "isUdpCustom", "isUdpRequest",
                         "isHysteria", "isOpenVpn", "isPsiphon", "isZivpn")
             if config.get(k)]
    return {
        "message": config.get("message"),
        "mode": config.get("mode"),
        "modes": modes,
        "udpServer": config.get("udpServer"),
        "sni": config.get("sni"),
        "payload": (config.get("payload") or "")[:80],
        "slowDnsDNS": config.get("slowDnsDNS"),
        "has_password": bool(config.get("pw")),
        "has_hwid": bool(config.get("hwid")),
        "expiry_t": config.get("t"),
        "fields": len(config),
    }


# ------------------------------------------------------------- Self-test
def _self_test() -> dict:
    checks = {}
    cfg = {
        "hwid": "", "hysteriaLink": "", "isHysteria": False, "isOpenVpn": False,
        "isPayload": True, "isProxy": False, "isPsiphon": False,
        "isSlowDns": True, "isSlowUdp": False, "isSni": True, "isSsh": True,
        "isUdp": False, "isUdpCustom": False, "isUdpRequest": False,
        "isZivpn": False, "message": "perfil de prueba", "mode": 1,
        "openUserPass": "", "openVPNCfg": "", "payload": "GET / HTTP/1.1\r\nHost: ejemplo.test\r\n\r\n",
        "proxy": "", "psiphonAuth": "", "psiphonEntry": "", "pw": "",
        "slowDnsDNS": "1.1.1.1", "slowUdpLink": "", "sni": "ejemplo.test",
        "t": "0", "udpAuth": "", "udpCustomLink": "", "udpObfs": "",
        "udpPort": "", "udpRequestPassword": "", "udpRequestPortEnd": "",
        "udpRequestPortStart": "", "udpRequestReceiverCounter": "",
        "udpRequestSenderCounter": "", "udpRequestServer": "",
        "udpRequestUsername": "", "udpServer": "192.0.2.10",
        "udpUpDown": "", "upstreamProxyHeaders": "", "upstreamProxyHost": "",
        "upstreamProxyPassword": "", "upstreamProxyPort": "",
        "upstreamProxyUsername": "", "useHwidCfg": False, "usePassCfg": False,
        "useUpstreamProxy": False, "useUpstreamProxyAuth": False,
        "useUpstreamProxyHeaders": False, "v2rayEntry": "",
        "zivpnDownlink": "", "zivpnLink": "", "zivpnPassword": "",
        "zivpnRecvWindow": 0, "zivpnServer": "", "zivpnTestMode": False,
        "zivpnUplink": "", "i": "", "isSelected": False,
    }
    # 1. Ida y vuelta: sellar -> abrir, mismo JSON.
    text = seal_mina(cfg)
    out = open_mina(text)
    checks["seal_open_roundtrip"] = out["status"] == "OK" and out["config"] == cfg
    # 2. La basura esta en las posiciones que espera la app: la segunda
    # insercion (5-7) desplaza la primera (20-22) a 23-25.
    checks["garbage_positions"] = text[5:8] == text[23:26] and len(text[5:8]) == 3
    # 3. Caducidad: t="0" valido; t pasado caducado; t futuro valido.
    cfg_past = dict(cfg, t=str(int(time.time() * 1000) - 1000))
    cfg_future = dict(cfg, t=str(int(time.time() * 1000) + 3600_000))
    checks["expiry_past"] = open_mina(seal_mina(cfg_past))["status"] == "EXPIRED"
    checks["expiry_future"] = open_mina(seal_mina(cfg_future))["status"] == "OK"
    checks["expiry_zero"] = open_mina(seal_mina(dict(cfg, t="0")))["status"] == "OK"
    # 4. Un texto alterado no abre (la app lo rechazaria igual).
    bad = text[:100] + ("A" if text[100] != "A" else "B") + text[101:]
    try:
        open_mina(bad)
        checks["tamper_rejected"] = False
    except DecodeError:
        checks["tamper_rejected"] = True
    # 5. xde/xec y k() basicos.
    s = "MinaProNet .mina test 123"
    checks["xec_xde"] = xde(xec(s)) == s
    checks["all_ok"] = all(checks.values())
    return checks


# ------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="MinaProNet 88.0.0: abrir y sellar archivos .mina.")
    ap.add_argument("--file", help="Archivo .mina a abrir.")
    ap.add_argument("--text", help="Texto .mina a abrir (en lugar de --file).")
    ap.add_argument("--seal", help="Archivo JSON con un ConfigCustom para sellar como .mina.")
    ap.add_argument("--out", help="Archivo de salida para --seal.")
    ap.add_argument("--json", action="store_true", help="Salida en JSON.")
    ap.add_argument("--self-test", action="store_true", help="Pruebas internas sin red.")
    args = ap.parse_args(argv)

    if args.self_test:
        res = _self_test()
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            for k, v in res.items():
                print(("OK  " if v else "FALLO  ") + k)
        return 0 if res["all_ok"] else 1

    if args.seal:
        config = json.loads(Path(args.seal).read_text(encoding="utf-8"))
        text = seal_mina(config)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print("Escrito: %s (%d bytes)" % (args.out, len(text)))
        else:
            print(text)
        return 0

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    elif args.text:
        text = args.text
    else:
        ap.error("Falta --file, --text o --seal.")
        return 2

    try:
        res = open_mina(text)
    except DecodeError as exc:
        print("MINA: %s: %s" % (exc.code, exc))
        return 2
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("Estado: %s" % res["status"])
        print(json.dumps(summarize_config(res["config"]), ensure_ascii=False, indent=2))
    return 0 if res["status"] == "OK" else 3


if __name__ == "__main__":
    sys.exit(main())
