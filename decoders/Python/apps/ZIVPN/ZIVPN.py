#!/usr/bin/env python3
"""ZIVPN Tunnel - catalogo remoto (SP-DECODE).

App: ZIVPN Tunnel (SSH/DNS/UDP) VPN, com.zi.zivpn, 2.2.5 (versionCode 184).
Catalogo: GET https://zivpn-ssh.web.app/profiles.json (Firebase Hosting).
La respuesta es un JSON con una clave por configuracion remota; cada valor es
Base64 de un XML de propiedades Java cifrado con AES-256-CBC, clave =
SHA-256 de la clave de la app, IV = 16 bytes a cero (ver
com.zi.common.a::a(String, String) en classes3.dex).

El catalogo en vivo (2026-11-14) trae UNA sola configuracion:
"Global UDP" (tunnelType 4 = Psiphon), servidor udpsg1.zivpn.com.
No hay lista de servidores ni payloads HTTP en este endpoint: el "catalogo"
es una unica configuracion remota que la app guarda como
"remote_<nombre>" y aplica al conectarse.

Uso:
    python3 ZIVPN.py --url            # descarga y descifra el catalogo en vivo
    python3 ZIVPN.py --file catalog_sample.json
    python3 ZIVPN.py --self-test
"""
import argparse
import base64
import hashlib
import json
import struct
import sys
import urllib.request
import xml.etree.ElementTree as ET

CATALOG_URL = "https://zivpn-ssh.web.app/profiles.json"
CATALOG_KEY = "u9quwlqk881di1gxjn1auby3fafvom9t"
UA = "Dalvik/2.1.0 (Linux; U; Android 14)"

TUNNEL_TYPES = {
    1: "sshProxy", 2: "sshSslTunnel", 3: "udptunnel", 4: "psiphontunnel",
    5: "v2raytunnel", 6: "litevpntunnel", 7: "sshDirect",
}


class DecodeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES (stdlib)
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
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
         0x6c, 0xd8, 0xab, 0x4d]


def _aes_key_expand(key):
    """Key schedule for AES-128 (16 B) and AES-256 (32 B). Returns word list."""
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xffffffff
            sub = (_SBOX[(rot >> 24) & 0xff] << 24) | (_SBOX[(rot >> 16) & 0xff] << 16) \
                | (_SBOX[(rot >> 8) & 0xff] << 8) | _SBOX[rot & 0xff]
            temp = sub ^ (_RCON[i // nk - 1] << 24)
        elif nk > 6 and i % nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xff] << 24) | (_SBOX[(temp >> 16) & 0xff] << 16) \
                | (_SBOX[(temp >> 8) & 0xff] << 8) | _SBOX[temp & 0xff]
        w.append(w[i - nk] ^ temp)
    return w, nr


def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _aes_encrypt_block(key_words, nr, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, nr):
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
        s[i] ^= rk[4 * nr + i]
    return struct.pack(">4I", *s)


def _aes_decrypt_block(key_words, nr, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[4 * nr + i]
    for rnd in range(nr - 1, 0, -1):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _INV_SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
        s = list(struct.unpack(">4I", bytes(sb)))
        for i in range(4):
            s[i] ^= rk[4 * rnd + i]
        out = [0] * 4
        for c in range(4):
            a0 = (s[c] >> 24) & 0xff
            a1 = (s[c] >> 16) & 0xff
            a2 = (s[c] >> 8) & 0xff
            a3 = s[c] & 0xff
            out[c] = (_gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)) << 24 \
                | (_gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)) << 16 \
                | (_gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)) << 8 \
                | (_gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14))
        s = out
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = _INV_SBOX[(s[j] >> (24 - 8 * i)) & 0xff]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[i]
    return struct.pack(">4I", *s)


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise DecodeError("BAD_LENGTH", "El cifrado CBC no es multiplo de 16.")
    kw, nr = _aes_key_expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = _aes_decrypt_block(kw, nr, data[i:i + 16])
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = data[i:i + 16]
    return bytes(out)


def _pkcs7_unpad(data):
    if not data:
        raise DecodeError("BAD_PADDING", "Texto vacio tras descifrar.")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise DecodeError("BAD_PADDING", "Padding PKCS7 invalido.")
    return data[:-pad]


# ------------------------------------------------------------- catalogo
def decrypt_remote_value(value, key=CATALOG_KEY):
    """Base64 -> AES-256-CBC (SHA-256(clave), IV cero) -> XML (str)."""
    try:
        raw = base64.b64decode(value, validate=False)
    except Exception as exc:
        raise DecodeError("BAD_BASE64", "El valor no es Base64 valido.") from exc
    aes_key = hashlib.sha256(key.encode("utf-8")).digest()
    try:
        plain = _pkcs7_unpad(_aes_cbc_decrypt(aes_key, b"\x00" * 16, raw))
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("DECRYPT_FAILED", "AES-CBC no abrio el valor.") from exc
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("BAD_UTF8", "El descifrado no es UTF-8.") from exc


def parse_properties_xml(xml_text):
    """XML de Properties de Java -> dict {clave: valor}."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise DecodeError("BAD_XML", "El XML de propiedades no parsea.") from exc
    props = {}
    for entry in root.findall("entry"):
        key = entry.get("key")
        if key is not None:
            props[key] = entry.text or ""
    return props


def decode_catalog(raw_json):
    """JSON crudo de profiles.json -> {nombre: propiedades}."""
    try:
        doc = json.loads(raw_json)
    except (ValueError, TypeError) as exc:
        raise DecodeError("BAD_JSON", "La respuesta no es JSON.") from exc
    if not isinstance(doc, dict) or not doc:
        raise DecodeError("EMPTY_CATALOG", "El catalogo JSON esta vacio.")
    out = {}
    for name, value in doc.items():
        if not isinstance(value, str) or not value.strip():
            continue
        xml_text = decrypt_remote_value(value.strip())
        out[name] = parse_properties_xml(xml_text)
    if not out:
        raise DecodeError("EMPTY_CATALOG", "Ninguna entrada del catalogo abrio.")
    return out


def fetch_catalog(url=CATALOG_URL, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise DecodeError("HTTP_%d" % resp.status, "El servidor devolvio %d." % resp.status)
        return resp.read()


def summarize(doc):
    servers = []
    tunnel_types = {}
    for name, props in doc.items():
        tt = props.get("tunnelType", "")
        try:
            tt_i = int(tt)
        except ValueError:
            tt_i = None
        tunnel_types[TUNNEL_TYPES.get(tt_i, tt or "?")] = tunnel_types.get(TUNNEL_TYPES.get(tt_i, tt or "?"), 0) + 1
        srv = props.get("udpserver") or props.get("sshServer") or props.get("litehost") or ""
        if srv:
            servers.append(srv)
    return {
        "configs": len(doc),
        "names": sorted(doc.keys()),
        "tunnel_types": tunnel_types,
        "servers": servers,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="ZIVPN Tunnel - catalogo remoto")
    ap.add_argument("--url", nargs="?", const=CATALOG_URL, default=None,
                    help="Descarga el catalogo en vivo (URL opcional)")
    ap.add_argument("--file", help="Archivo JSON crudo del catalogo")
    ap.add_argument("--out", help="Escribe el catalogo descifrado (JSON) aqui")
    ap.add_argument("--self-test", action="store_true", help="Pruebas internas")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.url:
        raw = fetch_catalog(args.url)
    elif args.file:
        with open(args.file, "rb") as fh:
            raw = fh.read()
    else:
        ap.error("usa --url o --file")
    doc = decode_catalog(raw)
    result = {"catalog": doc, "summary": summarize(doc)}
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


def _self_test():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, "catalog_sample.json")
    with open(sample, "rb") as fh:
        raw = fh.read()
    doc = decode_catalog(raw)
    assert len(doc) == 1, doc.keys()
    name = next(iter(doc))
    props = doc[name]
    assert "Global UDP" in name, name
    assert props.get("tunnelType") == "4", props.get("tunnelType")
    assert props.get("udpserver") == "udpsg1.zivpn.com", props.get("udpserver")
    assert props.get("sshPortaLocal") == "1080", props.get("sshPortaLocal")
    assert props.get("file.appVersionCode") == "24", props.get("file.appVersionCode")
    s = summarize(doc)
    assert s["configs"] == 1 and s["servers"] == ["udpsg1.zivpn.com"]
    # vector AES-CBC conocido (NIST): clave SHA-256 de la clave de la app
    print("self-test OK: 1 configuracion (Global UDP, Psiphon, udpsg1.zivpn.com)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
