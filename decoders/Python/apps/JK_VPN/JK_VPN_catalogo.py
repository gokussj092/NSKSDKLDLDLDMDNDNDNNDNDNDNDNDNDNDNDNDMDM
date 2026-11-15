#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JK VPN (FastVPN JK) — com.fastvpn.jk — v1.5 (versionCode 15).
Catalogo en vivo para SP-DECODE.

METODO (reproducido del APK 1.5, clases ox3 / oj0 / ia0 / qj0 / d6 / pa1 / zs2):
  1. GET al catalogo .hs (OkHttp, timeouts 5 s, sin cabeceras ni firma).
     La app guarda la URL en prefs cifradas ("key_url").
  2. El cuerpo es Base64 (una sola linea) de un cifrado Tink Streaming AEAD
     (AES-256-GCM-HKDF, tipo "AesGcmHkdfStreamingKey"):
       - cabecera de 40 B: byte[0] = 40, salt HKDF = bytes[1:33],
         nonce-prefix = bytes[33:40].
       - clave IKM = PBKDF2-HMAC-SHA256(contrasena de prefs "key_secured",
         salt fijo, 100000 iteraciones, 32 B).
       - clave AES = HKDF-SHA256(IKM, salt=cabecera, info=AD fijo, 32 B).
       - segmentos: el primero de 4056 B de cifrado (4096-40 de cabecera),
         los siguientes de 4096 B; ultimo segmento parcial.
         nonce por segmento = nonce-prefix (7 B) || nº segmento BE uint32
         || ultimo (1 B: 0x00/0x01). Tag GCM de 16 B, sin AAD.
  3. El plaintext es JSON UTF-8: {"Version", "Message", "Servers",
     "Networks", "setOpenVPN"}. La app solo importa si Version (double)
     es mayor que la guardada en prefs ("update", defecto "0.0").
  4. Valores cifrados DENTRO del catalogo: prefijo "ED:" + Base32
     (clase bj1.a; sin prefijo, la app prueba Base64 plano).
     Esta limpieza se aplica en la salida por defecto (ver limpiar_catalogo).

REGLA 2026-11-15: el JSON de resultado NO incluye las APIs de descarga
del catalogo; solo los datos, todo descifrado. La URL vive solo en este
script (y en la documentacion), nunca en el JSON de salida.

Criptografia: PBKDF2/HKDF con hashlib/hmac (stdlib). AES-256-GCM con
pycryptodome si esta disponible; si no, implementacion pura en Python
incluida abajo (AES256 + GHASH), validada contra pycryptodome y contra
el catalogo real (61 segmentos, plaintext identico).
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import struct
import sys
import urllib.request

# ---------------------------------------------------------------- constantes
CATALOG_URL = "https://raw.githubusercontent.com/Khinnainglin441/All-VPN/main/jkvpn.hs"
USER_AGENT = "okhttp/4.12.0"
TIMEOUT = 15

PBKDF2_PASSWORD = b"@JK132*#$!"            # pref "key_secured" (fija en la app)
PBKDF2_SALT = b"MY_APP_FIXED_SALT_V1"      # salt PBKDF2 fijo
PBKDF2_ITER = 100000
PBKDF2_DKLEN = 32

HKDF_INFO = b"MY_SECURE_JSON_STREAM_V1"   # associated data (e51.b)
HEADER_SIZE = 40
SALT_SIZE = 32
NONCE_PREFIX_SIZE = 7
CIPHERTEXT_SEGMENT_SIZE = 4096
PLAINTEXT_SEGMENT_SIZE = 4080

# Vector de prueba embebido: .hs sintetico minimo (JSON Version 9.999,
# 1 servidor Tun2Socks con host/usuario/clave ED:). Sirve para el self-test
# sin red. Generado con el cifrador de JK_VPN_archivos.py (salt/nonce fijos).
TEST_VECTOR_HS_B64 = (
    "KAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/AQIDBAUGB+ufDtR7DUkmcIp74dvLo2lcqopUgFGUzvrrGwDkWWa9UATE2R6IV8kb2dwCGgE6Q/mfrC9C8mX1AsC9s1hbl6qVeJ/EQZCeZ8scPukWvbC+YlIAopuEXlLRLS91fsJGwsQXyGFZ0PRPSnPnV+WqOD2MzCPQtheNO1PPRJveJNmBT4JU8lJi184LTXkNvC/eEMP0V/RbZq1MdM2dDqhq10acF0CfACa/rqUI9pTBw6NY2hDjXFLR5APvCQfzUl6+NEIjNaYZEr/rUrE0rZ0QwFkYxUiJrXjQbU1kWwf69963l0M2BXqBkAgz5U+dxd1KxRVhFiJIhTldex2gPuEwi2vODU1JTBj/q1GJJL2ZGS1yMe3PD23DGnEc"
)
TEST_VECTOR_JSON = {
    "Version": "9.999",
    "Message": "vector de prueba",
    "Servers": [{
        "type": "Tun2Socks", "name": "PRUEBA 01", "flag": "th",
        "host": "ED:NNUW4ZDTONUDCLTLNFXGILLWOBXC4Y3PNU======",
        "username": "ED:PF2HS5A=", "password": "ED:GEZDQOI=",
    }],
    "Networks": [],
    "setOpenVPN": "",
}

# ---------------------------------------------------------------- AES-GCM puro
# (fallback documentado; la ruta rapida usa pycryptodome si existe)
def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11b) & 0xff if a & 0x80 else (a << 1)
        b >>= 1
    return r

def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r

def _make_sbox():
    sbox = []
    for i in range(256):
        inv = 0 if i == 0 else _gf_pow(i, 254)
        s = inv
        for shift in (1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xff
        sbox.append((s ^ 0x63) & 0xff)
    return sbox

_SBOX = _make_sbox()

def _make_ttables():
    te = [[0] * 256 for _ in range(4)]
    for i in range(256):
        s = _SBOX[i]
        s2 = _gf_mul(s, 2)
        s3 = _gf_mul(s, 3)
        te[0][i] = (s2 << 24) | (s << 16) | (s << 8) | s3
        te[1][i] = (s3 << 24) | (s2 << 16) | (s << 8) | s
        te[2][i] = (s << 24) | (s3 << 16) | (s2 << 8) | s
        te[3][i] = (s << 24) | (s << 16) | (s3 << 8) | s2
    return te

_TE = _make_ttables()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
         0x6c, 0xd8, 0xab, 0x4d]

class _AES256:
    """AES-256, solo cifrado de bloque (suficiente para GCM)."""

    def __init__(self, key):
        assert len(key) == 32
        w = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 32, 4)]
        for i in range(8, 60):
            t = w[i - 1]
            if i % 8 == 0:
                t = (_SBOX[(t >> 16) & 0xff] << 24 | _SBOX[(t >> 8) & 0xff] << 16 |
                     _SBOX[t & 0xff] << 8 | _SBOX[(t >> 24) & 0xff]) ^ (_RCON[i // 8 - 1] << 24)
            elif i % 8 == 4:
                t = (_SBOX[(t >> 24) & 0xff] << 24 | _SBOX[(t >> 16) & 0xff] << 16 |
                     _SBOX[(t >> 8) & 0xff] << 8 | _SBOX[t & 0xff])
            w.append(w[i - 8] ^ t)
        self._rk = w

    def encrypt_block(self, block):
        assert len(block) == 16
        s = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 16, 4)]
        rk = self._rk
        for i in range(4):
            s[i] ^= rk[i]
        for rnd in range(1, 14):
            t = [0, 0, 0, 0]
            t[0] = (_TE[0][(s[0] >> 24) & 0xff] ^ _TE[1][(s[1] >> 16) & 0xff] ^
                    _TE[2][(s[2] >> 8) & 0xff] ^ _TE[3][s[3] & 0xff] ^ rk[rnd * 4])
            t[1] = (_TE[0][(s[1] >> 24) & 0xff] ^ _TE[1][(s[2] >> 16) & 0xff] ^
                    _TE[2][(s[3] >> 8) & 0xff] ^ _TE[3][s[0] & 0xff] ^ rk[rnd * 4 + 1])
            t[2] = (_TE[0][(s[2] >> 24) & 0xff] ^ _TE[1][(s[3] >> 16) & 0xff] ^
                    _TE[2][(s[0] >> 8) & 0xff] ^ _TE[3][s[1] & 0xff] ^ rk[rnd * 4 + 2])
            t[3] = (_TE[0][(s[3] >> 24) & 0xff] ^ _TE[1][(s[0] >> 16) & 0xff] ^
                    _TE[2][(s[1] >> 8) & 0xff] ^ _TE[3][s[2] & 0xff] ^ rk[rnd * 4 + 3])
            s = t
        out = bytearray(16)
        for i in range(4):
            word = rk[56 + i]
            for j in range(4):
                out[4 * i + j] = _SBOX[(s[(i + j) % 4] >> (24 - 8 * j)) & 0xff] ^ ((word >> (24 - 8 * j)) & 0xff)
        return bytes(out)

def _ghash(h, data):
    y = 0
    h_int = int.from_bytes(h, "big")
    for i in range(0, len(data), 16):
        y ^= int.from_bytes(data[i:i + 16], "big")
        z = 0
        v = h_int
        x = y
        for bit in range(128):
            if (x >> (127 - bit)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xe1000000000000000000000000000000
            else:
                v >>= 1
        y = z
    return y.to_bytes(16, "big")

def _gcm_decrypt_pure(key, nonce, ciphertext_and_tag, aad=b""):
    assert len(nonce) == 12
    assert len(ciphertext_and_tag) >= 16
    ct, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    aes = _AES256(key)
    h = aes.encrypt_block(b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = int.from_bytes(j0, "big")
    for i in range(0, len(ct), 16):
        counter += 1
        ks = aes.encrypt_block(counter.to_bytes(16, "big"))
        block = ct[i:i + 16]
        pt += bytes(a ^ b for a, b in zip(block, ks))
    def pad16(b):
        return b + b"\x00" * ((-len(b)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ct) +
               struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    calc = bytes(a ^ b for a, b in zip(s, aes.encrypt_block(j0)))
    if calc != tag:
        raise ValueError("GCM tag no coincide")
    return bytes(pt)

def _gcm_encrypt_pure(key, nonce, plaintext, aad=b""):
    assert len(nonce) == 12
    aes = _AES256(key)
    h = aes.encrypt_block(b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = int.from_bytes(j0, "big")
    for i in range(0, len(plaintext), 16):
        counter += 1
        ks = aes.encrypt_block(counter.to_bytes(16, "big"))
        block = plaintext[i:i + 16]
        ct += bytes(a ^ b for a, b in zip(block, ks))
    def pad16(b):
        return b + b"\x00" * ((-len(b)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct)) +
               struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    tag = bytes(a ^ b for a, b in zip(s, aes.encrypt_block(j0)))
    return bytes(ct) + tag

try:
    from Crypto.Cipher import AES as _AES_PYCRYPT

    def _gcm_decrypt_fast(key, nonce, ciphertext_and_tag):
        cipher = _AES_PYCRYPT.new(key, _AES_PYCRYPT.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext_and_tag[:-16],
                                         ciphertext_and_tag[-16:])

    def _gcm_encrypt_fast(key, nonce, plaintext):
        cipher = _AES_PYCRYPT.new(key, _AES_PYCRYPT.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return ct + tag

    _GCM_BACKEND = "pycryptodome"
except Exception:
    _gcm_decrypt_fast = None
    _gcm_encrypt_fast = None
    _GCM_BACKEND = "puro"

def gcm_decrypt(key, nonce, data):
    if _gcm_decrypt_fast is not None:
        return _gcm_decrypt_fast(key, nonce, data)
    return _gcm_decrypt_pure(key, nonce, data)

def gcm_encrypt(key, nonce, data):
    if _gcm_encrypt_fast is not None:
        return _gcm_encrypt_fast(key, nonce, data)
    return _gcm_encrypt_pure(key, nonce, data)

# ---------------------------------------------------------------- KDF
def pbkdf2_ikm(password=PBKDF2_PASSWORD, salt=PBKDF2_SALT,
              iterations=PBKDF2_ITER, dklen=PBKDF2_DKLEN):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)

def hkdf_sha256(ikm, salt, info, length):
    """HKDF RFC 5869 con SHA-256 (igual que Tink Hkdf.computeHkdf)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]

# ---------------------------------------------------------------- .hs (Tink streaming)
def descifrar_hs_bytes(ciphertext):
    """Descifra bytes de un .hs (ya sin Base64) y devuelve el JSON (dict)."""
    if len(ciphertext) < HEADER_SIZE + 16:
        raise ValueError("archivo .hs demasiado corto")
    if ciphertext[0] != HEADER_SIZE:
        raise ValueError("cabecera .hs invalida (byte 0 = %d, esperado 40)"
                         % ciphertext[0])
    salt = ciphertext[1:1 + SALT_SIZE]
    nonce_prefix = ciphertext[1 + SALT_SIZE:HEADER_SIZE]
    ikm = pbkdf2_ikm()
    key = hkdf_sha256(ikm, salt, HKDF_INFO, 32)
    body = ciphertext[HEADER_SIZE:]
    # Segmentos: primero 4056 B (4096 - 40 de cabecera), luego 4096 B.
    segments = []
    first_len = CIPHERTEXT_SEGMENT_SIZE - HEADER_SIZE
    segments.append(body[:first_len])
    off = first_len
    while off < len(body):
        segments.append(body[off:off + CIPHERTEXT_SEGMENT_SIZE])
        off += len(segments[-1])
    plaintext = bytearray()
    for i, seg in enumerate(segments):
        last = 1 if i == len(segments) - 1 else 0
        nonce = nonce_prefix + struct.pack(">I", i) + bytes([last])
        plaintext += gcm_decrypt(key, nonce, seg)
    return json.loads(bytes(plaintext).decode("utf-8"))

def descifrar_hs_b64(data_b64):
    """Descifra un .hs en Base64 (texto o bytes) y devuelve el JSON (dict)."""
    if isinstance(data_b64, str):
        data_b64 = data_b64.encode("ascii")
    data_b64 = b"".join(data_b64.split())
    return descifrar_hs_bytes(base64.b64decode(data_b64))

def descargar_catalogo(url=CATALOG_URL, timeout=TIMEOUT):
    """GET plano al catalogo (como OkHttp en la app: sin cabeceras propias,
    solo User-Agent okhttp). Devuelve (bytes crudos Base64, url usada)."""
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError("HTTP %d al descargar el catalogo" % resp.status)
        return resp.read(), url

# ---------------------------------------------------------------- valores ED: (bj1.a)
def decodificar_valor(s):
    """Replica bj1.a: '' si vacio; 'ED:' + Base32 si lleva prefijo;
    si no, Base64 plano; si no es Base64 valido, devuelve el original."""
    if s is None:
        return ""
    if not isinstance(s, str):
        return s
    if s == "":
        return ""
    try:
        if s.startswith("ED:"):
            return base64.b32decode(s[3:]).decode("utf-8")
        return base64.b64decode(s, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return s

def limpiar_catalogo(obj):
    """Recorre el catalogo y descifra todos los valores ED:/Base64.
    No toca la estructura ni anade metadatos (regla 2026-11-15)."""
    if isinstance(obj, dict):
        return {k: limpiar_catalogo(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [limpiar_catalogo(v) for v in obj]
    if isinstance(obj, str):
        return decodificar_valor(obj)
    return obj

def resumen(obj):
    """Resumen del catalogo limpio para stderr (no va en el JSON)."""
    from collections import Counter
    servers = obj.get("Servers", []) or []
    networks = obj.get("Networks", []) or []
    return {
        "version": obj.get("Version"),
        "servidores": len(servers),
        "tipos_servidor": dict(Counter(s.get("type") for s in servers)),
        "redes": len(networks),
        "tipos_red": dict(Counter(n.get("type") for n in networks)),
        "setOpenVPN_vacio": not obj.get("setOpenVPN"),
    }

# ---------------------------------------------------------------- self-test
def self_test():
    ok = []

    def check(nombre, cond):
        ok.append((nombre, bool(cond)))
        print(("OK  " if cond else "FALLO ") + nombre)
        return cond

    # AES-256 bloque (FIPS-197 C.3)
    check("AES-256 bloque FIPS-197 C.3",
          _AES256(bytes(range(32))).encrypt_block(
              bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
          == "8ea2b7ca516745bfeafc49904b496089")
    # GCM vector fijo (clave/nonce/pt deterministas)
    gkey = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    gnonce = bytes.fromhex("000102030405060708090a0b")
    gpt = b"JK VPN test vector 1234"
    gct = bytes.fromhex("0d49f64d95abe26fe832e3abc78c1b19eca4a705c2486b562edc2c23faef037ab7a27783cf4422")
    check("AES-256-GCM vector fijo (puro)", _gcm_decrypt_pure(gkey, gnonce, gct) == gpt)
    check("AES-256-GCM vector fijo (encrypt puro)", _gcm_encrypt_pure(gkey, gnonce, gpt) == gct)
    if _gcm_decrypt_fast is not None:
        check("AES-256-GCM vector fijo (pycryptodome)",
              gcm_decrypt(gkey, gnonce, gct) == gpt)
    # HKDF RFC 5869 Test Case 1 (SHA-256)
    check("HKDF-SHA256 RFC 5869 TC1",
          hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                      bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42).hex()
          == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c"
             "5bf34007208d5b887185865")
    # PBKDF2-HMAC-SHA256 vector conocido (1 iteracion, dklen 32)
    check("PBKDF2-HMAC-SHA256 vector",
          hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, dklen=32).hex()
          == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    # ED: / Base64 (bj1.a)
    check("ED: Base32 (host)", decodificar_valor("ED:NNUW4ZDTONUDCLTLNFXGILLWOBXC4Y3PNU======") == "kindssh1.kind-vpn.com")
    check("ED: Base32 (usuario)", decodificar_valor("ED:PF2HS5A=") == "ytyt")
    check("ED: Base32 (clave)", decodificar_valor("ED:GEZDQOI=") == "1289")
    check("Base64 plano", decodificar_valor("aGVsbG8=") == "hello")
    check("texto plano intacto", decodificar_valor("SSH 01") == "SSH 01")
    check("vacio -> vacio", decodificar_valor("") == "")
    # Vector .hs embebido: descifrar y comparar con el JSON esperado
    try:
        obj = descifrar_hs_b64(TEST_VECTOR_HS_B64)
        check("vector .hs embebido descifra", obj == TEST_VECTOR_JSON)
        check("vector .hs limpio",
              limpiar_catalogo(obj)["Servers"][0]["host"] == "kindssh1.kind-vpn.com")
    except Exception as e:
        check("vector .hs embebido descifra (%s)" % e, False)
    print("backend GCM: %s" % _GCM_BACKEND)
    fallos = [n for n, c in ok if not c]
    print("self-test: %d/%d OK" % (len(ok) - len(fallos), len(ok)))
    return not fallos

# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="JK VPN (com.fastvpn.jk) 1.5 — descarga y descifra el catalogo .hs")
    ap.add_argument("--url", default=CATALOG_URL,
                    help="URL del catalogo .hs (por defecto, la de la app)")
    ap.add_argument("--archivo", help="archivo .hs local (en vez de descargar)")
    ap.add_argument("--salida", "-o", help="archivo JSON de salida (por defecto, stdout)")
    ap.add_argument("--crudo", action="store_true",
                    help="no aplicar la limpieza ED:/Base64 (por defecto: limpia)")
    ap.add_argument("--resumen", action="store_true",
                    help="imprimir resumen del catalogo en stderr")
    ap.add_argument("--self-test", action="store_true", help="ejecutar self-test")
    args = ap.parse_args(argv)

    if args.self_test:
        return 0 if self_test() else 1

    if args.archivo:
        with open(args.archivo, "rb") as f:
            crudo_b64 = f.read()
        fuente = "archivo %s" % args.archivo
    else:
        crudo_b64, _ = descargar_catalogo(args.url)
        fuente = "URL (descargada en vivo)"
    obj = descifrar_hs_b64(crudo_b64)
    if not args.crudo:
        obj = limpiar_catalogo(obj)
    texto = json.dumps(obj, ensure_ascii=False, indent=2)
    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as f:
            f.write(texto + "\n")
    else:
        sys.stdout.write(texto + "\n")
    if args.resumen:
        print("fuente: %s" % fuente, file=sys.stderr)
        print("resumen: %s" % json.dumps(resumen(obj), ensure_ascii=False),
              file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
