#!/usr/bin/env python3
"""S Tunnel 11.1.0 (Play name "MSY VPN TUNNEL"): catalog decoder.

Python 3.10+, solo biblioteca estandar. AES-128-GCM implementado en Python
puro en este archivo (el nucleo AES es generico 128/192/256 bits y esta
verificado contra PyCryptodome/cryptography y contra el vector NIST).
Package com.stunnel.dev, versionCode 147, versionName 11.1.0, minSdk 32.
El APK es la version publica de Google Play (11.1.0); se descargo de APKPure
porque APKMirror no tenia listado. Sin cobertura previa en el repo de
SP-DECODE (86 carpetas revisadas; no hay nada para com.stunnel.dev,
com.msyvpn.lite, jk5 ni MSY_VPN_SECURITY_SALT).

La app es en realidad MSY VPN LITE (MainActivity com.msyvpn.lite.MainActivity,
sin librerias nativas: Java/Kotlin puro, sin splits de arquitectura).

Catalogo (clase defpackage.zh, caso default; r80.h; yh0.a/c/f):

  GET http://servers.jk5.fun/servers.json
  (GET plano por Socket TCP, sin TLS; la URL esta ofuscada en el DEX como
  35 bytes con XOR 0x4B. Sin cabeceras propias ni autenticacion; la peticion
  exacta de la app es:
    GET /servers.json HTTP/1.1
    Host: <host>
    Connection: close
  El servidor responde HTTP 200, Content-Type: application/octet-stream,
  Content-Length: <n>, Connection: close.)

  El cuerpo es el catalogo cifrado con r80.h:
    si el primer byte no blanco es '{' (0x7B) o '[' (0x5B), el cuerpo ya es
    JSON en claro; si no:
      clave = SHA-256("MSY_VPN_SECURITY_SALT_2026_@JuanitoProSniff")[:16]
      IV    = cuerpo[0:12]
      ct    = cuerpo[12:]  (texto cifrado + tag GCM de 16 B al final)
      texto = AES-128-GCM/NoPadding descifrar(clave, IV, ct), sin AAD
    El texto plano es un JSON:
      {v_k7, a_v3, a_vn, a_ur, a_mg, s_nd[], c_mx[]}
    v_k7 = version del catalogo; a_v3/a_vn = versionCode/versionName de la
    app que publico ese catalogo; s_nd = servidores {x_i, x_n, x_c, x_h
    (host), x_a (IP), x_tp[] (puertos TCP), x_up[] (puertos UDP), x_dn
    (host DNS), x_cd (host CDN)}; c_mx = configs/payloads {z_i, z_n, z_gp
    (grupo/pais), z_s (servidor), z_t (tipo: tcp/udp/dns/hcr/payload/proxy/
    ssl/ssl_ws/...), z_p (puerto), z_r, z_w (SNI/host), z_b (payload HTTP),
    z_wp (path WS), z_dn (DNS)}.

  La app tambien puede descargar el catalogo desde los propios servidores
  del catalogo (zh): GET http://<x_h>:<puerto>/servers.json con el mismo
  formato, probando los puertos de x_tp/x_up ([80, 8080, 8880, 443, 444,
  8443] en el catalogo vivo). Este script prueba primero la URL principal
  y despues los hosts del catalogo incluido (mia.jk5.fun, fr1.jk5.fun).

  Quirk de red (verificado en vivo): el servidor a veces corta la descarga
  (cuerpos de 0, 1923, 3539, 4429, 4784, 4949, 5119, 5472 B en vez de los
  6351 B completos). Un cuerpo truncado NO verifica el tag GCM, asi que el
  script reintenta el GET completo hasta que el tag verifica (el tag es la
  prueba de que el cuerpo esta completo). Nunca se usa Range. El cuerpo
  completo es determinista (SHA-256 8fa9c886...); el IV es fijo en el
  servidor (los primeros 12 B son iguales en cada descarga).

  Asset incluido: res/raw/servers.bin es el catalogo incluido en el APK,
  cifrado con el mismo r80.h (v37, 2 servidores, 11 configs).

LIVE STATUS (2026-11-13, verificado con --url): el endpoint principal
responde HTTP 200, 6351 B, y el catalogo abre: Version (v_k7) 49, a_v3 147,
a_vn "11.1.0", 2 servidores (Miami mia.jk5.fun, France 1 fr1.jk5.fun) y
19 configs (8 con payload: WOM Colombia, IMWI x6 #1/#2, Digicel, Flow
#1-#4). El descifrado completo tarda <1 s en Python puro.

La app no tiene formato propio de archivo de perfiles importable (sin
ACTION_VIEW ni ACTION_GET_CONTENT en el manifiesto, sin extension propia,
sin .sks) ni esquema URI propio (sin data scheme en el manifiesto; solo
MAIN/LAUNCHER). Los configs se crean en la UI y se guardan en el almacen
interno; por eso no hay S_Tunnel_archivos.py.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import socket
import struct
import sys
from pathlib import Path
from urllib.parse import urlparse

CATALOG_URL = "http://servers.jk5.fun/servers.json"
# Hosts del catalogo incluido; el script los prueba si la URL principal falla.
FALLBACK_HOSTS = ("mia.jk5.fun", "fr1.jk5.fun")
FALLBACK_PORTS = (80, 8080, 8880, 443, 444, 8443)
SALT = "MSY_VPN_SECURITY_SALT_2026_@JuanitoProSniff"
MAX_BYTES = 8 * 1024 * 1024
TAG_LEN = 16
IV_LEN = 12


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- AES (pure python, stdlib only)
# Nucleo AES generico (128/192/256 bits), verificado contra cryptography y
# contra el vector NIST GCM (clave cero, nonce cero, 16 B cero).

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
        s[i] ^= rk[4 * nr + i]
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
    """AES-GCM decrypt (pure stdlib). nonce: 12 bytes; tag: 16 bytes."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = 1
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ciphertext)
               + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    calc_tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if calc_tag != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


def _aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    """AES-GCM encrypt (pure stdlib). Returns (ciphertext, tag)."""
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct))
               + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    return bytes(ct), tag


# ---------------------------------------------------------------- r80.h (catalogo)

def _catalog_key():
    return hashlib.sha256(SALT.encode("utf-8")).digest()[:16]


def decrypt_catalog_body(data):
    """r80.h: si el cuerpo ya es JSON en claro lo devuelve; si no, lo
    descifra con AES-128-GCM (clave SHA-256 del salt, IV = primeros 12 B)."""
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El cuerpo supera el limite de tamano.")
    i = 0
    while i < len(data) and data[i] in (32, 9, 13, 10):
        i += 1
    if i < len(data) and data[i] in (0x7b, 0x5b):  # '{' o '['
        return data.decode("utf-8")
    if len(data) <= IV_LEN + TAG_LEN:
        raise DecodeError("FORMAT_ERROR", "Cuerpo demasiado corto para ser un catalogo cifrado.")
    key = _catalog_key()
    try:
        plain = _aes_gcm_decrypt(key, data[:IV_LEN], data[IV_LEN:-TAG_LEN], data[-TAG_LEN:])
    except ValueError as exc:
        raise DecodeError("LIVE_DECRYPT_FAILED",
                          "El tag GCM no verifica; el cuerpo esta truncado o no es "
                          "el catalogo de S Tunnel con la clave actual.") from exc
    return plain.decode("utf-8")


def decode(data):
    """Descifra el catalogo (cuerpo cifrado o JSON en claro) y devuelve el dict."""
    if isinstance(data, str):
        text = data
    elif isinstance(data, (bytes, bytearray)):
        text = decrypt_catalog_body(bytes(data))
    else:
        raise DecodeError("FORMAT_ERROR", "Se esperaba bytes o texto.")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DecodeError("FORMAT_ERROR", "El texto plano no es JSON.") from exc
    if not isinstance(doc, dict) or "s_nd" not in doc or "c_mx" not in doc:
        raise DecodeError("FORMAT_ERROR", "El JSON no es un catalogo de S Tunnel.")
    return doc


def run(file_bytes):
    """Devuelve el catalogo decodificado como JSON (texto)."""
    doc = decode(file_bytes)
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def summary(doc):
    """Resumen corto del catalogo."""
    servers = doc.get("s_nd", []) or []
    configs = doc.get("c_mx", []) or []
    with_payload = sum(1 for c in configs if isinstance(c, dict) and c.get("z_b"))
    return {
        "catalog_version": doc.get("v_k7"),
        "app_version_code": doc.get("a_v3"),
        "app_version_name": doc.get("a_vn"),
        "servers": len(servers),
        "configs": len(configs),
        "configs_with_payload": with_payload,
        "server_names": [s.get("x_n") for s in servers if isinstance(s, dict)],
    }


# ---------------------------------------------------------------- descarga en vivo

def _proxy_env():
    """Devuelve (host, puerto, usuario, clave) del proxy del entorno, o None."""
    raw = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
           or os.environ.get("all_proxy") or os.environ.get("ALL_PROXY"))
    if not raw:
        return None
    parsed = urlparse(raw)
    if not parsed.hostname or not parsed.port:
        return None
    return parsed.hostname, parsed.port, parsed.username, parsed.password


def _raw_get(host, port, timeout=20):
    """GET exactamente como la app (Socket TCP plano, sin TLS):
    GET /servers.json HTTP/1.1 / Host: <host> / Connection: close.
    Con proxy en el entorno usa un tunel CONNECT explicito; sin proxy,
    conexion directa. Devuelve (status, headers_dict, body)."""
    proxy = _proxy_env()
    no_proxy = os.environ.get("no_proxy", "") or ""
    if proxy and host not in [h.strip() for h in no_proxy.split(",") if h.strip()]:
        p_host, p_port, p_user, p_pass = proxy
        sock = socket.create_connection((p_host, p_port), timeout=timeout)
        try:
            req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
            if p_user is not None:
                token = base64.b64encode(
                    ("%s:%s" % (p_user, p_pass or "")).encode()).decode()
                req += "Proxy-Authorization: Basic %s\r\n" % token
            req += "\r\n"
            sock.sendall(req.encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise OSError("el proxy cerro la conexion CONNECT")
                buf += chunk
            if b"200" not in buf.split(b"\r\n")[0]:
                raise DecodeError("DOWNLOAD_FAILED",
                                  "El proxy rechazo el tunel CONNECT: %s"
                                  % buf.split(b"\r\n")[0].decode(errors="replace"))
        except Exception:
            sock.close()
            raise
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(("GET /servers.json HTTP/1.1\r\nHost: %s\r\n"
                      "Connection: close\r\n\r\n" % host).encode())
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    idx = data.find(b"\r\n\r\n")
    if idx < 0:
        raise DecodeError("DOWNLOAD_FAILED", "Respuesta HTTP invalida (sin cabeceras).")
    head = data[:idx].decode(errors="replace")
    lines = head.split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise DecodeError("DOWNLOAD_FAILED", "Respuesta HTTP invalida (sin estado).")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = data[idx + 4:]
    return status, headers, body


def fetch_url(url, attempts=6, timeout=20):
    """Descarga el cuerpo de un URL http://<host>[:puerto]/servers.json con
    reintentos: el servidor a veces corta la descarga y solo el tag GCM
    prueba que el cuerpo llego completo."""
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise DecodeError("URL_ERROR", "Se esperaba una URL http:// (la app usa HTTP plano).")
    host = parsed.hostname
    port = parsed.port or 80
    last_error = None
    for attempt in range(max(1, attempts)):
        try:
            status, headers, body = _raw_get(host, port, timeout=timeout)
            if status != 200:
                raise DecodeError("ACCESS_DENIED" if status in (401, 403) else "DOWNLOAD_FAILED",
                                  "El endpoint devolvio HTTP %d." % status)
        except DecodeError:
            raise
        except (OSError, ValueError) as exc:
            last_error = exc
            continue
        if not body or len(body) > MAX_BYTES:
            last_error = ValueError("cuerpo vacio o demasiado grande")
            continue
        expected = headers.get("content-length")
        if expected is not None:
            try:
                if len(body) != int(expected):
                    last_error = ValueError("cuerpo truncado: %d de %s bytes"
                                            % (len(body), expected))
                    continue
            except ValueError:
                pass
        try:
            decode(body)
        except DecodeError as exc:
            last_error = exc
            continue
        return body
    raise DecodeError("DOWNLOAD_FAILED",
                      "No se pudo descargar un catalogo completo de %s "
                      "tras %d intentos (ultimo error: %s)."
                      % (url, max(1, attempts), last_error)) from last_error


def catalog_urls():
    """URLs a probar en orden: la principal y despues cada host del catalogo
    incluido con cada puerto de x_tp/x_up."""
    urls = [CATALOG_URL]
    for host in FALLBACK_HOSTS:
        for port in FALLBACK_PORTS:
            urls.append("http://%s:%d/servers.json" % (host, port))
    return urls


def fetch_catalog(url=None):
    """Descarga el catalogo en vivo y devuelve (catalogo, info). Con --url se
    usa solo esa URL; sin el, se prueban la principal y los fallbacks."""
    tried = [url] if url else catalog_urls()
    errors = []
    for candidate in tried:
        try:
            raw = fetch_url(candidate)
            doc = decode(raw)
            info = {
                "catalog_url": candidate,
                "bytes": len(raw),
            }
            info.update(summary(doc))
            return doc, info
        except DecodeError as exc:
            errors.append("%s: %s" % (candidate, exc))
    raise DecodeError("DOWNLOAD_FAILED",
                      "Ninguna URL devolvio un catalogo valido. " + "; ".join(errors))


# ---------------------------------------------------------------- self-test

def _self_test():
    """Verifica AES-GCM, el descifrado r80.h, el asset incluido y la muestra
    real del catalogo vivo."""
    checks = {}
    # 1. AES-128-GCM contra el vector NIST (clave cero, nonce cero, 16 B cero).
    key0 = bytes(16)
    ct, tag = _aes_gcm_encrypt(key0, bytes(12), bytes(16))
    checks["gcm_nist_aes128_zero"] = (
        ct.hex() == "0388dace60b6a392f328c2b971b2fe78"
        and tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf")
    pt0 = _aes_gcm_decrypt(key0, bytes(12), ct, tag)
    checks["gcm_nist_aes128_roundtrip"] = pt0 == bytes(16)
    # 2. Ida y vuelta con la clave real de la app.
    sample = {"v_k7": 999, "a_v3": 147, "a_vn": "11.1.0",
              "s_nd": [{"x_i": "t", "x_h": "test.example"}],
              "c_mx": [{"z_i": "t", "z_b": "GET / HTTP/1.1"}]}
    plain = json.dumps(sample, ensure_ascii=False).encode("utf-8")
    iv = bytes(range(12))
    ct2, tag2 = _aes_gcm_encrypt(_catalog_key(), iv, plain)
    checks["app_key_roundtrip"] = decode(iv + ct2 + tag2) == sample
    # 3. JSON en claro pasa tal cual (r80.h lo devuelve sin descifrar).
    checks["plain_json_passthrough"] = decode('{"v_k7": 1, "s_nd": [], "c_mx": []}')["v_k7"] == 1
    # 4. Cuerpo truncado o con tag alterado se rechaza.
    try:
        decode(iv + ct2 + tag2[:-1] + bytes([tag2[-1] ^ 1]))
        checks["tampered_tag_rejected"] = False
    except DecodeError:
        checks["tampered_tag_rejected"] = True
    try:
        decode((iv + ct2 + tag2)[:100])
        checks["truncated_rejected"] = False
    except DecodeError:
        checks["truncated_rejected"] = True
    # 5. Asset incluido (res/raw/servers.bin): v37, 2 servidores, 11 configs.
    asset_path = Path(__file__).with_name("servers.bin")
    if asset_path.exists():
        doc = decode(asset_path.read_bytes())
        checks["bundled_asset_version"] = doc.get("v_k7") == 37
        checks["bundled_asset_servers"] = len(doc.get("s_nd", [])) == 2
        checks["bundled_asset_configs"] = len(doc.get("c_mx", [])) == 11
    else:
        checks["bundled_asset_present"] = False
    # 6. Muestra real del catalogo vivo (2026-11-13, v49).
    sample_path = Path(__file__).with_name("catalog_sample.bin")
    if sample_path.exists():
        doc = decode(sample_path.read_bytes())
        checks["live_sample_version"] = doc.get("v_k7") == 49
        checks["live_sample_app_version"] = doc.get("a_v3") == 147
        checks["live_sample_servers"] = len(doc.get("s_nd", [])) == 2
        checks["live_sample_configs"] = len(doc.get("c_mx", [])) == 19
        checks["live_sample_payloads"] = sum(
            1 for c in doc.get("c_mx", []) if c.get("z_b")) == 8
    else:
        checks["live_sample_present"] = False
    return checks


# ---------------------------------------------------------------- CLI

def _read(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el limite de tamano.")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path,
                        help="Cuerpo cifrado guardado o servers.bin")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga el catalogo en vivo; por defecto usa "
                             "http://servers.jk5.fun/servers.json (con fallbacks)")
    source.add_argument("--asset", action="store_true",
                        help="Descifra el catalogo incluido en el APK (servers.bin)")
    source.add_argument("--stdin", action="store_true",
                        help="Leer el cuerpo cifrado desde stdin")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON completo; por defecto stdout")
    parser.add_argument("--summary", action="store_true",
                        help="Mostrar solo el resumen del catalogo")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica AES-GCM, r80.h, el asset y la muestra viva")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(result.values()) else 1
        if args.asset:
            asset_path = Path(__file__).with_name("servers.bin")
            if not asset_path.exists():
                raise DecodeError("IO_ERROR", "No se encontro servers.bin junto al script.")
            doc = decode(asset_path.read_bytes())
            info = {"source": "bundled asset servers.bin"}
            info.update(summary(doc))
        elif args.url is not None:
            doc, info = fetch_catalog(args.url)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            doc = decode(raw)
            info = summary(doc)
        elif args.file is not None:
            doc = decode(_read(args.file))
            info = summary(doc)
        else:
            parser.error("se requiere un archivo, --url, --asset o --stdin (o --self-test)")
        rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        if args.summary or args.output:
            print(json.dumps(info, ensure_ascii=False), file=sys.stderr)
        if not args.output:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
