#!/usr/bin/env python3
"""MT KING NET 15.35.2 (app.mtkingnet.buildd, versionCode 25) — catálogo Cloud.

Método (verificado en vivo 2026-11-14):
  Endpoint: GET https://isvsoft-vpn-worker.isvsoft.workers.dev/api/app
              ?json=0d1faab335584c37b40c142375a7f967&type=full   (o type=servers)
  Petición exacta de la app (OkHttp, interceptor ISVSOFT):
    User-Agent: ISVSOFT-CloudSync/2.0
    X-ISV-Timestamp: segundos unix actuales
    X-ISV-Nonce: UUID aleatorio sin guiones (32 hex)
    X-ISV-Signature: HMAC-SHA256(clave de formato, "ts:nonce:/api/app") en hex
    (la firma se calcula sobre el encodedPath "/api/app", SIN la query).
    Sin estos headers el worker responde 403 (sin UA: "Unauthorized Client
    User-Agent"; con UA pero sin firma: "Missing Native App-Proof
    credentials"; con firma inválida: "Invalid Native App-Proof signature";
    con firma vieja: "App-Proof handshake expired").
  Respuesta: JSON {meta, servers, tweaks, settings} donde cada valor
  sensible es "enc:<base64url>" y se abre con:
    AES-256-GCM, clave fija de formato (32 B ASCII, en libisvcrypto.so),
    nonce = primeros 12 B, tag = últimos 16 B, sin AAD.
    Sobre: base64url( nonce[12] || ct || tag[16] ).

  Catálogo en vivo (type=full, 2026-11-15): versión 21.31.299, 80 servidores
  (80 online), 367 tweaks (127 con payload HTTP, 211 con SNI), settings con
  predefinedCredentials y 1 certProfile. type=servers devuelve los mismos
  80 servidores sin tweaks/settings.
  Los assets incluidos en el APK son viejos (servers/tweaks/settings 1.0.0:
  9 servidores, 11 tweaks) y el worker sirve la versión 21.31.299: las
  listas difieren. Misma familia ISVSoft que TSC VPN Proxy (mismo worker,
  misma clave de formato, distinto json de app).

Python 3.10+, solo biblioteca estándar. AES-256-GCM en Python puro
(reutilizado del script SP-DECODE de RNV Tunnel VPN, mismo algoritmo).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import hmac as _hmac
import json
import os
import struct
import sys
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from http.client import HTTPException

# ---------------------------------------------------------------- constantes
CATALOG_HOST = "isvsoft-vpn-worker.isvsoft.workers.dev"
CATALOG_PATH = "/api/app"
CATALOG_JSON = "0d1faab335584c37b40c142375a7f967"
CATALOG_URL = (f"https://{CATALOG_HOST}{CATALOG_PATH}"
               f"?json={CATALOG_JSON}&type=full")
USER_AGENT = "ISVSOFT-CloudSync/2.0"
# Clave fija de formato (libisvcrypto.so, libisvcrypto; misma clave para el
# sobre AES-256-GCM y para la firma HMAC-SHA256 App-Proof).
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


def sign_proof(path: str, timestamp: str, nonce: str) -> str:
    """X-ISV-Signature: HMAC-SHA256(clave, 'ts:nonce:path') en hex minúsculas.

    El path es el encodedPath SIN query (la app firma '/api/app', no la URL
    completa). Verificado contra libisvcrypto.so (Unicorn) con dos pares
    conocidos; la firma es determinista para los mismos inputs.
    """
    msg = f"{timestamp}:{nonce}:{path}".encode("utf-8")
    return _hmac.new(FORMAT_KEY, msg, hashlib.sha256).hexdigest()


def decrypt_value(value):
    """Descifra recursivamente todos los valores 'enc:' de un documento."""
    if isinstance(value, dict):
        return {k: decrypt_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decrypt_value(v) for v in value]
    if isinstance(value, str) and value.startswith("enc:"):
        return decrypt_enc(value)
    return value


# ------------------------------------------------------------------- decode
def decode(data: bytes | str) -> dict:
    """Decodifica una respuesta del worker (bytes o str) -> dict descifrado.

    Falla cerrado (DecodeError) si el JSON no es un catálogo o si algún
    valor enc: no abre: nunca devuelve un catálogo parcial inventado.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError("BAD_UTF8", "La respuesta no es UTF-8.") from exc
    else:
        text = data
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DecodeError("BAD_JSON", "La respuesta no es JSON.") from exc
    if not isinstance(doc, dict) or "servers" not in doc:
        raise DecodeError("NOT_A_CATALOG",
                          "El JSON no es un catálogo MT KING NET (falta 'servers').")
    return decrypt_value(doc)


def summarize(doc: dict) -> dict:
    """Resumen del catálogo descifrado (versión, servidores, payloads)."""
    meta = doc.get("meta") or {}
    servers = doc.get("servers") or []
    tweaks = doc.get("tweaks") or []
    version = meta.get("serverVersion") or meta.get("version")
    return {
        "version": version,
        "servers": len(servers),
        "servers_online": sum(1 for s in servers if s.get("isOnline")),
        "tweaks": len(tweaks),
        "tweaks_with_payload": sum(1 for t in tweaks if t.get("payload")),
        "tweaks_with_sni": sum(1 for t in tweaks if t.get("sni")),
        "settings": bool(doc.get("settings")),
    }


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: catálogo descifrado como JSON, o None si no abre."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2,
                          allow_nan=False) + "\n"
    except DecodeError:
        return None


# ------------------------------------------------------------------ descarga
def _https_url(url: str):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid HTTPS URL")
    return parsed


def _proxy_for(host: str):
    import os
    from urllib.parse import urlsplit as _split
    no_proxy = os.environ.get("no_proxy", "") or os.environ.get("NO_PROXY", "")
    for entry in [e.strip().lower() for e in no_proxy.split(",") if e.strip()]:
        if host.lower() == entry or host.lower().endswith("." + entry.lstrip(".")):
            return None
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
    if not raw:
        return None
    parsed = _split(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    auth = None
    if parsed.username:
        auth = base64.b64encode(
            f"{parsed.username}:{parsed.password or ''}".encode("utf-8")).decode("ascii")
    return parsed.hostname, parsed.port or 3128, auth


def fetch_catalog(url: str = CATALOG_URL, retries: int = 8) -> bytes:
    """GET exactamente como la app: UA ISVSOFT-CloudSync/2.0 + X-ISV-*.

    La firma se calcula en el momento de cada intento (timestamp fresco y
    nonce nuevo); el worker rechaza firmas viejas ('handshake expired').
    Implementado con http.client (no urllib): en este entorno urllib
    trunca el body en algunas respuestas grandes.
    """
    parsed = _https_url(url)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    # El path firmado es solo el encodedPath, sin query.
    sign_path = parsed.path or "/"
    last_error: Exception | None = None
    for attempt in range(max(1, retries)):
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        signature = sign_proof(sign_path, timestamp, nonce)
        headers = {
            "User-Agent": USER_AGENT,
            "X-ISV-Timestamp": timestamp,
            "X-ISV-Nonce": nonce,
            "X-ISV-Signature": signature,
            "Accept-Encoding": "identity",
        }
        try:
            import http.client as _http
            import ssl as _ssl
            proxy = _proxy_for(host)
            if proxy is not None:
                proxy_host, proxy_port, proxy_auth = proxy
                conn = _http.HTTPConnection(proxy_host, proxy_port, timeout=30)
                tunnel_headers = {}
                if proxy_auth:
                    tunnel_headers["Proxy-Authorization"] = "Basic " + proxy_auth
                tunnel_headers["Proxy-Connection"] = "Keep-Alive"
                conn.set_tunnel(host, 443, headers=tunnel_headers)
                conn.connect()
                conn.sock = _ssl.create_default_context().wrap_socket(
                    conn.sock, server_hostname=host)
            else:
                conn = _http.HTTPSConnection(host, 443, timeout=30)
            try:
                conn.putrequest("GET", path, skip_host=False,
                                skip_accept_encoding=False)
                conn.putheader("Host", host)
                for name, value in headers.items():
                    conn.putheader(name, value)
                conn.endheaders()
                resp = conn.getresponse()
                if resp.status != 200:
                    body = resp.read(512)
                    raise DecodeError(
                        "ACCESS_DENIED" if resp.status in (401, 403) else "DOWNLOAD_FAILED",
                        f"El worker devolvió HTTP {resp.status}: "
                        f"{body[:200]!r}.")
                raw = resp.read(MAX_BYTES + 1)
                if resp.getheader("Content-Encoding", "identity") == "gzip":
                    raw = gzip.decompress(raw)
            finally:
                conn.close()
        except DecodeError:
            raise
        except (OSError, ValueError, URLError, HTTPException, gzip.BadGzipFile) as exc:
            last_error = exc
            if attempt + 1 < max(1, retries):
                time.sleep(1 + attempt)
            continue
        if not raw or len(raw) > MAX_BYTES or raw.lstrip().startswith(b"<"):
            raise DecodeError("DOWNLOAD_FAILED",
                              "Catálogo vacío, incompatible o superior a 8 MiB.")
        return raw
    raise DecodeError("DOWNLOAD_FAILED",
                      "No se pudo descargar el catálogo mediante HTTPS.") from last_error


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


# -------------------------------------------------------------------- tests
_SELF_TEST_VECTORS = [
    # (valor enc:, plaintext esperado) — vectores reales verificados.
    ("enc:CTl6T-nGkv948sNqdBiHELnrkdOR70BCg-qWA_dDtybYFVU8I7ftbQ",
     "78.46.243.53"),  # host del servidor 1 del asset servers.json
    ("enc:sVaP9sQH2A0YDebdTxhEAXodqQu4P2M2zK9-6ZsXaKXdtjHR16KlEYmlpV8",
     "udp.xkingdns.xyz"),  # host del servidor 1 del catálogo en vivo
    ("enc:l_qKr0K1fTp3u_umh0AHst3cux5YJbIr1QJwGUNVxqNR76vWT9SGGMQ",
     "m.youtube.com"),  # sni de un tweak del catálogo en vivo
]
_SELF_TEST_SIGNS = [
    # (path, timestamp, nonce, firma esperada) — verificadas contra la .so.
    ("/api/app", "1794680950", "c2081a132d2848cd8a648151a4e89b82",
     "8d957d7541bfb9f42fb7815ab20f7e99bf3894e444ea82b26d19c3a82d75a66c"),
    ("/api/app", "1794680615", "6730e238de3c4bd286687318612167d3",
     "4091e48cf6925115106bca649282ddcee2b26182db8870aef8a4513022a3fb6d"),
]


def self_test() -> dict:
    """Auto-prueba sin red: vectores enc:, firmas HMAC y round-trip."""
    checks = []
    for enc, want in _SELF_TEST_VECTORS:
        got = decrypt_enc(enc)
        checks.append(("decrypt", enc[:24], got == want))
        if got != want:
            raise DecodeError("SELF_TEST_FAIL",
                              f"decrypt_enc falló: {enc[:24]} -> {got!r} != {want!r}")
    for path, ts, nonce, want in _SELF_TEST_SIGNS:
        got = sign_proof(path, ts, nonce)
        checks.append(("signproof", ts, got == want))
        if got != want:
            raise DecodeError("SELF_TEST_FAIL",
                              f"sign_proof falló para ts={ts}: {got} != {want}")
    # Round-trip cifrado/descifrado + rechazo de tag alterado.
    for plain in ("hello.example.com", "udp.xkingdns.xyz", "GET / HTTP/1.1[crlf]"):
        enc = encrypt_enc(plain)
        if decrypt_enc(enc) != plain:
            raise DecodeError("SELF_TEST_FAIL", f"round-trip falló: {plain!r}")
        checks.append(("roundtrip", plain[:20], True))
    blob = bytearray(_b64url_decode(encrypt_enc("x")[4:]))
    blob[-1] ^= 1
    bad = "enc:" + base64.urlsafe_b64encode(bytes(blob)).decode("ascii").rstrip("=")
    try:
        decrypt_enc(bad)
    except DecodeError as exc:
        if exc.code != "DECRYPT_FAILED":
            raise
        checks.append(("tampered_tag_rejected", "", True))
    else:
        raise DecodeError("SELF_TEST_FAIL", "tag alterado aceptado (no debería).")
    # decode() sobre un mini-catálogo sintético con valores enc:.
    mini = json.dumps({
        "meta": {"serverVersion": "9.9-test"},
        "servers": [{"id": 1, "name": "T",
                     "host": _SELF_TEST_VECTORS[0][0], "isOnline": True}],
        "tweaks": [{"id": 1, "name": "T",
                    "sni": _SELF_TEST_VECTORS[2][0], "payload": "GET /"}],
        "settings": {}})
    doc = decode(mini)
    assert doc["servers"][0]["host"] == "78.46.243.53"
    assert doc["tweaks"][0]["sni"] == "m.youtube.com"
    checks.append(("decode_mini_catalog", "", True))
    return {"self_test": "OK", "checks": len(checks)}


# ---------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path,
                        help="Respuesta del catálogo guardada localmente")
    source.add_argument("--url", nargs="?", const=CATALOG_URL,
                        help="Descarga explícita; por defecto usa el endpoint original")
    source.add_argument("--stdin", action="store_true",
                        help="Leer la respuesta cifrada desde stdin")
    parser.add_argument("--type", choices=("full", "servers"), default="full",
                        help="Tipo de catálogo al descargar (por defecto full)")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON descifrado; por defecto stdout")
    parser.add_argument("--save-raw", type=Path,
                        help="Guardar también la respuesta cruda del worker")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica vectores enc:, firmas HMAC y round-trip (sin red)")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = self_test()
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if args.url is not None:
            url = args.url
            # El tipo pedido manda: sustituye type=... si ya está en la URL.
            import re as _re
            if _re.search(r"([?&])type=[^&]*", url):
                url = _re.sub(r"([?&])type=[^&]*", r"\1type=" + args.type, url)
            else:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}type={args.type}"
            raw = fetch_catalog(url)
            if args.save_raw:
                args.save_raw.write_bytes(raw)
        elif args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file is not None:
            raw = _read(args.file)
        else:
            parser.error("se requiere un archivo, --url o --stdin (o --self-test)")
        doc = decode(raw)
        rendered = json.dumps(doc, ensure_ascii=False, indent=2,
                              allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        print(json.dumps(summarize(doc), ensure_ascii=False), file=sys.stderr)
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
