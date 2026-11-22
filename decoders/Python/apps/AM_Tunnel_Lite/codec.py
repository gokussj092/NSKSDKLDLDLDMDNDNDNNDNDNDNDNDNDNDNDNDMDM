#!/usr/bin/env python3
"""AM Tunnel Lite (app.vpn.amtunnellite) 63 ("AM") — codec de catalogo.

Adapted from the dossier deliverable ``amtunnel.py`` (analysis
``app.vpn.amtunnellite/63/``); same algorithm and behaviour, no rewrite.
Only the module interface follows the server pattern (``DecodeError``,
``MAX_BYTES``, ``decode_catalog`` / ``render`` / ``run`` contract).

Scheme (recovered from the DEX: ``LQf::run`` + ``Ltm`` + ``LfY::m``):
  HTTP body (Base64, may carry spaces/newlines)
    -> strip ' ' and '\\n'  (as LQf.run does)
    -> Base64-decode       (LfY.m: tolerant standard Base64)
    -> XXTEA-decrypt       (Ltm.b; static key Ltm.a = '...|...')
    -> JSON UTF-8

The XXTEA key is the literal ``'...|...'`` (7 UTF-8 bytes, zero-padded
to 16 bytes per Ltm.b). The delta is NOT the standard 0x9E3779B9: the
code uses the literal -1638454863 == 0x9E5729B1 (verified: the standard
delta does not open the live or the embedded catalog; 0x9E5729B1 opens
both).

Endpoint: GET https://freedomnavigate.com/updater/8112011e98856d3ca814d0f8ce3231
  Without an Android UA the server answers 403 (LiteSpeed). With an
  Android Chrome UA it answers 200. Every response is cut to multiples
  of 16 KiB, so the download is done by ranges with resumption (see
  ``server_catalog_decoder.py``). No authentication, no session, no
  redirects.

Python >=3.10, standard library only.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import urllib.error
import urllib.request

CATALOG_URL = "https://freedomnavigate.com/updater/8112011e98856d3ca814d0f8ce3231"
ANDROID_UA = ("Mozilla/5.0 (Linux; Android 14; Redmi 14C) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")
XXTEA_KEY = b"...|..."            # Ltm.a (Deobfuscator getString, DEX2)
XXTEA_DELTA = 0x9E5729B1          # literal -1638454863 de Ltm.b / Ltm.d
CHUNK = 16384                     # the server cuts every response to 16 KiB
MAX_BYTES = 8 * 1024 * 1024

_M32 = 0xFFFFFFFF
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class DecodeError(ValueError):
    """The catalog bytes are not a complete AM Tunnel Lite catalog."""


# ---------------------------------------------------------------- XXTEA (Ltm)
def _mx(sum_, y, z, p, e, k):
    r0 = ((((z >> 5) & _M32) ^ ((y << 2) & _M32))
          + (((y >> 3) & _M32) ^ ((z << 4) & _M32))) & _M32
    return ((((sum_ ^ y) & _M32) + ((k[(p & 3) ^ e] ^ z) & _M32)) & _M32
            ^ r0) & _M32


def _to_words(data: bytes, include_length: bool):
    n = (len(data) + 3) // 4
    v = [0] * (n + (1 if include_length else 0))
    for i, b in enumerate(data):
        v[i >> 2] |= (b & 0xFF) << ((i & 3) << 3)
    if include_length:
        v[n] = len(data)
    return v


def _to_bytes(v, include_length: bool):
    n = len(v) << 2
    if include_length:
        length = v[-1]
        if length < n - 7 or length > n - 4:
            return None
        n = length
    return bytes((v[i >> 2] >> ((i & 3) << 3)) & 0xFF for i in range(n))


def _key_words(key: bytes):
    k = bytearray(16)
    k[:min(16, len(key))] = key[:16]
    return _to_words(bytes(k), False)


def xxtea_decrypt(data: bytes, key: bytes = XXTEA_KEY,
                  delta: int = XXTEA_DELTA) -> bytes | None:
    """Ltm.b: XXTEA-decrypt with trailing length word (includeLength)."""
    v = _to_words(data, False)
    k = _key_words(key)
    n = len(v)
    if n < 2:
        return data
    rounds = (52 // n) + 6
    sum_ = (rounds * delta) & _M32
    y = v[0]
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - _mx(sum_, y, z, p, e, k)) & _M32
        z = v[n - 1]
        y = v[0] = (v[0] - _mx(sum_, y, z, 0, e, k)) & _M32
        sum_ = (sum_ - delta) & _M32
    return _to_bytes(v, True)


def xxtea_encrypt(data: bytes, key: bytes = XXTEA_KEY) -> bytes:
    """Ltm.d: XXTEA-encrypt (inverse of xxtea_decrypt). Only for tests."""
    v = _to_words(data, True)
    k = _key_words(key)
    n = len(v)
    if n < 2:
        return data
    rounds = (52 // n) + 6
    sum_ = 0
    z = v[n - 1]
    for _ in range(rounds):
        sum_ = (sum_ + XXTEA_DELTA) & _M32
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = v[p] = (v[p] + _mx(sum_, y, z, p, e, k)) & _M32
        y = v[0]
        z = v[n - 1] = (v[n - 1] + _mx(sum_, y, z, n - 1, e, k)) & _M32
    return _to_bytes(v, False)


# ---------------------------------------------------------------- catalogo
def decode_catalog_b64(b64_text: bytes | str) -> dict:
    """Decrypt a catalog Base64 body and return the complete JSON."""
    if isinstance(b64_text, str):
        b64_text = b64_text.encode("utf-8")
    # LQf.run: strip spaces and newlines before decrypting.
    cleaned = b64_text.replace(b" ", b"").replace(b"\n", b"").replace(b"\r", b"")
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except binascii.Error:
        try:
            raw = base64.b64decode(cleaned, validate=False)
        except (binascii.Error, ValueError) as exc:
            raise DecodeError("El cuerpo no es Base64 valido.") from exc
    try:
        plain = xxtea_decrypt(raw)
    except (ValueError, IndexError) as exc:
        raise DecodeError("XXTEA: descifrado invalido.") from exc
    if plain is None:
        raise DecodeError("XXTEA: palabra de longitud invalida (clave/delta?)")
    try:
        doc = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise DecodeError("El catalogo descifrado no es JSON UTF-8.") from exc
    validate_catalog(doc)
    return doc


def decode_catalog(data: bytes) -> dict:
    """Decrypt one complete catalog body (remote bytes or pdrv2.json)."""
    if not isinstance(data, bytes) or not data:
        raise DecodeError("Catalogo vacio.")
    if len(data) > MAX_BYTES:
        raise DecodeError("El catalogo supera el limite de tamano.")
    if data.lstrip().startswith(b"<"):
        raise DecodeError("El catalogo es HTML, no un catalogo AM.")
    return decode_catalog_b64(data)


def render(doc: dict) -> str:
    """Render the complete catalog document, preserving every field."""
    return json.dumps(doc, ensure_ascii=False, indent=2)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code,
                                     "redirect no permitido: %s" % newurl,
                                     headers, fp)


def fetch_catalog(url: str = CATALOG_URL, timeout: int = 60,
                  max_retries: int = 8) -> tuple[bytes, int]:
    """GET with Android UA and ranged download (the server cuts at 16 KiB).

    The server/proxy closes the connection mid-response (sometimes with
    0 bytes read); each range is retried from the last good byte until
    complete. Returns (raw Base64 body, total length). No redirects.
    Uses the environment proxy (HTTPS_PROXY) if defined.
    """
    import http.client
    import time

    opener = urllib.request.build_opener(_NoRedirect,
                                         urllib.request.ProxyHandler())
    body = bytearray()
    total = None
    start = 0
    retries = 0
    while total is None or start < total:
        end = start + CHUNK - 1
        req = urllib.request.Request(url, headers={
            "User-Agent": ANDROID_UA,
            "Range": "bytes=%d-%d" % (start, end),
            "Accept": "*/*",
        })
        try:
            with opener.open(req, timeout=timeout) as resp:
                if resp.status == 206:
                    cr = resp.headers.get("Content-Range", "")
                    m = re.match(r"bytes \d+-\d+/(\d+)", cr)
                    if m:
                        total = int(m.group(1))
                elif resp.status == 200:
                    total = int(resp.headers.get("Content-Length", "0") or 0)
                else:
                    raise urllib.error.HTTPError(
                        url, resp.status,
                        "HTTP %s inesperado" % resp.status, resp.headers, None)
                try:
                    chunk = resp.read()
                except http.client.IncompleteRead as e:
                    chunk = e.partial  # bytes that did arrive before the cut
        except (http.client.HTTPException, urllib.error.URLError,
                TimeoutError, OSError) as e:
            retries += 1
            if retries > max_retries:
                raise IOError("descarga abandonada en %d/%s: %s"
                              % (start, total, e))
            time.sleep(min(2.0, 0.25 * retries))
            continue
        if not chunk:
            retries += 1
            if retries > max_retries:
                raise IOError("descarga cortada en %d/%s (sin bytes)"
                              % (start, total))
            time.sleep(min(2.0, 0.25 * retries))
            continue
        retries = 0
        body += chunk
        start += len(chunk)
        if total is not None and len(body) >= total:
            break
    if total is not None and len(body) != total:
        raise IOError("descarga incompleta: %d de %d B" % (len(body), total))
    return bytes(body), (total if total is not None else len(body))


def validate_catalog(doc: dict) -> None:
    """Minimal structural check of the decrypted catalog."""
    if not isinstance(doc, dict):
        raise DecodeError("el catalogo no es un objeto JSON")
    for key in ("Version", "Free_servers", "Payloads"):
        if key not in doc:
            raise DecodeError("falta la clave %r en el catalogo" % key)
    if not isinstance(doc["Free_servers"], list):
        raise DecodeError("Free_servers no es una lista")
    if not isinstance(doc["Payloads"], list):
        raise DecodeError("Payloads no es una lista")


def sanitize_catalog(doc: dict) -> dict:
    """Sanitized version of the catalog, for saving/sharing.

    Credential values (host/user/password) and literal IPs inside
    payload templates are redacted; structure and counts are kept.
    The complete catalog is reproduced by running this same module
    without --sanitize.
    """
    out = json.loads(json.dumps(doc))  # deep copy
    out["Username"] = "[redacted]"
    out["Password"] = "[redacted]"
    for srv in out.get("Free_servers", []):
        hosts = srv.pop("server_host", "")
        if isinstance(hosts, list):
            count = len(hosts)
        elif isinstance(hosts, str):
            # server_host is a string with ';'-separated endpoints
            count = len([h for h in hosts.split(";") if h])
        else:
            count = 0
        srv["server_host_count"] = count
        srv["server_host"] = "[redacted]"
        srv["username"] = ""
        srv["password"] = ""
    for pay in out.get("Payloads", []):
        if isinstance(pay.get("payload"), str):
            pay["payload"] = _IPV4_RE.sub("[IP]", pay["payload"])
        if isinstance(pay.get("message"), str):
            pay["message"] = _IPV4_RE.sub("[IP]", pay["message"])
    return out


# Synthetic self-test vector: JSON encrypted with Ltm.d + Base64 (real
# key). Generated with xxtea_encrypt(); contains no real catalog data.
_SELF_TEST_B64 = ("GRhNArfpMxuBxmeOj7emYqZAqI6P5v+MomSv9RyuyFOygjaYQB1JwiN2epU/"
                   "zoN4xB67RFkOkltLo80oBSkxA5QtIV2R1kj8hrB/Y5p4Oj2V1j5R99jznXHyZ0k5D7f9F9dYP0IA0YpKt82UqWhI82O7K1le6SFJ")
_SELF_TEST_JSON = {"Version": "0.0", "Free_servers": [], "Payloads": [],
                   "UpdaterLink": "", "UDPVersion": "v2", "Changelogs": "test"}


def self_test() -> int:
    print("AM Tunnel Lite — self-test")
    ok = 0

    def check(name, cond):
        nonlocal ok
        print("  %s: %s" % ("ok" if cond else "FALLO", name))
        ok += bool(cond)

    # 1. XXTEA round-trip (Ltm.d -> Ltm.b) over a synthetic JSON.
    sample = json.dumps(_SELF_TEST_JSON, ensure_ascii=False).encode("utf-8")
    rt = xxtea_decrypt(xxtea_encrypt(sample))
    check("round-trip XXTEA sintetico", rt == sample)
    # 2. Known vector (encrypted with the real key/delta, synthetic JSON).
    doc = decode_catalog_b64(_SELF_TEST_B64)
    check("vector sintetico Base64+XXTEA", doc == _SELF_TEST_JSON)
    # 3. The standard delta must NOT open the vector (negative test).
    raw = base64.b64decode(_SELF_TEST_B64)
    std = xxtea_decrypt(raw, delta=0x9E3779B9)
    check("delta estandar rechaza el vector",
          std is None or std != sample)
    # 4. Structural validation.
    try:
        validate_catalog(doc)
        check("validate_catalog sintetico", True)
    except DecodeError:
        check("validate_catalog sintetico", False)
    # 5. Sanitized output: no hosts or credentials left.
    dirty = {"Username": "u", "Password": "p", "Version": "1.0",
             "Free_servers": [{"server_name": "X", "server_host": ["h1", "h2"],
                               "username": "u", "password": "p"}],
             "Payloads": [{"payload": "GET http://1.2.3.4/ HTTP/1.1",
                           "message": "ver 5.6.7.8"}]}
    clean = sanitize_catalog(dirty)
    check("sanitize redacta credenciales",
          clean["Username"] == "[redacted]"
          and clean["Password"] == "[redacted]"
          and clean["Free_servers"][0]["server_host"] == "[redacted]"
          and clean["Free_servers"][0]["server_host_count"] == 2
          and "1.2.3.4" not in clean["Payloads"][0]["payload"]
          and "5.6.7.8" not in clean["Payloads"][0]["message"])
    print("SELF-TEST OK (%d comprobaciones)" % ok if ok == 5
          else "SELF-TEST FALLO (%d/5)" % ok)
    return 0 if ok == 5 else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="AM Tunnel Lite 63 — catalogo para SP-DECODE")
    ap.add_argument("--url", default=CATALOG_URL, help="URL del catalogo")
    ap.add_argument("--b64", help="archivo .bin/.b64 con el catalogo crudo "
                                  "(en vez de descargar)")
    ap.add_argument("--output", help="archivo donde guardar el catalogo JSON")
    ap.add_argument("--raw-output", help="archivo donde guardar el catalogo "
                                         "crudo (Base64)")
    ap.add_argument("--sanitize", action="store_true",
                    help="redactar credenciales (host/usuario/contrasena) "
                         "e IPs en el JSON de salida")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.b64:
        with open(args.b64, "rb") as f:
            body = f.read()
        raw_len = len(body)
    else:
        print("Descargando catalogo de", args.url, file=sys.stderr)
        body, raw_len = fetch_catalog(args.url)
    print("Catalogo crudo: %d B Base64" % raw_len, file=sys.stderr)
    if args.raw_output:
        with open(args.raw_output, "wb") as f:
            f.write(body)
    doc = decode_catalog(body)
    if args.sanitize:
        doc = sanitize_catalog(doc)
    print("Catalogo Version %s: %d servidores libres, %d payloads"
          % (doc.get("Version"), len(doc.get("Free_servers", [])),
             len(doc.get("Payloads", []))), file=sys.stderr)
    out = render(doc)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
