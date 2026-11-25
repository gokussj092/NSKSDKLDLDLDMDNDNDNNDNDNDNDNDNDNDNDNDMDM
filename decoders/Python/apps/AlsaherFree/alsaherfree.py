#!/usr/bin/env python3
"""ALSAHERFREE 1.0.5 (com.alsaher.vpnFree, versionCode 6): catalog decoder.

Standard library only.

Method verified in the APK (CB Tunnel Plus base, package com.cbtunnel.plus):
  - Download: com.cbtunnel.plus.thread.checkUpdate$FetchJSON does a plain
    OkHttp GET on the stored CONFIG_URL, no headers of its own, no body,
    no auth (OkHttp 4.12.0 default User-Agent). The response body is a
    Base64 blob, not JSON.
  - Decrypt: com.cbtunnel.plus.utils.FileUtils.showJson applies
    XxTea.decryptBase64StringToString(blob, "4669") and then subtracts
    4669 from every UTF-16 code unit twice (De2, FileUtils._De). The
    XXTEA DELTA in this APK's XxTea class is the non-standard value
    772515655; the key is the fixed pass "4669" (FileUtils.getPass),
    zero-padded to 16 bytes. The same showJson is applied field by
    field to ServerIP / ServerCloudFront / ServerHTTP / ProxyHost /
    Username / Password / ovpnCertificate, to SSLSNI / SSLPayload /
    NetworkPayload / SquidProxy, and to config_url / account_api /
    upload_get_api / upload_post_api / AppConfPass. Values that do not
    decrypt are kept as-is (the app's showJson returns the input on
    failure), and plaintext JSON starting with "{" passes through.
  - Update chain: OpenVPNClient.autoUpdate fetches CONFIG_URL; if the
    remote "Version" is newer than the stored CONFIG_VERSION it replaces
    Servers / HTTPNetworks / SSLNetworks (keeping user-added entries)
    and stores the new file's config_url as the next CONFIG_URL.
    First run loads the bundled asset mtkConfig.zip -> mtk.hs instead:
    that file is only the CB Tunnel template config ("Neuralqubit"
    9.9.9, demo servers), NOT Alsaher data.
  - serverType: 0=OVPN, 1=SSH, 2=DNS, 3=V2RAY, 4=UDP_HYSTERIA_V1.
    proto_spin (networks): 0=HTTP, 1=UDP, 2=SLOWDNS, 3=SSL,
    4=SSL+PAYLOAD, 5=SSL+PROXY.
  - No custom text-link scheme is defined by the app (no BROWSABLE
    intent filter, no vmess:// / vless:// / trojan:// strings in the
    DEX). V2Ray links only appear as data: in v2ray.json the
    ServerCloudFront field of serverType-3 servers holds vmess://,
    vless:// or full V2Ray JSON configs. Config import is by pasting
    an encrypted (hideJson) blob from the clipboard, or by importing
    a .ovpn file; there is no proprietary file extension of its own
    (the encrypted blob format is what assets/mtk.hs uses).

Live state (2026-11-25, verified with this script):
  - The URL hardcoded in the APK,
    https://raw.githubusercontent.com/Skytells0/Alsaher/main/Alsaherfree.json
    returns HTTP 404: the file was renamed to Alsaherjihad.json in the
    repo (commit 956dcdc, 2026-11-22). The app 1.0.5 therefore cannot
    update its catalog until it is rebuilt with the new name.
  - Live catalog (renamed file): HTTP 200, 38989 bytes,
    FileName "ALSAHER Free2028", Version 9.9.72, 4 servers (all SSH,
    Category "0", AutoLogin true), 0 HTTP networks, 8 SSL networks
    (2 with a payload, 8 with SNI). Its config_url chains to
    jihadvip.json (Version 9.9.58, lower, so it does not replace it).
  - The same repo holds three related catalogs in the same format,
    none of them fetched by this APK: Miro.json ("ALSAHER free FREE
    vip0100000", 9.9.58, 6 servers, 26 HTTP + 32 SSL networks),
    jihadvip.json ("ALSAHER VIPo20", 9.9.58, 14 servers, 3 HTTP +
    9 SSL networks) and v2ray.json ("ALSAHER free v2ray1", 9.9.47,
    18 V2Ray servers, 0 networks). Use --url with any of them.
  - cloud_get_api / cloud_post_api are empty in all four files; the
    only "cloud" is the public GitHub raw hosting. The servers carry
    shared SSH usernames/passwords, so the full decrypted catalog is
    credentials-bearing: keep it out of the ZIP/Drive deliverable.

The JSON this script prints is the decrypted catalog data only. It
does not add the download endpoint to the result.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import os
from pathlib import Path
import re
import sys
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 1_000_000
# Live catalog: the file the APK hardcodes was renamed on 2026-11-22.
CATALOG_URL = "https://raw.githubusercontent.com/Skytells0/Alsaher/main/Alsaherjihad.json"
# URL baked into APK 1.0.5; HTTP 404 since the 2026-11-22 rename.
LEGACY_URL = "https://raw.githubusercontent.com/Skytells0/Alsaher/main/Alsaherfree.json"
# Related catalogs in the same repo, same format, not fetched by this APK.
VIP_URL = "https://raw.githubusercontent.com/Skytells0/Alsaher/main/jihadvip.json"
MIRO_URL = "https://raw.githubusercontent.com/Skytells0/Alsaher/main/Miro.json"
V2RAY_URL = "https://raw.githubusercontent.com/Skytells0/Alsaher/main/v2ray.json"
# The app fetches with OkHttp and sets no headers of its own.
USER_AGENT = "okhttp/4.12.0"
# Fixed pass from FileUtils.getPass(); shared format key, not an account credential.
CATALOG_PASS = b"4669"
# Non-standard DELTA in this APK's XxTea class.
XXTEA_DELTA = 772515655
LIST_FIELDS = ("Servers", "HTTPNetworks", "SSLNetworks")
SERVER_ENCRYPTED_FIELDS = (
    "ServerIP", "ServerCloudFront", "ServerHTTP", "ProxyHost",
    "Username", "Password", "ovpnCertificate",
)
NETWORK_ENCRYPTED_FIELDS = ("SSLSNI", "SSLPayload", "NetworkPayload", "SquidProxy")
TOP_ENCRYPTED_FIELDS = (
    "config_url", "account_api", "upload_get_api", "upload_post_api", "AppConfPass",
)
_MASK = 0xFFFFFFFF
# Synthetic self-test vector: hideJson of
# {"FileName":"self-test","Version":"99.9", ... 1 SSH server, 1 HTTP payload}
_SELF_TEST_VECTOR = (
    "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"
)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _u32(x: int) -> int:
    return x & _MASK


def _to_int_array(data: bytes, include_length: bool) -> list[int]:
    n = (len(data) + 3) // 4
    arr = [0] * (n + (1 if include_length else 0))
    for i, b in enumerate(data):
        arr[i >> 2] |= b << ((i & 3) << 3)
    if include_length:
        arr[n] = len(data)
    return arr


def _to_byte_array(arr: list[int], include_length: bool) -> bytes | None:
    n = len(arr) << 2
    if include_length:
        m = arr[-1]
        if m < n - 7 or m > n - 4:
            return None
        n = m
    out = bytearray()
    for i in range(n):
        out.append((arr[i >> 2] >> ((i & 3) << 3)) & 0xFF)
    return bytes(out)


def _fix_key(key: bytes) -> bytes:
    if len(key) == 16:
        return key
    k = bytearray(16)
    k[:min(len(key), 16)] = key[:16]
    return bytes(k)


def _mx(sum_: int, y: int, z: int, p: int, e: int, k: list[int]) -> int:
    # Java MX: ((sum ^ y) + (k[(p&3)^e] ^ z)) ^ (((z>>>5) ^ (y<<2)) + ((y>>>3) ^ (z<<4)))
    # >>> is a LOGICAL shift; all arithmetic is mod 2**32.
    a = _u32(_u32(sum_ ^ y) + _u32(k[(p & 3) ^ e] ^ z))
    b = _u32(_u32((z >> 5) ^ _u32(y << 2)) + _u32((y >> 3) ^ _u32(z << 4)))
    return _u32(a ^ b)


def xxtea_decrypt(data: bytes, key: bytes = CATALOG_PASS, delta: int = XXTEA_DELTA) -> bytes | None:
    if len(data) == 0:
        return data
    v = _to_int_array(data, False)
    k = _to_int_array(_fix_key(key), False)
    n = len(v)
    if n < 2:
        return data
    rounds = (52 // n) + 6
    s = _u32(rounds * delta)
    y = v[0]
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = _u32(v[p] - _mx(s, y, z, p, e, k))
            v[p] = y
        z = v[n - 1]
        y = _u32(v[0] - _mx(s, y, z, 0, e, k))
        v[0] = y
        s = _u32(s - delta)
    return _to_byte_array(v, True)


def xxtea_encrypt(data: bytes, key: bytes = CATALOG_PASS, delta: int = XXTEA_DELTA) -> bytes:
    v = _to_int_array(data, True)
    k = _to_int_array(_fix_key(key), False)
    n = len(v)
    rounds = (52 // n) + 6
    s = 0
    z = v[n - 1]
    for _ in range(rounds):
        s = _u32(s + delta)
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = _u32(v[p] + _mx(s, y, z, p, e, k))
            v[p] = z
        y = v[0]
        z = _u32(v[n - 1] + _mx(s, y, z, n - 1, e, k))
        v[n - 1] = z
    return _to_byte_array(v, False)


def _shift_chars(s: str, amount: int) -> str:
    # Java char arithmetic wraps mod 65536.
    return "".join(chr((ord(c) + amount) % 65536) for c in s)


def _split_astral(s: str) -> str:
    # Java works on UTF-16 code units: split astral chars into surrogate pairs.
    out = []
    for ch in s:
        o = ord(ch)
        if o > 0xFFFF:
            o -= 0x10000
            out.append(chr(0xD800 + (o >> 10)))
            out.append(chr(0xDC00 + (o & 0x3FF)))
        else:
            out.append(ch)
    return "".join(out)


def show_json(blob: str) -> str | None:
    """Replicates FileUtils.showJson; None when the blob does not decrypt."""
    try:
        raw = base64.b64decode(blob.strip(), validate=False)
    except (ValueError, binascii.Error):
        return None
    pt = xxtea_decrypt(raw)
    if pt is None:
        return None
    try:
        txt = pt.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None
    out = _shift_chars(_shift_chars(txt, -4669), -4669)
    # Java stores astral chars (emoji) as UTF-16 surrogate pairs; merge them.
    try:
        out = out.encode("utf-16", "surrogatepass").decode("utf-16")
    except Exception:
        pass
    return out


def hide_json(plain: str) -> str:
    """Replicates FileUtils.hideJson (inverse of show_json)."""
    plain = _split_astral(plain)
    shifted = _shift_chars(_shift_chars(plain, 4669), 4669)
    return base64.b64encode(xxtea_encrypt(shifted.encode("utf-8"))).decode()


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La entrada no es UTF-8 válido.") from exc
    return value.strip()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("SIZE_LIMIT", "El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("INVALID_JSON", "Número JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("INVALID_JSON", "Unicode JSON inválido.") from exc
    return doc


def _json(data):
    try:
        # strict=False: the live catalog carries raw control characters
        # inside string values (org.json tolerates them, as does the app).
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_nonfinite, strict=False)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("INVALID_JSON", "JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("WRONG_DOCUMENT", "El catálogo debe contener un objeto JSON.")
    return _validate(doc)


def _show_field(value):
    """showJson on one catalog field; the app keeps the raw value on failure."""
    if not isinstance(value, str) or value == "":
        return value
    result = show_json(value)
    return value if result is None or result == "" else result


def decrypt_catalog_text(data: bytes | str) -> str:
    text = _text(data)
    if text.startswith("{"):
        return text  # showJson returns plaintext unchanged when it cannot decode it.
    result = show_json(text)
    if result is None or result == "":
        raise DecodeError("DECRYPT_FAILED", "No se pudo descifrar este catálogo.")
    return result


def decode(data: bytes | str) -> dict:
    doc = _json(decrypt_catalog_text(data))
    if not any(field in doc for field in LIST_FIELDS):
        raise DecodeError("WRONG_DOCUMENT", "No hay listas de servidores o redes en el catálogo.")
    for field in LIST_FIELDS:
        if field in doc and (not isinstance(doc[field], list) or any(not isinstance(v, dict) for v in doc[field])):
            raise DecodeError("WRONG_DOCUMENT", "Las listas de catálogo deben contener objetos completos.")
    # Field-level showJson, exactly as the app applies it when loading a server/network.
    for field in TOP_ENCRYPTED_FIELDS:
        if field in doc:
            doc[field] = _show_field(doc[field])
    for server in doc.get("Servers", []):
        for field in SERVER_ENCRYPTED_FIELDS:
            if field in server:
                server[field] = _show_field(server[field])
    for net_field in ("HTTPNetworks", "SSLNetworks"):
        for net in doc.get(net_field, []):
            for field in NETWORK_ENCRYPTED_FIELDS:
                if field in net:
                    net[field] = _show_field(net[field])
    return doc


def summary(doc: dict) -> dict:
    """Counts only: version plus the length of each catalog list. No values."""
    out = {"FileName": doc.get("FileName"), "Version": doc.get("Version")}
    for field in LIST_FIELDS:
        if field in doc:
            out[field] = len(doc[field])
    http = doc.get("HTTPNetworks") or []
    ssl = doc.get("SSLNetworks") or []
    out["HTTPPayloads"] = sum(1 for n in http if isinstance(n, dict) and (n.get("NetworkPayload") or "").strip())
    out["SSLPayloads"] = sum(1 for n in ssl if isinstance(n, dict) and (n.get("SSLPayload") or "").strip())
    out["SSLSNIs"] = sum(1 for n in ssl if isinstance(n, dict) and (n.get("SSLSNI") or "").strip())
    return out


def run(file_bytes: bytes | str) -> str | None:
    """Offline API: complete catalog JSON or None; never a partial list."""
    try:
        return json.dumps(decode(file_bytes), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except DecodeError:
        return None


class _HTTPSRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_catalog(url: str = CATALOG_URL) -> bytes:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("invalid HTTPS URL")
        req = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        with build_opener(_HTTPSRedirect()).open(req, timeout=30) as response:
            if response.status != 200:
                raise OSError("unexpected HTTP status")
            data = response.read(MAX_BYTES + 1)
    except HTTPError as exc:
        code = "ACCESS_DENIED" if exc.code in (401, 403) else "DOWNLOAD_FAILED"
        raise DecodeError(code, "El endpoint no devolvió un catálogo accesible.") from exc
    except (OSError, ValueError, URLError, HTTPException) as exc:
        raise DecodeError("DOWNLOAD_FAILED", "No se pudo descargar el catálogo mediante HTTPS.") from exc
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La respuesta supera el límite de tamaño.")
    return data


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def _write_output(path: Path, rendered: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, rendered.encode("utf-8"))
    finally:
        os.close(fd)


def _self_test() -> dict:
    checks = {}
    # 1. Synthetic hideJson envelope (same method, Version 99.9).
    doc = decode(_SELF_TEST_VECTOR)
    checks["synthetic_envelope"] = (
        doc.get("Version") == "99.9"
        and len(doc.get("Servers", [])) == 1
        and len(doc.get("HTTPNetworks", [])) == 1
        and doc["Servers"][0].get("ServerIP") == "example.invalid"
    )
    # 2. hide/show round trip is byte-identical for a live-style blob.
    checks["hide_show_roundtrip"] = show_json(hide_json('{"Version":"1.0"}')) == '{"Version":"1.0"}'
    # 3. Plain JSON passes through unchanged (as showJson does on failure).
    checks["plain_json_passthrough"] = decode('{"Version":"1.0","Servers":[]}').get("Version") == "1.0"
    # 4. Garbage is rejected, not invented.
    try:
        decode("aGVsbG8gd29ybGQ=")
        checks["garbage_rejected"] = False
    except DecodeError:
        checks["garbage_rejected"] = True
    checks["ok"] = all(checks.values())
    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", type=Path, help="Respuesta del catálogo guardada localmente (o assets/mtk.hs del APK)")
    source.add_argument("--url", nargs="?", const=CATALOG_URL, help="Descarga explícita; por defecto usa el catálogo vivo (renombrado)")
    parser.add_argument("--vip", action="store_true", help="Usa jihadvip.json en lugar del catálogo libre")
    parser.add_argument("--miro", action="store_true", help="Usa Miro.json en lugar del catálogo libre")
    parser.add_argument("--v2ray", action="store_true", help="Usa v2ray.json en lugar del catálogo libre")
    parser.add_argument("--legacy", action="store_true", help="Usa la URL original del APK (Alsaherfree.json, 404 desde 2026-11-22)")
    parser.add_argument("-o", "--output", type=Path, help="Guardar JSON completo con modo 0600; por defecto stdout")
    parser.add_argument("--summary", action="store_true", help="Imprimir solo versión y recuentos, sin valores")
    parser.add_argument("--self-test", action="store_true", help="Verifica el sobre sintético, el round-trip y el rechazo de basura")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result["ok"] else 1
        if args.url is not None:
            url = args.url
            if args.vip:
                url = VIP_URL
            elif args.miro:
                url = MIRO_URL
            elif args.v2ray:
                url = V2RAY_URL
            elif args.legacy:
                url = LEGACY_URL
            result = decode(fetch_catalog(url))
        elif args.file is not None:
            result = decode(_read(args.file))
        else:
            parser.error("se requiere un archivo, --url o --self-test")
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, rendered)
        if args.summary:
            sys.stdout.write(json.dumps(summary(result), ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        elif not args.output:
            sys.stdout.write(rendered)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
