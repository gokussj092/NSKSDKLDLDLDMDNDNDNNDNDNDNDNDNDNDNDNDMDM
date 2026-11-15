#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DocNet VPN - decodificador de catalogo para SP-DECODE
=====================================================
App: DocNet VPN
Paquete: tech.docnet.docnetvpn
Version: 6.1.4 (versionCode 314, minSdk 25)
Fuente: XAPK de APKPure (version de Google Play), SHA-256
  a20339c3bc46e59b55529669ab200ceafd2030b663a2ec4065cfce67f6b24076

Catalogo publico (FUNCIONA EN VIVO, sin autenticacion):
  GET https://docnet.tech/configs/
  Peticion exacta de la app (Dart http): GET plano, sin headers propios,
  sin autenticacion. Responde HTTP 200 con un JSON: una lista de configs.
  Verificado en vivo 2026-11-13: 591 configs (371 http, 220 tls),
  574 gratis, 17 premium.

Cada config trae metadatos completos (nombre, tipo, cdnName, operador,
forpremium, noteMsg, sshServerIP, votos, etc.) y el campo "config":
un blob Base64 con el payload cifrado.

ESTADO HONESTO DEL CIFRADO DEL PAYLOAD
---------------------------------------
El campo "config" esta cifrado con AES-256 (texto propio de la app:
"o encriptados com AES-256"). El descifrado NO se pudo recuperar
offline en esta version (6.1.4):
  * La app es Flutter (Dart AOT, libapp.so) + nucleo Go (libdocksocks.so).
  * En Dart no hay paquete de cifrado (no hay `encrypt`/PointyCastle);
    solo `package:crypto` (SHA-256/HMAC) y el AES del paquete `archive`
    (solo para entradas ZIP, funcion `_decodeAes` de ZipFile).
  * El nucleo Go es solo el motor del tunel (xray/tun2socks); recibe los
    campos ya descifrados desde Dart.
  * La clave NO es una cadena literal en el binario ni se deriva de
    ninguna cadena embebida con los KDF/modos estandar probados
    (SHA-256, PBKDF2-HMAC-SHA1 1000 iters, raw; CTR/CFB/OFB/CBC/GCM/
    ChaCha20-Poly1305; layouts con IV/nonce/salt al inicio y WinZip AES).
  * Estructura de los blobs: longitudes decodificadas siempre multiplo
    de 4 (591/591), NUNCA multiplo de 16 -> modo stream (CTR/CFB/OFB)
    o AEAD, NO CBC con PKCS7. El texto claro es un JSON como
    {"name":...,"type":"HTTP","payload":"GET / HTTP/1.1[crlf]...",
    "cdnName":"direct","isTls":false,"isQuic":false,"description":...}
    (muestra embebida en libapp.so).
  * El endpoint /api/* (servidores) exige header `X-API-Key` y la clave
    tampoco se recupero offline; los JWT de ejemplo embebidos en
    libapp.so estan caducados (exp sep/oct 2025).
  * Para abrir los payloads hace falta una captura en vivo en un
    telefono con la app oficial (proxy/Frida durante la descarga del
    catalogo) o la clave autorizada del emisor.

Por eso este script entrega el catalogo COMPLETO de metadatos y el
blob cifrado de cada config, y marca cada payload como
ENCRYPTED_AES256_PENDING en lugar de inventar un descifrado.

Esquemas de texto (deep links de importacion, verificados en el
AndroidManifest.xml de ESTE apk):
  * docnet://docnet.tech
  * https://import.docnet.tech
  Formato exacto del payload del enlace NO verificado (hace falta un
  enlace real generado por la app); el dialogo de importacion existe
  en la app ("Falha ao importar a configuracao").

Formatos de archivo: la app NO tiene formato propio importable
(no hay ACTION_VIEW para archivos ni extension propia en el manifest;
solo el deep link anterior). No hay .sks.

Uso:
  python3 DocNet_VPN.py --url            # descarga el catalogo en vivo
  python3 DocNet_VPN.py --url -o out.json
  python3 DocNet_VPN.py --file configs.json
  python3 DocNet_VPN.py --self-test
  python3 DocNet_VPN.py --url --summary  # resumen corto

Solo stdlib de Python 3.10+.
"""

import argparse
import base64
import binascii
import json
import os
import sys
import urllib.request
import urllib.error

CONFIGS_URL = "https://docnet.tech/configs/"
APP_PACKAGE = "tech.docnet.docnetvpn"
APP_VERSION = "6.1.4"
APP_VERSION_CODE = 314

# Muestra embebida de 5 configs reales (catalogo en vivo 2026-11-13),
# para --self-test sin red. Archivo junto a este script.
SAMPLE_FILE = "docnet_configs_sample.json"

PAYLOAD_STATUS = "ENCRYPTED_AES256_PENDING"


def _proxy_env():
    """(host, port, auth_header) desde https_proxy/HTTPS_PROXY, o None.
    Las credenciales del proxy rotan; se leen del entorno en cada
    llamada, nunca se guardan."""
    import re
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
    match = re.match(r"^https?://(?:([^:@]+):([^@]*)@)?([^:/]+):(\d+)", raw)
    if not match:
        return None
    user, password, host, port = match.groups()
    auth = None
    if user is not None:
        auth = "Basic " + base64.b64encode(
            ("%s:%s" % (user, password or "")).encode("utf-8")).decode("ascii")
    return host, int(port), auth


def fetch_catalog(url=CONFIGS_URL, timeout=60):
    """Descarga el catalogo exactamente como la app: GET plano, sin headers
    propios ni autenticacion. Devuelve (body_bytes, http_status).
    Notas:
    - El servidor bloquea el User-Agent por defecto de Python-urllib
      (HTTP 403); la app usa Dart http, asi que se envia su UA
      ("Dart/3.4 (dart:io)").
    - Se usa http.client directamente (nunca urllib: urllib anade
      `Connection: close`, que corta este endpoint a traves del proxy
      de salida). Un cuerpo truncado se reintenta con un GET nuevo
      (hasta 6 intentos) y solo se acepta el cuerpo completo segun
      Content-Length.
    """
    import http.client
    import time
    from urllib.parse import urlparse

    parsed = urlparse(url)
    last_error = None
    for attempt in range(6):
        proxy = _proxy_env()
        if proxy is not None:
            phost, pport, pauth = proxy
            conn = http.client.HTTPSConnection(phost, pport, timeout=timeout)
            tunnel_headers = {"Proxy-Authorization": pauth} if pauth else {}
            conn.set_tunnel(parsed.hostname, parsed.port or 443, tunnel_headers)
        else:
            conn = http.client.HTTPSConnection(
                parsed.hostname, parsed.port or 443, timeout=timeout)
        try:
            conn.putrequest("GET", parsed.path or "/")
            conn.putheader("User-Agent", "Dart/3.4 (dart:io)")
            conn.putheader("Accept-Encoding", "identity")
            conn.putheader("Connection", "keep-alive")
            conn.endheaders()
            resp = conn.getresponse()
            status = resp.status
            if status != 200:
                resp.read()
                raise urllib.error.HTTPError(
                    url, status, "HTTP %s" % status, resp.headers, None)
            expected = resp.getheader("Content-Length")
            try:
                body = resp.read()
            except http.client.IncompleteRead as e:
                body = e.partial or b""
            if expected is not None and len(body) != int(expected):
                last_error = "cuerpo incompleto: %d de %s bytes (intento %d)" % (
                    len(body), expected, attempt + 1)
                time.sleep(1)
                continue
            return body, status
        except urllib.error.HTTPError:
            raise
        except Exception as e:
            last_error = "%s (intento %d)" % (e, attempt + 1)
            time.sleep(1)
        finally:
            conn.close()
    raise RuntimeError("no se pudo descargar el catalogo completo: %s" % last_error)


def decode(data, source=""):
    """Decodifica el catalogo (bytes JSON o lista ya parseada).

    Devuelve un dict con:
      source, total, free, premium, by_type, by_operator, by_cdn,
      configs: lista de dicts con los metadatos de cada config y el
      blob cifrado (config_b64) + config_status.
    """
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8")
        raw = json.loads(text)
    elif isinstance(data, str):
        raw = json.loads(data)
    else:
        raw = data
    if not isinstance(raw, list):
        raise ValueError("el catalogo no es una lista JSON (se esperaba una lista de configs)")

    configs = []
    for c in raw:
        if not isinstance(c, dict):
            continue
        b64 = c.get("config") or ""
        blob = None
        blob_len = None
        blob_error = None
        if b64:
            try:
                blob = base64.b64decode(b64, validate=False)
                blob_len = len(blob)
            except (binascii.Error, ValueError) as e:
                blob_error = str(e)
        configs.append({
            "id": c.get("id", ""),
            "name": c.get("name", ""),
            "type": c.get("type", ""),
            "default": bool(c.get("default", False)),
            "cdnName": c.get("cdnName", ""),
            "noteMsg": c.get("noteMsg", ""),
            "operator": c.get("operator", ""),
            "sshServerIP": c.get("sshServerIP", ""),
            "SshServerPORT": c.get("SshServerPORT", ""),
            "SshServerName": c.get("SshServerName", ""),
            "Ssh": bool(c.get("Ssh", False)),
            "cdn": bool(c.get("cdn", False)),
            "multiproxy": bool(c.get("multiproxy", False)),
            "notes": bool(c.get("notes", False)),
            "downloaded": c.get("downloaded", 0),
            "cdnNumber": c.get("cdnNumber", 0),
            "testPriority": c.get("testPriority", 0),
            "onlines": c.get("onlines", 0),
            "votesPositives": c.get("votesPositives", 0),
            "votesNegatives": c.get("votesNegatives", 0),
            "forpremium": bool(c.get("forpremium", False)),
            "config_b64": b64,
            "config_bytes": blob_len,
            "config_status": PAYLOAD_STATUS if b64 else "EMPTY",
            "config_error": blob_error,
            "payload": None,  # cifrado AES-256; ver cabecera del script
        })

    by_type = {}
    by_operator = {}
    by_cdn = {}
    free = 0
    premium = 0
    for c in configs:
        by_type[c["type"]] = by_type.get(c["type"], 0) + 1
        by_operator[c["operator"]] = by_operator.get(c["operator"], 0) + 1
        by_cdn[c["cdnName"]] = by_cdn.get(c["cdnName"], 0) + 1
        if c["forpremium"]:
            premium += 1
        else:
            free += 1

    return {
        "source": source or CONFIGS_URL,
        "app_package": APP_PACKAGE,
        "app_version": APP_VERSION,
        "app_version_code": APP_VERSION_CODE,
        "total": len(configs),
        "free": free,
        "premium": premium,
        "by_type": by_type,
        "by_operator": by_operator,
        "by_cdn": by_cdn,
        "payload_note": (
            "Cada campo 'config' es un blob Base64 cifrado con AES-256. "
            "La clave no se recupero offline en la version 6.1.4; "
            "config_status = ENCRYPTED_AES256_PENDING. "
            "Hace falta una captura en vivo o la clave autorizada."
        ),
        "configs": configs,
    }


def summarize(result):
    lines = []
    lines.append("DocNet VPN %s (build %s) - catalogo %s" % (
        result["app_version"], result["app_version_code"], result["source"]))
    lines.append("Total: %d configs (%d gratis, %d premium)" % (
        result["total"], result["free"], result["premium"]))
    lines.append("Tipos: " + ", ".join(
        "%s %d" % kv for kv in sorted(result["by_type"].items())))
    top_ops = sorted(result["by_operator"].items(), key=lambda kv: -kv[1])[:5]
    lines.append("Operadores top: " + ", ".join(
        "%s %d" % kv for kv in top_ops))
    top_cdn = sorted(result["by_cdn"].items(), key=lambda kv: -kv[1])[:5]
    lines.append("CDN top: " + ", ".join("%s %d" % kv for kv in top_cdn))
    lines.append("Payloads: " + result["payload_note"])
    return "\n".join(lines)


def self_test():
    """Prueba sin red con la muestra embebida (5 configs reales)."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, SAMPLE_FILE)
    with open(path, "rb") as f:
        data = f.read()
    result = decode(data, source=SAMPLE_FILE)
    checks = []
    checks.append(("total == 5", result["total"] == 5))
    checks.append(("todos con config_b64", all(
        c["config_b64"] for c in result["configs"])))
    checks.append(("todos ENCRYPTED_AES256_PENDING", all(
        c["config_status"] == PAYLOAD_STATUS for c in result["configs"])))
    checks.append(("blobs decodifican Base64", all(
        isinstance(c["config_bytes"], int) and c["config_bytes"] > 0
        for c in result["configs"])))
    checks.append(("longitudes blob multiplo de 4", all(
        c["config_bytes"] % 4 == 0 for c in result["configs"])))
    checks.append(("tipos http/tls presentes", set(
        result["by_type"]) <= {"http", "tls"} and len(result["by_type"]) >= 1))
    checks.append(("metadatos presentes", all(
        c["name"] and c["type"] and c["operator"] is not None
        for c in result["configs"])))
    ok = all(v for _, v in checks)
    for name, v in checks:
        print(("OK  " if v else "FAIL") + "  " + name)
    print("self-test: %d/%d" % (sum(1 for _, v in checks if v), len(checks)))
    return 0 if ok else 1


def run(argv=None):
    p = argparse.ArgumentParser(
        description="DocNet VPN %s - catalogo de configs (SP-DECODE)" % APP_VERSION)
    p.add_argument("--url", nargs="?", const=CONFIGS_URL, default=None,
                   help="descargar el catalogo en vivo (por defecto %s)" % CONFIGS_URL)
    p.add_argument("--file", help="catalogo JSON local (lista de configs)")
    p.add_argument("-o", "--output", help="escribir el resultado JSON en este archivo")
    p.add_argument("--summary", action="store_true", help="mostrar solo el resumen")
    p.add_argument("--self-test", action="store_true", help="prueba sin red con la muestra embebida")
    args = p.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
        result = decode(data, source=args.file)
    elif args.url is not None:
        url = args.url
        try:
            body, status = fetch_catalog(url)
        except urllib.error.HTTPError as e:
            print("HTTP %s al descargar %s" % (e.code, url), file=sys.stderr)
            return 2
        except Exception as e:
            print("Error al descargar %s: %s" % (url, e), file=sys.stderr)
            return 2
        if status != 200:
            print("HTTP %s al descargar %s" % (status, url), file=sys.stderr)
            return 2
        result = decode(body, source=url)
    else:
        p.print_help()
        return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(summarize(result))
        print("Guardado en %s" % args.output)
    elif args.summary:
        print(summarize(result))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(run())
