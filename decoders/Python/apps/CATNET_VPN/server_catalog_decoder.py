#!/usr/bin/env python3
"""CATNET VPN | FAST SECURE VPN (net.catnet.vpn) 1.2.7 / build 29 — catálogo Cloud.

NOTA DE VERSIÓN: los resultados corresponden a la 1.2.7 (build 29, 9 nov 2026),
la versión más reciente disponible en los espejos. En Google Play la versión
pública actual es la 1.2.9 (13 nov 2026); ningún espejo la tenía todavía cuando
se hizo este análisis. El método se verificó en el APK 1.2.7 de APKPure.

MÉTODO (verificado en este APK, no asumido; coincide con la cobertura que ya
tiene SP-DECODE en decoders/Python/apps/CATNET_VPN/ para este mismo paquete
y build):
  1. Preflight: GET https://pussyvpn.com/xjvpn/mobile/public/app-update
     ?app_key=pussy_vpn&current_version_code=29
  2. Catálogo: GET https://pussyvpn.com/xjvpn/mobile/public/servers
  Cabeceras exactas de la app (ApiClient.java): X-XJ-App-Key / X-App-Key =
  "pussy_vpn" (identificador de cliente estático incluido en la APK, no una
  contraseña de cuenta), X-XJ-App-Package / X-App-Package / X-Package-Name /
  X-XJ-Package-Name = net.catnet.vpn, X-XJ-Version-Code = 29,
  X-XJ-Installation-Id = UUID nuevo por operación, User-Agent okhttp/4.12.0,
  Accept-Encoding: identity. Sin redirects, sin auth de cuenta.
  La respuesta del catálogo es JSON UTF-8 plano, sin cifrado:
  {"success": true, "servers": [{"id": int, "servername": str, "ip": str, ...}],
   "message": str, "has_defaults": bool, "def_user"/"def_pass_plain"/
   "back_user"/"back_pass_plain": str, ...}. Se conserva el documento completo.

ESTADO EN VIVO (2026-11-13, fallo honesto): el preflight responde HTTP 200
pero con "integrity_required": true y un "integrity_challenge". Sin un token
de Play Integrity válido (que solo puede emitir un dispositivo real con la
app oficial instalada desde Google Play), los endpoints devuelven HTTP 403:
{"success": false, "modified_app": true, "message": "This app installation
is not verified. Install the official XJ app from Google Play."}. Lo mismo
ocurre con /mobile/public/payloads y /mobile/public/xray_payloads, en
pussyvpn.com y en el host alternativo xjdev.net. Este script NO fabrica
Play Integrity ni sesiones: si el preflight exige verificación, se detiene
con CATNET_INTEGRITY_REQUIRED. El catálogo volverá a abrir sin cambios si
el servidor deja de exigir integridad (o con un token real de un dispositivo).
Las rutas de payloads/xray no forman parte del alcance del catálogo público
de servidores.

Archivos de configuración: la app no define ningún formato propio de archivo
(el manifest solo tiene MAIN/LAUNCHER; no hay intent-filter VIEW ni
asociación de extensiones) y no hay esquema URI de texto propio. Solo usa los
protocolos estándar (vmess/vless/ss/trojan, .ovpn) que SP-DECODE ya cubre.
Sin .sks. Por eso no hay script CATNET_VPN_archivos.py.

Uso:
  python3 CATNET_VPN.py --url [-o catalogo.json]   # descarga en vivo (preflight + servidores)
  python3 CATNET_VPN.py catalogo.json              # decodifica un JSON guardado
  python3 CATNET_VPN.py --stdin < catalogo.json
  python3 CATNET_VPN.py --self-test                # muestra de sintaxis válida + guardas
"""
import argparse
import base64
import http.client
import json
import os
import socket
import ssl
import sys
import time
import uuid
from urllib.parse import urlsplit

APP_PACKAGE = "net.catnet.vpn"
BUILD = 29
APP_KEY = "pussy_vpn"
USER_AGENT = "okhttp/4.12.0"
PREFLIGHT_URL = (
    "https://pussyvpn.com/xjvpn/mobile/public/app-update"
    "?app_key=pussy_vpn&current_version_code=" + str(BUILD)
)
SERVERS_URL = "https://pussyvpn.com/xjvpn/mobile/public/servers"
MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024


class CatalogError(ValueError):
    """Error de catálogo CATNET (descarga o formato inválido)."""


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise CatalogError("Duplicate JSON key: %r" % key)
        obj[key] = value
    return obj


def _constant(name):
    raise CatalogError("Invalid JSON constant: %s" % name)


def parse_document(text):
    """JSON estricto: objeto raíz, sin duplicados, sin NaN/Infinity, con
    límites de profundidad y nodos (igual que el codec del repo)."""
    try:
        obj = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
    except CatalogError:
        raise
    except (ValueError, RecursionError) as e:
        raise CatalogError("Invalid JSON: %s" % e) from e
    if not isinstance(obj, dict):
        raise CatalogError("Expected JSON object")
    pending = [(obj, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > 64 or nodes > 200000:
            raise CatalogError("JSON structure exceeds limits")
        if isinstance(value, dict):
            for key in value:
                if not isinstance(key, str):
                    raise CatalogError("Non-string JSON key")
                pending.append((value[key], depth + 1))
        elif isinstance(value, list):
            for item in value:
                pending.append((item, depth + 1))
    return obj


def decode_catalog(data):
    """Valida y devuelve el documento completo del catálogo de servidores.

    Mismo criterio que decoders/Python/apps/CATNET_VPN/codec.py: success
    true, lista de servidores no vacía, cada registro con id entero,
    servername e ip no vacíos; los campos opcionales de mensaje/defaults
    con sus tipos. No se descarta ningún campo: se conserva todo.
    """
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_INPUT:
        raise CatalogError("Invalid CATNET input size")
    try:
        doc = parse_document(data.decode("utf-8"))
    except (UnicodeError, RecursionError) as e:
        raise CatalogError("Invalid CATNET server catalog") from e
    rows = doc.get("servers")
    if doc.get("success") is not True or not isinstance(rows, list) or not rows:
        raise CatalogError("Invalid CATNET server catalog")
    for row in rows:
        if (
            not isinstance(row, dict)
            or type(row.get("id")) is not int
            or not 0 < row["id"] <= 9007199254740991
            or any(
                not isinstance(row.get(k), str) or not row[k]
                for k in ("servername", "ip")
            )
        ):
            raise CatalogError("Invalid CATNET server record")
    if "message" in doc and not isinstance(doc["message"], str):
        raise CatalogError("Invalid CATNET message")
    if "has_defaults" in doc and type(doc["has_defaults"]) is not bool:
        raise CatalogError("Invalid CATNET defaults flag")
    for key in ("def_user", "def_pass_plain", "back_user", "back_pass_plain"):
        if key in doc and not isinstance(doc[key], str):
            raise CatalogError("Invalid CATNET defaults")
    return doc


def decode(data):
    """Decodifica un catálogo CATNET (bytes) y devuelve el dict completo."""
    return decode_catalog(data)


def run(data):
    """Decodifica y renderiza el catálogo completo como JSON (str)."""
    out = json.dumps(
        decode_catalog(data), ensure_ascii=False, indent=2, allow_nan=False
    ).encode("utf-8")
    if len(out) > MAX_OUTPUT:
        raise CatalogError("CATNET result exceeds size limit")
    return out.decode("utf-8")


def original_headers():
    return {
        "X-XJ-App-Key": APP_KEY,
        "X-App-Key": APP_KEY,
        "X-XJ-App-Package": APP_PACKAGE,
        "X-App-Package": APP_PACKAGE,
        "X-Package-Name": APP_PACKAGE,
        "X-XJ-Package-Name": APP_PACKAGE,
        "X-XJ-Version-Code": str(BUILD),
        "X-XJ-Installation-Id": str(uuid.uuid4()),
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
    }


def _proxy_for(host):
    """Proxy del entorno (túnel CONNECT), o None para conexión directa."""
    no_proxy = os.environ.get("no_proxy", "") or os.environ.get("NO_PROXY", "")
    for entry in [e.strip().lower() for e in no_proxy.split(",") if e.strip()]:
        if host.lower() == entry or host.lower().endswith("." + entry.lstrip(".")):
            return None
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
    parsed = urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    auth = None
    if parsed.username:
        auth = base64.b64encode(
            ("%s:%s" % (parsed.username, parsed.password or "")).encode("utf-8")
        ).decode("ascii")
    return parsed.hostname, parsed.port or 3128, auth


def _get(url, headers, deadline):
    """Un GET con las cabeceras exactas de la app; rechaza redirects."""
    parsed = urlsplit(url)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    last_error = None
    for _attempt in range(2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CatalogError("CATNET deadline exceeded")
        try:
            proxy = _proxy_for(host)
            if proxy is not None:
                proxy_host, proxy_port, proxy_auth = proxy
                conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=remaining)
                tunnel_headers = {"Proxy-Connection": "Keep-Alive"}
                if proxy_auth:
                    tunnel_headers["Proxy-Authorization"] = "Basic " + proxy_auth
                conn.set_tunnel(host, 443, headers=tunnel_headers)
                conn.connect()
                conn.sock = ssl.create_default_context().wrap_socket(
                    conn.sock, server_hostname=host
                )
            else:
                conn = http.client.HTTPSConnection(host, 443, timeout=remaining)
            try:
                conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=False)
                conn.putheader("Host", host)
                for key, value in headers.items():
                    conn.putheader(key, value)
                conn.endheaders()
                reply = conn.getresponse()
                status = reply.status
                encoding = reply.getheader("Content-Encoding", "identity")
                data = reply.read(MAX_INPUT + 1)
            finally:
                conn.close()
            if status in (301, 302, 303, 307, 308):
                raise CatalogError("CATNET redirect denied")
            if status in (502, 503, 504):
                last_error = CatalogError("CATNET HTTP %d" % status)
                continue
            if status != 200 or encoding != "identity":
                detail = ""
                if data:
                    try:
                        body = json.loads(data.decode("utf-8", "replace"))
                        if isinstance(body, dict) and body.get("message"):
                            detail = ": %s" % body["message"]
                    except ValueError:
                        pass
                raise CatalogError(
                    "Invalid CATNET HTTP response (%d)%s" % (status, detail)
                )
            if not data or len(data) > MAX_INPUT or data.lstrip().startswith(b"<"):
                raise CatalogError("Empty, HTML or oversized CATNET response")
            return data
        except CatalogError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout) as e:
            last_error = e
            continue
    raise CatalogError("Unable to obtain CATNET server catalog: %s" % last_error)


def check_preflight(data):
    """Valida el preflight. Si el servidor exige verificación de integridad
    (Play Integrity), nos detenemos: no se fabrica attestation ni sesión."""
    doc = parse_document(data.decode("utf-8"))
    info = doc.get("data")
    if doc.get("success") is not True or not isinstance(info, dict):
        raise CatalogError("Invalid CATNET preflight")
    if info.get("maintenance") is True:
        raise CatalogError("CATNET maintenance")
    if info.get("integrity_required") is not False:
        raise CatalogError(
            "CATNET_INTEGRITY_REQUIRED: el servidor exige verificación "
            "Play Integrity (integrity_required=true) y sin un token real "
            "de un dispositivo con la app oficial no se puede descargar "
            "el catálogo. No se fabrica attestation."
        )


def download():
    """Preflight + descarga del catálogo, exactamente como la app."""
    headers = original_headers()
    deadline = time.monotonic() + 30
    check_preflight(_get(PREFLIGHT_URL, headers, deadline))
    data = _get(SERVERS_URL, headers, deadline)
    decode_catalog(data)
    return data


def _self_test():
    """Muestra sintética con el formato documentado + guardas."""
    sample = {
        "success": True,
        "message": "OK",
        "has_defaults": True,
        "def_user": "user",
        "def_pass_plain": "pass",
        "back_user": "back",
        "back_pass_plain": "backpass",
        "servers": [
            {"id": 1, "servername": "BR-01", "ip": "1.2.3.4"},
            {"id": 2, "servername": "US-01", "ip": "5.6.7.8"},
        ],
    }
    checks = []

    def check(name, ok):
        checks.append((name, bool(ok)))
        print(("ok  " if ok else "FAIL") + " " + name)

    data = json.dumps(sample, ensure_ascii=False).encode("utf-8")
    doc = decode_catalog(data)
    check("decode sample (2 servers)", doc["servers"][1]["servername"] == "US-01")
    check("run renders full doc", '"servername": "US-01"' in run(data))
    try:
        decode_catalog(b'{"success":true,"servers":[]}')
        check("reject empty servers", False)
    except CatalogError:
        check("reject empty servers", True)
    try:
        decode_catalog(b'{"success":true,"servers":[{"id":0,"servername":"x","ip":"y"}]}')
        check("reject bad server id", False)
    except CatalogError:
        check("reject bad server id", True)
    try:
        decode_catalog(b'{"success":true,"servers":[{"id":1,"servername":"","ip":"y"}]}')
        check("reject empty servername", False)
    except CatalogError:
        check("reject empty servername", True)
    try:
        decode_catalog(b'not json')
        check("reject non-JSON", False)
    except CatalogError:
        check("reject non-JSON", True)
    try:
        check_preflight(
            b'{"success":true,"data":{"maintenance":false,"integrity_required":true}}'
        )
        check("reject integrity_required=true", False)
    except CatalogError as e:
        check("reject integrity_required=true", "CATNET_INTEGRITY_REQUIRED" in str(e))
    check_preflight(
        b'{"success":true,"data":{"maintenance":false,"integrity_required":false}}'
    )
    check("accept integrity_required=false", True)
    failed = [n for n, ok in checks if not ok]
    print("self-test: %d/%d passed" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="CATNET VPN 1.2.7 — catálogo Cloud de servidores públicos."
    )
    parser.add_argument("file", nargs="?", help="JSON de catálogo guardado")
    parser.add_argument("--url", action="store_true", help="descargar en vivo")
    parser.add_argument("--stdin", action="store_true", help="leer de stdin")
    parser.add_argument("-o", "--output", help="archivo de salida para --url")
    parser.add_argument("--self-test", action="store_true", help="pruebas internas")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.file and args.stdin:
        parser.error("Choose file or --stdin")
    try:
        if args.url or (not args.file and not args.stdin):
            data = download()
            if args.output:
                with open(args.output, "wb") as f:
                    f.write(data)
            print(run(data))
        elif args.stdin:
            data = sys.stdin.buffer.read(MAX_INPUT + 1)
            print(run(data))
        else:
            with open(args.file, "rb") as f:
                data = f.read(MAX_INPUT + 1)
            print(run(data))
        return 0
    except (CatalogError, ValueError, OSError, RecursionError) as e:
        print("CATNET error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
