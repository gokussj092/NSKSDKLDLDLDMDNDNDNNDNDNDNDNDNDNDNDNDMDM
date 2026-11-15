#!/usr/bin/env python3
"""VertexSnipher 0.1.46: lector de catálogo (servidores y prebuilt configs).

Python 3.10+, solo biblioteca estándar.

App: codes.juanscript.vertexsnipher, versionCode 46, versionName 0.1.46,
minSdk 32. Versión pública de Google Play (0.1.46), descargada de APKPure
porque APKMirror no tenía listado. Sin cobertura previa en el repo de
SP-DECODE (86 carpetas revisadas; VIP_Snipher_Pro es otra app).

Catálogo (m61.k, fh3.e, n61.j, q70.m, AnnouncementInbox.d del DEX):

  GET https://www.juanscript.codes/api/servers?users=76
  GET https://www.juanscript.codes/api/prebuilt-configs?users=76&include_global=0
  GET https://www.juanscript.codes/api/prebuilt-xrays?users=76&include_global=0
  GET https://www.juanscript.codes/api/openvpn-files
  GET https://www.juanscript.codes/api/app-sync?users=76

  Cabeceras exactas de la app (todas las rutas):
    User-Agent: Vertex/0.1.46
    Accept: application/json   (openvpn-files: application/json, application/x-openvpn-profile)
    X-App-Package: codes.juanscript.vertexsnipher
    X-App-Version-Code: 46
    X-App-Version-Name: 0.1.46
  Solo prebuilt-*: X-Content-User-Id: 76. Solo app-sync: X-App-Installation-Id,
  If-None-Match (ETag de la última sincronización).

  Identidad del dispositivo (ab0.b + g52.a, en TODAS las rutas del catálogo):
    X-App-Variant: vertexsnipher
    X-Report-Device-Id: ANDROID_ID del dispositivo (hex 1-16)
    X-Report-Installation-Id: UUID de instalación de la app
    X-Reward-Device-Id: mismo ANDROID_ID
    X-Play-Integrity-Session: token de sesión de Google Play Integrity,
      guardado en SharedPreferences "play_integrity_session" (g52.b/k).

La respuesta es JSON en claro, sin cifrar: {"ok": true, "data": [...]}.
Servidores: [{id, status, country, domain, ip, cert, ovpn_online,
cloudfront, fastly, cloudrun, vless, vmess, trojan, shadowsocks/ss,
udp_version, udpv1/udp_v1, udpv2/udp_v2, obfs_value, ns_domain,
public_key}]. Prebuilt configs: [{id, name, mode, country_code, owned_by,
...todos los campos del perfil}]. Prebuilt xrays: [{id, name, type, mode,
transport, address, port, ws_host, path, xhttp_mode, allow_insecure,
alpn[], sni, country_code, owned_by}]. OpenVPN files: [{name, ...}].
La app guarda el catálogo en SharedPreferences ("server_cache_user_76" /
"prebuilt_config_cache_user_76"); el APK no trae catálogo incluido.

BLOQUEO HONESTO (verificado en vivo el 2026-11-13, tres veces):

  Sin cabeceras de dispositivo -> HTTP 403
  {"ok": false, "error": "device_identity_required",
   "message": "Update the app and verify this device to continue."}
  Con ANDROID_ID + installation-id fabricados (sin sesión de integridad):
  HTTP 403 {"ok": false, "error": "play_integrity_required",
   "message": "Install or update the official app from Google Play to continue."}

El token X-Play-Integrity-Session lo emite Google Play Integrity en el
dispositivo, con la app oficial instalada desde Play (g52.i:
IntegrityManager.warmUp/requestIntegrityToken), va ligado a la app, al
dispositivo y al nonce del desafío, y caduca en minutos: NO se puede
fabricar ni reutilizar offline. La propia app reintenta una vez tras
refrescar la sesión (nf3.r + g52.a.d()). Sin un dispositivo real con la
app oficial, el catálogo NO se puede descargar; este script reproduce la
petición exacta y reporta el bloqueo sin inventar servidores (salida 2).

Para abrir el catálogo hace falta: un teléfono con la app oficial
instalada desde Google Play y verificada, y pasar sus valores con
--device-id (ANDROID_ID), --installation-id y --integrity-session
(token de sesión vigente). Con ellos, --url descarga y guarda el JSON
tal cual. También sirve un `servers_json` / `configs` guardado por la
app en el teléfono (SharedPreferences), que se abre con --file.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

MAX_BYTES = 8 * 1024 * 1024

BASE_URL = "https://www.juanscript.codes/api"
USER_AGENT = "Vertex/0.1.46"
APP_PACKAGE = "codes.juanscript.vertexsnipher"
APP_VERSION_CODE = "46"
APP_VERSION_NAME = "0.1.46"
CONTENT_USER_ID = "76"

ENDPOINTS = {
    "servers": "/servers?users=76",
    "prebuilt-configs": "/prebuilt-configs?users=76&include_global=0",
    "prebuilt-xrays": "/prebuilt-xrays?users=76&include_global=0",
    "openvpn-files": "/openvpn-files",
    "app-sync": "/app-sync?users=76",
}


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def build_headers(endpoint: str, device_id: str | None = None,
                  installation_id: str | None = None,
                  integrity_session: str | None = None,
                  etag: str | None = None) -> dict:
    """Cabeceras exactas de la app (m61.k / fh3.e / n61.j / q70.B / ab0.b / g52.a)."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": ("application/json, application/x-openvpn-profile"
                   if endpoint == "openvpn-files" else "application/json"),
        "X-App-Package": APP_PACKAGE,
        "X-App-Version-Code": APP_VERSION_CODE,
        "X-App-Version-Name": APP_VERSION_NAME,
    }
    if endpoint in ("prebuilt-configs", "prebuilt-xrays", "app-sync"):
        headers["X-Content-User-Id"] = CONTENT_USER_ID
    if endpoint == "app-sync" and installation_id:
        headers["X-App-Installation-Id"] = installation_id
    if endpoint == "app-sync" and etag:
        headers["If-None-Match"] = etag
    if device_id:
        headers["X-App-Variant"] = "vertexsnipher"
        headers["X-Report-Device-Id"] = device_id
        headers["X-Reward-Device-Id"] = device_id
    if installation_id and endpoint != "app-sync":
        headers["X-Report-Installation-Id"] = installation_id
    if integrity_session:
        headers["X-Play-Integrity-Session"] = integrity_session
    return headers


def decode(data: bytes | str) -> dict:
    """Interpreta una respuesta del API (JSON en claro) o un catálogo guardado.

    Acepta el cuerpo completo {"ok": true, "data": [...]} o directamente
    un array JSON (p. ej. el `servers_json` guardado en SharedPreferences).
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise DecodeError("FORMAT_ERROR", "La respuesta no es texto UTF-8.") from exc
    else:
        text = data
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "La entrada supera el límite de tamaño.")
    stripped = text.strip()
    if not stripped:
        raise DecodeError("FORMAT_ERROR", "Respuesta vacía.")
    try:
        doc = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise DecodeError("FORMAT_ERROR", "La respuesta no es JSON.") from exc
    if isinstance(doc, list):
        return {"ok": True, "data": doc}
    if not isinstance(doc, dict):
        raise DecodeError("FORMAT_ERROR", "La respuesta no es un objeto JSON.")
    if not doc.get("ok", False):
        error = doc.get("error", "unknown_error")
        message = doc.get("message", "")
        code = {
            "device_identity_required": "VERTEX_DEVICE_IDENTITY_REQUIRED",
            "play_integrity_required": "VERTEX_INTEGRITY_REQUIRED",
        }.get(error, "API_ERROR")
        raise DecodeError(code, "El servidor rechazó la petición: %s%s" % (
            error, (" (%s)" % message) if message else ""))
    if "data" not in doc:
        raise DecodeError("FORMAT_ERROR", "La respuesta no trae el campo 'data'.")
    return doc


def run(data: bytes | str) -> str:
    """Devuelve el catálogo como JSON (texto)."""
    doc = decode(data)
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def summarize(doc: dict, endpoint: str) -> dict:
    """Resumen del catálogo: cuentas por tipo y países."""
    data = doc.get("data") or []
    info = {"endpoint": endpoint, "items": len(data)}
    if endpoint == "servers":
        countries = {}
        statuses = {}
        for item in data:
            if isinstance(item, dict):
                countries[item.get("country", "?")] = countries.get(item.get("country", "?"), 0) + 1
                statuses[item.get("status", "?")] = statuses.get(item.get("status", "?"), 0) + 1
        info["countries"] = countries
        info["statuses"] = statuses
    elif endpoint in ("prebuilt-configs", "prebuilt-xrays"):
        modes = {}
        for item in data:
            if isinstance(item, dict):
                modes[item.get("mode", "?")] = modes.get(item.get("mode", "?"), 0) + 1
        info["modes"] = modes
    return info


# ---------------------------------------------------------------- descarga en vivo

def _proxy_env():
    raw = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
           or os.environ.get("all_proxy") or os.environ.get("ALL_PROXY"))
    if not raw:
        return None
    parsed = urlparse(raw)
    if not parsed.hostname or not parsed.port:
        return None
    return parsed.hostname, parsed.port, parsed.username, parsed.password


def _http_get(url: str, headers: dict, timeout: int = 30):
    """GET con http.client. Con proxy en el entorno usa túnel CONNECT
    explícito (urllib trunca respuestas chunked en este entorno)."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    proxy = _proxy_env()
    no_proxy = os.environ.get("no_proxy", "") or ""
    if proxy and host not in [h.strip() for h in no_proxy.split(",") if h.strip()]:
        p_host, p_port, p_user, p_pass = proxy
        tunnel_headers = {}
        if p_user is not None:
            token = base64.b64encode(
                ("%s:%s" % (p_user, p_pass or "")).encode()).decode()
            tunnel_headers["Proxy-Authorization"] = "Basic " + token
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(
                p_host, p_port, timeout=timeout,
                context=ssl.create_default_context())
            conn.set_tunnel(host, port, headers=tunnel_headers)
        else:
            conn = http.client.HTTPConnection(p_host, p_port, timeout=timeout)
            conn.set_tunnel(host, port, headers=tunnel_headers)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read(), dict(resp.getheaders())
        finally:
            conn.close()
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read(), dict(resp.getheaders())


def fetch(endpoint: str, device_id: str | None = None,
          installation_id: str | None = None,
          integrity_session: str | None = None,
          etag: str | None = None, retries: int = 2):
    """Descarga un endpoint del catálogo con la petición exacta de la app.

    La app reintenta una vez tras refrescar la sesión de integridad
    (nf3.r); aquí el reintento solo repite la petición, porque refrescar
    la sesión exige el dispositivo real.
    """
    if endpoint not in ENDPOINTS:
        raise DecodeError("URL_ERROR", "Endpoint desconocido: %s." % endpoint)
    url = BASE_URL + ENDPOINTS[endpoint]
    headers = build_headers(endpoint, device_id, installation_id,
                            integrity_session, etag)
    last_error = None
    for _ in range(max(1, retries)):
        try:
            status, raw, resp_headers = _http_get(url, headers)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            last_error = exc
            continue
        if status == 304:
            return None, {"endpoint": endpoint, "status": 304, "not_modified": True}
        if status != 200:
            try:
                decode(raw)
            except DecodeError as exc:
                raise exc
            raise DecodeError("DOWNLOAD_FAILED", "El endpoint devolvió HTTP %d." % status)
        doc = decode(raw)
        info = summarize(doc, endpoint)
        info["status"] = status
        info["bytes"] = len(raw)
        info["etag"] = resp_headers.get("ETag")
        return doc, info
    raise DecodeError("DOWNLOAD_FAILED",
                      "No se pudo descargar el catálogo.") from last_error


def fetch_catalog(endpoint: str = "servers", **kwargs):
    """Descarga el catálogo y devuelve (catálogo, info)."""
    doc, info = fetch(endpoint, **kwargs)
    if doc is None:
        raise DecodeError("NOT_MODIFIED", "El servidor respondió 304 (sin cambios).")
    return doc, info


# ---------------------------------------------------------------- self-test

def _self_test() -> dict:
    checks = {}
    sample_servers = {
        "ok": True,
        "data": [
            {"id": 1, "status": "online", "country": "BR", "domain": "br1.example",
             "ip": "1.2.3.4", "cert": "-----BEGIN CERTIFICATE-----",
             "ovpn_online": 1, "cloudfront": "cf.example", "fastly": "",
             "cloudrun": "", "vless": "vless://x", "vmess": "", "trojan": "",
             "shadowsocks": "", "udp_version": "2", "udpv1": "udp://x",
             "udpv2": "", "obfs_value": "", "ns_domain": "ns.example",
             "public_key": "abc"},
            {"id": 2, "status": "offline", "country": "US", "domain": "us1.example",
             "ip": "5.6.7.8", "cert": "", "ovpn_online": 0, "cloudfront": "",
             "fastly": "", "cloudrun": "", "vless": "", "vmess": "",
             "trojan": "", "shadowsocks": "", "udp_version": "",
             "udpv1": "", "udpv2": "", "obfs_value": "", "ns_domain": "",
             "public_key": ""},
        ],
    }
    doc = decode(json.dumps(sample_servers))
    checks["servers_parse"] = len(doc["data"]) == 2
    info = summarize(doc, "servers")
    checks["servers_summary"] = info["items"] == 2 and info["countries"] == {"BR": 1, "US": 1}
    sample_configs = {"ok": True, "data": [
        {"id": 10, "name": "BR-SSH-1", "mode": "SSH", "country_code": "BR", "owned_by": 76},
        {"id": 11, "name": "US-XRAY-1", "mode": "Xray", "country_code": "US", "owned_by": 76}]}
    doc2 = decode(json.dumps(sample_configs))
    checks["prebuilt_configs_parse"] = len(doc2["data"]) == 2
    checks["prebuilt_configs_summary"] = summarize(doc2, "prebuilt-configs")["modes"] == {"SSH": 1, "Xray": 1}
    sample_xrays = {"ok": True, "data": [
        {"id": 20, "name": "X1", "type": "vless", "mode": "Xray", "transport": "ws",
         "address": "x.example", "port": 443, "ws_host": "x.example", "path": "/",
         "xhttp_mode": "", "allow_insecure": False, "alpn": ["h2"], "sni": "x.example",
         "country_code": "BR", "owned_by": 76}]}
    checks["prebuilt_xrays_parse"] = len(decode(json.dumps(sample_xrays))["data"]) == 1
    # Array directo (servers_json guardado por la app) también se acepta.
    checks["bare_array_parse"] = len(decode(json.dumps(sample_servers["data"]))["data"]) == 2
    # Cuerpos 403 reales -> códigos de bloqueo honestos.
    for body, code in (
            ('{"ok": false, "error": "device_identity_required", '
             '"message": "Update the app and verify this device to continue."}',
             "VERTEX_DEVICE_IDENTITY_REQUIRED"),
            ('{"ok": false, "error": "play_integrity_required", '
             '"message": "Install or update the official app from Google Play to continue."}',
             "VERTEX_INTEGRITY_REQUIRED")):
        try:
            decode(body)
            checks["blocked_" + code] = False
        except DecodeError as exc:
            checks["blocked_" + code] = exc.code == code
    # ok=false sin error conocido -> API_ERROR.
    try:
        decode('{"ok": false, "error": "otra_cosa"}')
        checks["api_error"] = False
    except DecodeError as exc:
        checks["api_error"] = exc.code == "API_ERROR"
    # Cabeceras exactas de la app.
    h = build_headers("servers")
    checks["headers_exact"] = (
        h["User-Agent"] == "Vertex/0.1.46"
        and h["Accept"] == "application/json"
        and h["X-App-Package"] == APP_PACKAGE
        and h["X-App-Version-Code"] == "46"
        and h["X-App-Version-Name"] == "0.1.46"
        and "X-Play-Integrity-Session" not in h)
    h2 = build_headers("prebuilt-configs", device_id="a1b2c3d4e5f60718",
                       installation_id="11111111-2222-3333-4444-555555555555",
                       integrity_session="TOKEN")
    checks["headers_device"] = (
        h2["X-Content-User-Id"] == "76"
        and h2["X-Report-Device-Id"] == "a1b2c3d4e5f60718"
        and h2["X-Reward-Device-Id"] == "a1b2c3d4e5f60718"
        and h2["X-Report-Installation-Id"] == "11111111-2222-3333-4444-555555555555"
        and h2["X-Play-Integrity-Session"] == "TOKEN")
    return checks


# ---------------------------------------------------------------- CLI

def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DecodeError("SIZE_LIMIT", "El archivo supera el límite de tamaño.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--url", nargs="?", const="servers",
                        choices=list(ENDPOINTS),
                        help="Descarga un endpoint en vivo (por defecto: servers)")
    source.add_argument("--file", type=Path,
                        help="Catálogo guardado (JSON {ok,data} o array directo)")
    source.add_argument("--stdin", action="store_true",
                        help="Leer el catálogo desde stdin")
    parser.add_argument("--device-id", metavar="ANDROID_ID",
                        help="ANDROID_ID del dispositivo (X-Report-Device-Id)")
    parser.add_argument("--installation-id", metavar="UUID",
                        help="UUID de instalación de la app")
    parser.add_argument("--integrity-session", metavar="TOKEN",
                        help="Token de sesión de Play Integrity vigente")
    parser.add_argument("--etag", metavar="ETAG",
                        help="ETag para app-sync (If-None-Match)")
    parser.add_argument("-o", "--output", type=Path,
                        help="Guardar JSON completo; por defecto stdout")
    parser.add_argument("--summary", action="store_true",
                        help="Imprimir solo el resumen en stderr")
    parser.add_argument("--self-test", action="store_true",
                        help="Verifica el parseo, los bloqueos 403 y las cabeceras")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = _self_test()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(result.values()) else 1
        if args.url is not None:
            doc, info = fetch_catalog(
                args.url, device_id=args.device_id,
                installation_id=args.installation_id,
                integrity_session=args.integrity_session, etag=args.etag)
            rendered = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            else:
                sys.stdout.write(rendered)
            print(json.dumps(info, ensure_ascii=False), file=sys.stderr)
            return 0
        if args.stdin:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        elif args.file is not None:
            raw = _read(args.file)
        else:
            parser.error("se requiere --url, --file, --stdin o --self-test")
        doc = decode(raw)
        endpoint = "servers" if isinstance(doc.get("data"), list) else "servers"
        rendered = run(raw)
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        if args.summary:
            print(json.dumps(summarize(doc, endpoint), ensure_ascii=False),
                  file=sys.stderr)
        return 0
    except DecodeError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 2 if exc.code in ("VERTEX_DEVICE_IDENTITY_REQUIRED",
                                 "VERTEX_INTEGRITY_REQUIRED") else 1
    except OSError:
        print(json.dumps({"error": "IO_ERROR", "message": "No se pudo leer o escribir el archivo."}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
