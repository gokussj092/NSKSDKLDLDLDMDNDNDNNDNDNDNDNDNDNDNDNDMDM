#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IGNIX VPN MAX — lector de catálogo para SP-DECODE.

Paquete: http.ignixmax.vpn — versión 44 / versionCode 44 (la versión pública
en Google Play, actualizada el 11 nov 2026; APK verificado contra Play).
Desarrollador: Prominex. El catálogo vive detrás de autenticación de
dispositivo (SCKIT VMP); este script replica la petición exacta de la app
hasta donde el servidor permite llegar sin un dispositivo registrado.

Flujo de la app (verificado en vivo el 2026-11-13):
  1. GET  https://accesos.ignix-vpn.site/updateapk/ignix_challenge.php
          con X-IGNIX-SIG: <SHA-1 del certificado firmante del APK>
          -> 200 {"ok":true,"nonce":"<32 hex>","ts":<unix>}
  2. POST https://accesos.ignix-vpn.site/updateapk/ignix_register.php
          (registro del dispositivo; el formato exacto de la petición vive
          dentro del bytecode VMP y no pudo recuperarse — ver README)
  3. GET  https://accesos.ignix-vpn.site/updateapk/ignix_update.php
          con X-IGNIX-SIG + X-IGNIX-AUTH: <server_token>
          -> sin token: 401 {"error":"no autorizado"}
          -> sin firma:  403 {"error":"firma invalida"}
  4. VIP: GET https://accesos.ignix-vpn.site/vip/vip_catalog.php
          (misma autenticación; sin token: 401 {"error":"desconocido"})

ESTADO EN VIVO (2026-11-13, verificado por el analista):
  - challenge: OK (200, nonce + ts).
  - sync.php con solo la firma: 200 {"premium":false,...}.
  - ignix_update.php con solo la firma: 401 "no autorizado".
  - ignix_register.php: 400 {"error":"bad request"} en todas las
    variantes probadas (JSON/form/query, con nonce+ts+firma HMAC-SHA256,
    device_secret generado, etc.). El registro exacto requiere ejecutar
    el método VMP ConfigUpdate, bloqueado por los controles de integridad
    del runtime (ver README).
  - El cifrado del catálogo NO está identificado: nunca se ha obtenido
    una respuesta de catálogo autenticada, y la contraseña / alfabeto
    viven dentro del bytecode VMP, no en las cadenas ni en el Java
    descompilado. decode() NO inventa servidores: si el cuerpo no es
    JSON de error ni catálogo en claro, lo reporta como CIPHER_PENDING
    con su SHA-256 para trabajo futuro.

Uso:
  python3 IGNIX_VPN_MAX.py [--url URL] [--vip] [--token TOKEN]
                           [--device-id ID] [--raw-out ARCHIVO]
                           [--self-test]
  --token TOKEN   server_token obtenido en un dispositivo registrado
                  (cabecera X-IGNIX-AUTH). Sin token el script llega
                  hasta el 401 y lo reporta.
  --self-test     verifica la capa de transporte/autenticación en vivo
                  (challenge + respuestas de error documentadas). NO
                  verifica un catálogo: no hay catálogo sin token.

Solo stdlib de Python 3.10+. Sin dependencias.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import urllib.parse

try:
    import http.client as http_client
except ImportError:  # pragma: no cover
    import httplib as http_client  # type: ignore

PACKAGE = "http.ignixmax.vpn"
VERSION_NAME = "44"
VERSION_CODE = 44

HOST = "accesos.ignix-vpn.site"
BASE = "https://" + HOST
URL_FREE = BASE + "/updateapk/ignix_update.php"
URL_VIP = BASE + "/vip/vip_catalog.php"
URL_CHALLENGE = BASE + "/updateapk/ignix_challenge.php"
URL_REGISTER = BASE + "/updateapk/ignix_register.php"
URL_SYNC = BASE + "/vip/sync.php"

# SHA-1 del certificado firmante del APK (v2 signing block, extraído del APK
# y confirmado por la cadena recuperada del VMP: id 446). La app lo compara
# en Nr.Z() y lo envía como X-IGNIX-SIG. Minúsculas = como se envía.
SIGNER_SHA1 = "05856dee81c2ffcbbbeb100d5e2cc0884a848be5"
SIGNER_SHA1_UPPER = "05856DEE81C2FFCBBBEB100D5E2CC0884A848BE5"

USER_AGENT = "IGNIX-VPN"
TIMEOUT = 30
MAX_BODY = 8 * 1024 * 1024


class IgnixError(Exception):
    """Error de transporte o de protocolo del lector."""


def _proxy_settings():
    """Devuelve (host, puerto, auth_b64) del proxy HTTPS del entorno o None."""
    raw = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if not raw:
        return None
    parsed = urllib.parse.urlparse(raw)
    if not parsed.hostname:
        return None
    auth = None
    if parsed.username:
        creds = parsed.username
        if parsed.password:
            creds += ":" + parsed.password
        auth = base64.b64encode(creds.encode()).decode()
    return (parsed.hostname, parsed.port or 3128, auth)


def fetch(method, url, headers=None, body=None):
    """Petición HTTPS exacta. Usa el proxy del entorno si existe (el mismo
    mecanismo que usa la app: CONNECT al host, sin redirecciones)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise IgnixError("solo se admiten URLs https: %s" % url)
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    proxy = _proxy_settings()
    if proxy:
        host, port, auth = proxy
        conn = http_client.HTTPSConnection(host, port, timeout=TIMEOUT, context=ctx)
        tunnel_headers = {}
        if auth:
            tunnel_headers["Proxy-Authorization"] = "Basic " + auth
        conn.set_tunnel(parsed.hostname, parsed.port or 443, headers=tunnel_headers)
    else:
        conn = http_client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                           timeout=TIMEOUT, context=ctx)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    conn.request(method, path, body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read(MAX_BODY + 1)
    status = resp.status
    resp_headers = dict(resp.getheaders())
    conn.close()
    if len(data) > MAX_BODY:
        raise IgnixError("respuesta mayor que el límite de 8 MiB")
    return status, data, resp_headers


def auth_headers(token=None):
    """Cabeceras exactas de la app: firma del firmante + token de dispositivo."""
    headers = {"X-IGNIX-SIG": SIGNER_SHA1}
    if token:
        headers["X-IGNIX-AUTH"] = token
    return headers


def challenge():
    """Paso 1: pide un nonce al servidor. Funciona solo con la firma."""
    status, data, _ = fetch("GET", URL_CHALLENGE, headers=auth_headers())
    if status != 200:
        raise IgnixError("challenge: HTTP %d %r" % (status, data[:200]))
    try:
        obj = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise IgnixError("challenge: respuesta no JSON: %r" % data[:200]) from exc
    if not obj.get("ok") or "nonce" not in obj or "ts" not in obj:
        raise IgnixError("challenge: respuesta inesperada: %r" % data[:200])
    return obj


def register_attempt(device_id, nonce, ts):
    """Paso 2 (mejor esfuerzo): intenta registrar el dispositivo.

    La petición exacta vive dentro del bytecode VMP (ConfigUpdate) y no
    pudo recuperarse: el runtime VMP rechaza ejecutar registerClass fuera
    de su mapeo RX y su tarea Rust de fondo aborta en emulación (ver
    README). Esta variante es la más plausible por el flujo
    challenge -> firma: HMAC-SHA256(clave=SHA-1 del firmante,
    mensaje=nonce+device_id). El servidor responde 400 a todas las
    variantes probadas hasta ahora; si algún día responde con un
    server_token, run() lo usa para el catálogo.
    """
    signature = hmac.new(SIGNER_SHA1.encode("utf-8"),
                         (nonce + device_id).encode("utf-8"),
                         hashlib.sha256).hexdigest()
    payload = json.dumps({
        "device_id": device_id,
        "nonce": nonce,
        "ts": ts,
        "signature": signature,
    }).encode("utf-8")
    status, data, _ = fetch(
        "POST", URL_REGISTER,
        headers=dict(auth_headers(),
                     **{"Content-Type": "application/json"}),
        body=payload)
    try:
        obj = json.loads(data.decode("utf-8"))
    except ValueError:
        obj = {"_raw": data[:200].decode("utf-8", "replace")}
    return status, obj


def fetch_catalog(url=URL_FREE, token=None):
    """Paso 3: descarga el catálogo con la autenticación disponible."""
    status, data, _ = fetch("GET", url, headers=auth_headers(token))
    return status, data


def decode(data):
    """Decodifica una respuesta de catálogo.

    Contrato honesto:
    - JSON con "error" -> {'status': 'ERROR', ...} (401/403/400 del servidor).
    - JSON con catálogo en claro (Version/Servers) -> lo devuelve tal cual.
    - Cualquier otro cuerpo (el catálogo cifrado) -> {'status':
      'CIPHER_PENDING', 'size', 'sha256', 'head'}: el cifrado aún no está
      identificado porque nunca se obtuvo una respuesta autenticada.
      NO se inventan servidores, versiones ni payloads.
    """
    if not data:
        return {"status": "ERROR", "error": "respuesta vacía"}
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {
            "status": "CIPHER_PENDING",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "head": data[:64].hex(),
            "note": ("cuerpo no JSON: catálogo cifrado. El cifrado no está "
                     "identificado (requiere dispositivo registrado). "
                     "Guarda el cuerpo con --raw-out para trabajo futuro."),
        }
    if isinstance(obj, dict) and "error" in obj:
        return {"status": "ERROR", "error": obj.get("error"), "raw": obj}
    if isinstance(obj, dict):
        servers = obj.get("Servers") or obj.get("servers") or []
        networks = obj.get("Networks") or obj.get("networks") or []
        return {
            "status": "OK",
            "version": obj.get("Version") or obj.get("version"),
            "servers": len(servers) if isinstance(servers, list) else None,
            "payloads": len(networks) if isinstance(networks, list) else None,
            "catalog": obj,
        }
    return {"status": "ERROR", "error": "JSON inesperado", "raw": obj}


def summarize(result):
    """Resumen legible de un resultado de decode()."""
    if result["status"] == "OK":
        return ("catálogo OK: versión %s, %s servidores, %s payloads"
                % (result.get("version"), result.get("servers"),
                   result.get("payloads")))
    if result["status"] == "ERROR":
        return "error: %s" % result.get("error")
    return ("catálogo cifrado pendiente de descifrar: %d bytes, "
            "SHA-256 %s" % (result["size"], result["sha256"]))


def run(url=URL_FREE, token=None, device_id=None, raw_out=None):
    """Flujo completo: challenge -> registro (intento) -> catálogo -> decode."""
    report = {
        "package": PACKAGE,
        "version": VERSION_NAME,
        "url": url,
        "challenge": None,
        "register": None,
        "catalog_http": None,
        "result": None,
    }
    ch = challenge()
    report["challenge"] = {"ok": True, "nonce": ch["nonce"], "ts": ch["ts"]}
    if token is None and device_id:
        status, obj = register_attempt(device_id, ch["nonce"], ch["ts"])
        report["register"] = {"http": status, "response": obj}
        if isinstance(obj, dict) and obj.get("server_token"):
            token = obj["server_token"]
    status, data = fetch_catalog(url, token=token)
    report["catalog_http"] = status
    if raw_out and data:
        with open(raw_out, "wb") as fh:
            fh.write(data)
        report["raw_saved"] = raw_out
    result = decode(data)
    report["result"] = result
    return report


def self_test():
    """Verifica en vivo la capa de transporte/autenticación.

    NO verifica un catálogo (no hay catálogo sin dispositivo registrado).
    Comprueba: challenge 200 con nonce+ts; update sin token -> 401;
    update sin firma -> 403; sync con solo firma -> 200; register con
    la variante documentada -> 400 (formato exacto pendiente).
    """
    checks = []
    try:
        ch = challenge()
        checks.append(("challenge 200 + nonce/ts",
                       bool(ch.get("nonce") and ch.get("ts")), ch))
    except Exception as exc:  # noqa: BLE001
        checks.append(("challenge 200 + nonce/ts", False, str(exc)))
    try:
        status, data, _ = fetch("GET", URL_FREE, headers=auth_headers())
        checks.append(("update sin token -> 401 no autorizado",
                       status == 401 and b"no autorizado" in data,
                       "%d %r" % (status, data[:120])))
    except Exception as exc:  # noqa: BLE001
        checks.append(("update sin token -> 401 no autorizado", False, str(exc)))
    try:
        status, data, _ = fetch("GET", URL_FREE,
                                headers={"User-Agent": USER_AGENT})
        checks.append(("update sin firma -> 403 firma invalida",
                       status == 403 and b"firma invalida" in data,
                       "%d %r" % (status, data[:120])))
    except Exception as exc:  # noqa: BLE001
        checks.append(("update sin firma -> 403 firma invalida", False, str(exc)))
    try:
        status, data, _ = fetch("GET", URL_SYNC, headers=auth_headers())
        checks.append(("sync con solo firma -> 200",
                       status == 200, "%d %r" % (status, data[:120])))
    except Exception as exc:  # noqa: BLE001
        checks.append(("sync con solo firma -> 200", False, str(exc)))
    try:
        ch = challenge()
        status, obj = register_attempt("a1b2c3d4e5f60718",
                                       ch["nonce"], ch["ts"])
        checks.append(("register variante documentada -> 400 (pendiente)",
                       status == 400, "%d %r" % (status, obj)))
    except Exception as exc:  # noqa: BLE001
        checks.append(("register variante documentada -> 400 (pendiente)",
                       False, str(exc)))
    ok = all(passed for _, passed, _ in checks)
    return ok, checks


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="IGNIX VPN MAX — lector de catálogo (SP-DECODE).")
    parser.add_argument("--url", default=URL_FREE,
                        help="URL del catálogo (por defecto, el gratuito)")
    parser.add_argument("--vip", action="store_true",
                        help="usar el catálogo VIP (vip_catalog.php)")
    parser.add_argument("--token", default=None,
                        help="server_token para X-IGNIX-AUTH")
    parser.add_argument("--device-id", default=None,
                        help="ID de dispositivo (16 hex) para intentar registro")
    parser.add_argument("--raw-out", default=None,
                        help="guardar el cuerpo crudo de la respuesta")
    parser.add_argument("--self-test", action="store_true",
                        help="verificación en vivo de la capa de auth")
    args = parser.parse_args(argv)

    if args.self_test:
        ok, checks = self_test()
        for name, passed, detail in checks:
            print("%s %s: %s" % ("PASS" if passed else "FAIL", name, detail))
        print("SELF-TEST %s (capa de auth; sin catálogo: falta token)"
              % ("OK" if ok else "FALLIDO"))
        return 0 if ok else 1

    url = URL_VIP if args.vip else args.url
    try:
        report = run(url=url, token=args.token,
                     device_id=args.device_id, raw_out=args.raw_out)
    except IgnixError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(summarize(report["result"]))
    if report["result"]["status"] != "OK":
        print("PENDIENTE: el catálogo requiere un dispositivo registrado "
              "(server_token) y el cifrado aún no está identificado. "
              "Ver README.md.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
