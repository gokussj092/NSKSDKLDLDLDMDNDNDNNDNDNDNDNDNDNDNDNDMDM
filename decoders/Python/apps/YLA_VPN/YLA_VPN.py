#!/usr/bin/env python3
"""YLA VPN (com.thuaung.ylavpn) 1.2.4 / build 10 — catálogo Cloud.

App Flutter (Dart AOT, libapp.so) + núcleo Xray Go (libv2jni.so, 32 bits,
solo armeabi-v7a). Sin cobertura previa en SP-DECODE (revisado
decoders/Python/apps/ en la rama feat/nuevas-integraciones: no hay carpeta
YLA ni mención de thuaung/ylavpn).

MÉTODO (verificado en este APK):
  Host del panel: https://adminpannel.ylavpn.store
  (la URL base llega por Firebase Remote Config; este es el dominio de
  reserva que trae la app y responde en vivo.)
  1. Registro del dispositivo (POST, JSON):
     POST /api/user/init
     {"device_id": "<id>", "device_model": "<modelo>",
      "app_version": "1.2.4"}
     -> 200 {"success": true, "is_banned": false,
             "data": {"user_code": "YLA-XXXXXX", "device_id": "...",
                      "is_vip": false, "vip_expired_at": null,
                      "vip_expired_formatted": "No Active VIP",
                      "unread_notifications": 1, "status": 1,
                      "ban_reason": null}}
     El device_id lo genera la app ("Generated Secure Device ID") y se
     guarda en caché (cached_device_id / cached_user_init_data). Cualquier
     device_id es aceptado por el registro; el user_code devuelto es el
     identificador del usuario en el panel.
  2. Catálogo de servidores (GET):
     GET /api/v2ray/list?device_id=<id>&signature=<firma>
     La app usa el cliente Dio (DioClient). La ruta solo acepta GET/HEAD.
     Sin firma (o con firma inválida) el servidor responde HTTP 403:
     {"success": false, "error": "Unauthorized access or invalid signature"}
  3. Endpoints abiertos (GET, sin auth, verificados en vivo 2026-11-13):
     GET /api/app-yla-setting  -> ajustes, versión, force_update, Telegram
     GET /api/plans            -> planes VIP en MMK
  4. Notificaciones (POST, JSON, solo device_id, verificado en vivo):
     POST /api/user/notifications {"device_id": "..."}
     POST /api/user/notifications/read {"device_id": "...",
                                        "user_code": "..."}

FIRMA (PENDIENTE — ver ESTADO EN VIVO): la app trae la constante
  YLA_VPN_SECURE_SALT_2026
y una función _hashWithSha256 (clase Dart con _generateSecureRandomId y
_loadCachedUserData). La firma se calcula en el cliente con SHA-256, pero
la fórmula exacta no pudo determinarse: se probaron en vivo ~280
combinaciones (sha256/HMAC-SHA256/MD5; órdenes de device_id, user_code y
sal; separadores '', '|', ':', '-', '_'; con y sin timestamp en segundos
y milisegundos; como parámetro ?signature, ?sign, ?sig y como cabeceras
X-Signature / Authorization: Bearer; con device_id hexadecimal y con
UUID) y todas devuelven el mismo 403. Este script usa como intento
documentado signature = sha256_hex(device_id + SALT) y lo marca como
NO VERIFICADO. Para desbloquear el catálogo hace falta capturar una
petición real de la app en un teléfono (proxy/Frida durante una
actualización de servidores) o completar el análisis del binario Dart AOT
(el pool de objetos usa direccionamiento relativo y no se pudo resolver
la referencia a la constante de la sal).

ESTADO EN VIVO (2026-11-13, fallo honesto): init, ajustes, planes y
notificaciones funcionan. El catálogo /api/v2ray/list NO se pudo descargar:
siempre HTTP 403 "Unauthorized access or invalid signature". Este script
NO inventa servidores: --url se detiene con LIVE_AUTH_FAILED. Cuando se
conozca la fórmula de la firma, solo hay que corregir compute_signature();
el resto (registro, descarga y parseo) ya está verificado.

ESQUEMA ESPERADO DEL CATÁLOGO (no confirmado en vivo; nombres de campo
tomados del binario Dart): la respuesta debería ser JSON con success y una
lista de servidores; cada registro con campos de outbound V2Ray
(address, port, protocol vmess/vless/trojan/shadowsocks, security,
network, path, host, sni, tls, flow, fingerprint, reality, fragment,
mux, remark, level, location, speed, country_code, flag, is_vip,
active, config). decode() es tolerante al esquema: busca la lista en
data/servers/list o en la raíz, conserva cada registro completo y resume
cuántos hay, cuántos son gratuitos y cuántos VIP.

Archivos de configuración: la app NO define ningún formato propio de
archivo (el manifest solo tiene MAIN/LAUNCHER en MainActivity; no hay
intent-filter VIEW ni asociación de extensiones) y NO tiene esquema URI
de texto propio. La importación es por portapapeles ("Paste your config
string here...", "No valid config found in Clipboard!") y por escaneo QR
(mobile_scanner); solo acepta los enlaces estándar vmess://, vless://,
trojan:// y ss://, que SP-DECODE ya cubre. Sin .sks. Por eso no hay
script YLA_VPN_archivos.py.

Uso:
  python3 YLA_VPN.py --url [--device-id ID] [-o catalogo.json]
      # registra el dispositivo si hace falta y descarga el catálogo
      # (hoy se detiene con LIVE_AUTH_FAILED; ver arriba)
  python3 YLA_VPN.py --init [--device-id ID]
      # registra un dispositivo y muestra su user_code
  python3 YLA_VPN.py --settings | --plans
      # endpoints abiertos, verificados en vivo
  python3 YLA_VPN.py catalogo.json     # decodifica un JSON guardado
  python3 YLA_VPN.py --stdin < catalogo.json
  python3 YLA_VPN.py --self-test       # pruebas internas (sin red)
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import ssl
import sys
import time
import uuid
from urllib.parse import urlsplit

APP_PACKAGE = "com.thuaung.ylavpn"
APP_VERSION = "1.2.4"
BUILD = 10
BASE_URL = "https://adminpannel.ylavpn.store"
INIT_URL = BASE_URL + "/api/user/init"
LIST_URL = BASE_URL + "/api/v2ray/list"
SETTINGS_URL = BASE_URL + "/api/app-yla-setting"
PLANS_URL = BASE_URL + "/api/plans"
NOTIFICATIONS_URL = BASE_URL + "/api/user/notifications"
NOTIFICATIONS_READ_URL = BASE_URL + "/api/user/notifications/read"

# Constante literal en libapp.so (Dart). La fórmula exacta de la firma es
# PENDIENTE: ver el docstring del módulo.
SECURE_SALT = "YLA_VPN_SECURE_SALT_2026"

MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024

# Campos de servidor que la app reconoce (nombres tomados del binario
# Dart); decode() los usa solo para el resumen, nunca para descartar.
SERVER_FIELDS = (
    "id", "remark", "name", "country_code", "country", "flag", "location",
    "address", "port", "protocol", "security", "network", "path", "host",
    "sni", "tls", "flow", "fingerprint", "reality", "fragment", "mux",
    "level", "speed", "is_vip", "is_premium", "is_free", "active",
    "config", "uuid", "password", "method",
)


class CatalogError(ValueError):
    """Error de catálogo YLA VPN (descarga o formato inválido)."""


def compute_signature(device_id):
    """Firma del catálogo (INTENTO DOCUMENTADO, NO VERIFICADO).

    sha256_hex(device_id + SECURE_SALT). El servidor rechaza esta fórmula
    en vivo (HTTP 403); ver el docstring del módulo para el estado y las
    combinaciones ya probadas. Cuando se conozca la fórmula real, corregir
    solo esta función.
    """
    return hashlib.sha256(
        (device_id + SECURE_SALT).encode("utf-8")
    ).hexdigest()


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
    """JSON estricto: objeto raíz, sin duplicados, sin NaN/Infinity."""
    try:
        return json.loads(
            text, object_pairs_hook=_unique, parse_constant=_constant
        )
    except CatalogError:
        raise
    except (ValueError, RecursionError) as exc:
        raise CatalogError("Invalid YLA VPN JSON document") from exc


def _find_server_list(doc):
    """Localiza la lista de servidores en el documento del catálogo."""
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        return None
    for key in ("data", "servers", "list", "v2ray", "result"):
        value = doc.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for sub in ("servers", "list", "data"):
                if isinstance(value.get(sub), list):
                    return value[sub]
    return None


def decode_catalog(data):
    """Valida un catálogo YLA VPN y devuelve el documento completo.

    Acepta bytes/str/dict. Exige success true (cuando el campo existe) y
    una lista de servidores no vacía; cada registro se conserva completo.
    No inventa servidores: si la lista falta o está vacía, es error.
    """
    if isinstance(data, dict):
        doc = data
    else:
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise CatalogError("Invalid YLA VPN input size")
        if len(data) > MAX_INPUT:
            raise CatalogError("Invalid YLA VPN input size")
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeError as exc:
            raise CatalogError("Invalid YLA VPN catalog encoding") from exc
        doc = parse_document(text)
    rows = _find_server_list(doc)
    if not isinstance(rows, list) or not rows:
        raise CatalogError("Invalid YLA VPN server catalog: no server list")
    if isinstance(doc, dict) and doc.get("success") is False:
        raise CatalogError(
            "Invalid YLA VPN server catalog: %s"
            % (doc.get("error") or doc.get("message") or "success false")
        )
    for row in rows:
        if not isinstance(row, dict):
            raise CatalogError("Invalid YLA VPN server record")
    return doc


def catalog_summary(doc):
    """Resumen del catálogo: versión, servidores, gratuitos, VIP, payloads.

    En YLA VPN cada servidor ES su payload (su config V2Ray): el conteo
    de payloads es el de servidores con config/uuid/address. La versión
    del catálogo no viene en un campo propio conocido; se usa la versión
    de la app que lo descargó.
    """
    rows = _find_server_list(doc) or []
    free = 0
    vip = 0
    with_payload = 0
    countries = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("is_vip") is True or row.get("is_premium") is True:
            vip += 1
        elif row.get("is_free") is True or (
            row.get("is_vip") is not True and row.get("is_premium") is not True
        ):
            free += 1
        if any(row.get(k) for k in ("config", "uuid", "address", "remark")):
            with_payload += 1
        country = row.get("country_code") or row.get("country")
        if isinstance(country, str) and country and country not in countries:
            countries.append(country)
    return {
        "app_version": APP_VERSION,
        "servers": len(rows),
        "free": free,
        "vip": vip,
        "payloads": with_payload,
        "countries": countries,
    }


def decode(data):
    """Decodifica un catálogo YLA VPN y devuelve el dict completo."""
    return decode_catalog(data)


def run(data):
    """Decodifica y renderiza el catálogo completo como JSON (str)."""
    out = json.dumps(
        decode_catalog(data), ensure_ascii=False, indent=2, allow_nan=False
    ).encode("utf-8")
    if len(out) > MAX_OUTPUT:
        raise CatalogError("YLA VPN result exceeds size limit")
    return out.decode("utf-8")


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


def _open(host, deadline):
    """Conexión TLS al host, por túnel CONNECT del proxy si lo hay."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CatalogError("YLA VPN deadline exceeded")
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
        return conn
    return http.client.HTTPSConnection(host, 443, timeout=remaining)


def _request(method, url, body=None, headers=None, timeout=30):
    """Una petición HTTP(S) con las cabeceras exactas de la app.

    Devuelve (status, bytes). No sigue redirects. El cuerpo JSON se
    envía tal cual lo hace Dio (Content-Type application/json).
    """
    parsed = urlsplit(url)
    host = parsed.hostname
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    deadline = time.monotonic() + timeout
    last_error = None
    for _attempt in range(3):
        try:
            conn = _open(host, deadline)
            try:
                payload = None
                hdrs = {"Host": host, "Accept": "application/json"}
                if headers:
                    hdrs.update(headers)
                if body is not None:
                    payload = (
                        body if isinstance(body, (bytes, str)) else json.dumps(body)
                    )
                    if isinstance(payload, str):
                        payload = payload.encode("utf-8")
                    hdrs["Content-Type"] = "application/json"
                    hdrs["Content-Length"] = str(len(payload))
                conn.putrequest(method, path, skip_host=True,
                                skip_accept_encoding=False)
                for key, value in hdrs.items():
                    conn.putheader(key, value)
                conn.endheaders(payload)
                resp = conn.getresponse()
                raw = resp.read(MAX_INPUT + 1)
                return resp.status, raw
            finally:
                conn.close()
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            last_error = exc
            if _attempt < 2:
                time.sleep(1 + _attempt)
                continue
            raise CatalogError(
                "YLA VPN download failed: %s" % (exc,)
            ) from exc
    raise CatalogError("YLA VPN download failed: %s" % (last_error,))


def _check_error_body(status, raw):
    """Detecta el 403 de firma inválida y lo convierte en LIVE_AUTH_FAILED."""
    if status == 403:
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
            detail = doc.get("error") or doc.get("message") or ""
        except (ValueError, UnicodeError):
            detail = ""
        raise CatalogError(
            "LIVE_AUTH_FAILED: el servidor devolvió HTTP 403 (%s). "
            "La firma del catálogo no está verificada; ver el docstring "
            "del módulo (constante YLA_VPN_SECURE_SALT_2026 y fórmula "
            "pendiente). Sin una firma válida no se puede descargar el "
            "catálogo; no se inventan servidores." % (detail or "forbidden")
        )
    if status == 405:
        raise CatalogError(
            "LIVE_AUTH_FAILED: HTTP 405, método no permitido en este endpoint"
        )
    if status != 200:
        raise CatalogError(
            "YLA VPN download failed: HTTP %s" % status
        )


def register_device(device_id=None, device_model="Redmi 14C"):
    """POST /api/user/init. Devuelve el dict completo de la respuesta."""
    device_id = device_id or str(uuid.uuid4())
    status, raw = _request(
        "POST",
        INIT_URL,
        body={
            "device_id": device_id,
            "device_model": device_model,
            "app_version": APP_VERSION,
        },
    )
    if status != 200:
        raise CatalogError("YLA VPN init failed: HTTP %s" % status)
    doc = parse_document(raw.decode("utf-8"))
    if doc.get("success") is not True:
        raise CatalogError("YLA VPN init failed: %s" % (doc,))
    return doc


def fetch_settings():
    """GET /api/app-yla-setting (abierto, verificado en vivo)."""
    status, raw = _request("GET", SETTINGS_URL)
    if status != 200:
        raise CatalogError("YLA VPN settings failed: HTTP %s" % status)
    return parse_document(raw.decode("utf-8"))


def fetch_plans():
    """GET /api/plans (abierto, verificado en vivo)."""
    status, raw = _request("GET", PLANS_URL)
    if status != 200:
        raise CatalogError("YLA VPN plans failed: HTTP %s" % status)
    return parse_document(raw.decode("utf-8"))


def fetch_notifications(device_id):
    """POST /api/user/notifications (solo device_id, verificado en vivo)."""
    status, raw = _request(
        "POST", NOTIFICATIONS_URL, body={"device_id": device_id}
    )
    if status != 200:
        raise CatalogError("YLA VPN notifications failed: HTTP %s" % status)
    return parse_document(raw.decode("utf-8"))


def fetch_catalog(device_id=None, user_code=None, device_model="Redmi 14C"):
    """Descarga el catálogo en vivo (GET /api/v2ray/list).

    Si no se pasa device_id, genera uno y lo registra con /api/user/init.
    Hoy el servidor responde HTTP 403 a todas las firmas probadas, así
    que esto se detiene con LIVE_AUTH_FAILED. Cuando la fórmula de la
    firma se conozca, este mismo flujo descargará el catálogo.
    """
    if device_id is None:
        init = register_device(device_model=device_model)
        data = init.get("data") or {}
        device_id = data.get("device_id")
        user_code = data.get("user_code")
    signature = compute_signature(device_id)
    url = "%s?device_id=%s&signature=%s" % (LIST_URL, device_id, signature)
    status, raw = _request("GET", url)
    _check_error_body(status, raw)
    return raw


def _read_input(path=None, use_stdin=False):
    if use_stdin:
        return sys.stdin.buffer.read()
    if path is None:
        raise CatalogError("YLA VPN: falta el archivo de entrada")
    with open(path, "rb") as stream:
        return stream.read(MAX_INPUT + 1)


def _self_test():
    """Pruebas internas sin red."""
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))
        return ok

    # 1. decode() abre un catálogo sintético con el esquema esperado
    #    (nombres de campo tomados del binario Dart; la muestra es
    #    sintética porque el catálogo en vivo está bloqueado por la firma).
    synthetic = {
        "success": True,
        "data": [
            {
                "id": 1,
                "remark": "Singapore-01",
                "country_code": "sg",
                "flag": "sg",
                "address": "sg1.example.invalid",
                "port": 443,
                "protocol": "vmess",
                "security": "auto",
                "network": "ws",
                "path": "/",
                "host": "sg1.example.invalid",
                "sni": "sg1.example.invalid",
                "tls": "tls",
                "flow": "",
                "fingerprint": "chrome",
                "is_vip": False,
                "active": True,
                "config": "vmess://e30=",
            },
            {
                "id": 2,
                "remark": "Japan-VIP-01",
                "country_code": "jp",
                "address": "jp1.example.invalid",
                "port": 443,
                "protocol": "vless",
                "security": "none",
                "network": "tcp",
                "is_vip": True,
                "active": True,
                "config": "vless://e30=",
            },
        ],
    }
    doc = decode(json.dumps(synthetic).encode("utf-8"))
    summary = catalog_summary(doc)
    check("decode synthetic", summary["servers"] == 2, summary)
    check("summary free/vip", summary["free"] == 1 and summary["vip"] == 1,
          summary)
    check("summary payloads", summary["payloads"] == 2, summary)
    check("run() round-trip",
          json.loads(run(json.dumps(synthetic).encode("utf-8"))) == synthetic)

    # 2. La firma documentada es determinista (aunque no verificada).
    sig_a = compute_signature("a1b2c3d4e5f60718")
    sig_b = compute_signature("a1b2c3d4e5f60718")
    check("signature deterministic", sig_a == sig_b and len(sig_a) == 64,
          sig_a)
    check("signature is sha256(device_id + salt)",
          sig_a == hashlib.sha256(
              ("a1b2c3d4e5f60718" + SECURE_SALT).encode("utf-8")).hexdigest())

    # 3. Guardas: JSON duplicado, constantes inválidas, lista vacía.
    try:
        decode(b'{"success": true, "data": [], "data": []}')
        check("duplicate key rejected", False)
    except CatalogError:
        check("duplicate key rejected", True)
    try:
        decode(b'{"success": true, "data": [{"id": 1}], "x": NaN}')
        check("NaN rejected", False)
    except CatalogError:
        check("NaN rejected", True)
    try:
        decode(b'{"success": true, "data": []}')
        check("empty list rejected", False)
    except CatalogError:
        check("empty list rejected", True)
    try:
        decode(b'{"success": false, "error": "Unauthorized access or '
               b'invalid signature"}')
        check("403 body rejected", False)
    except CatalogError:
        check("403 body rejected", True)

    # 4. _check_error_body convierte el 403 en LIVE_AUTH_FAILED.
    try:
        _check_error_body(
            403, b'{"success": false, "error": "Unauthorized access or '
                 b'invalid signature"}')
        check("403 -> LIVE_AUTH_FAILED", False)
    except CatalogError as exc:
        check("403 -> LIVE_AUTH_FAILED", "LIVE_AUTH_FAILED" in str(exc),
              str(exc)[:80])

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print("%s %s%s" % ("OK  " if ok else "FAIL", name,
                           (": %s" % (detail,)) if detail else ""))
    if failed:
        raise SystemExit("self-test failed: %d/%d" % (len(failed), len(checks)))
    print("self-test: %d/%d OK" % (len(checks), len(checks)))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="YLA VPN (com.thuaung.ylavpn) — catálogo Cloud")
    parser.add_argument("file", nargs="?", help="JSON de catálogo guardado")
    parser.add_argument("--url", action="store_true",
                        help="descargar el catálogo en vivo")
    parser.add_argument("--init", action="store_true",
                        help="registrar un dispositivo (POST /api/user/init)")
    parser.add_argument("--settings", action="store_true",
                        help="GET /api/app-yla-setting")
    parser.add_argument("--plans", action="store_true",
                        help="GET /api/plans")
    parser.add_argument("--notifications", action="store_true",
                        help="POST /api/user/notifications")
    parser.add_argument("--device-id", help="device_id a usar/registrar")
    parser.add_argument("--device-model", default="Redmi 14C",
                        help="device_model para --init/--url")
    parser.add_argument("--stdin", action="store_true",
                        help="leer el catálogo de stdin")
    parser.add_argument("-o", "--output", help="archivo de salida")
    parser.add_argument("--self-test", action="store_true",
                        help="pruebas internas (sin red)")
    args = parser.parse_args(argv)

    try:
        if args.self_test:
            return _self_test()

        if args.init:
            doc = register_device(args.device_id, args.device_model)
            out = json.dumps(doc, ensure_ascii=False, indent=2)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(out + "\n")
            else:
                print(out)
            data = doc.get("data") or {}
            print("user_code: %s" % data.get("user_code"), file=sys.stderr)
            print("device_id: %s" % data.get("device_id"), file=sys.stderr)
            return 0

        if args.settings:
            out = json.dumps(fetch_settings(), ensure_ascii=False, indent=2)
            print(out)
            return 0

        if args.plans:
            out = json.dumps(fetch_plans(), ensure_ascii=False, indent=2)
            print(out)
            return 0

        if args.notifications:
            if not args.device_id:
                parser.error("--notifications requiere --device-id")
            out = json.dumps(fetch_notifications(args.device_id),
                             ensure_ascii=False, indent=2)
            print(out)
            return 0

        if args.url:
            raw = fetch_catalog(args.device_id,
                                device_model=args.device_model)
            doc = decode(raw)
            summary = catalog_summary(doc)
            print("catalog version (app): %s" % summary["app_version"])
            print("servers: %d (free %d, vip %d)" % (
                summary["servers"], summary["free"], summary["vip"]))
            print("payloads: %d" % summary["payloads"])
            if summary["countries"]:
                print("countries: %s" % ", ".join(summary["countries"]))
            rendered = run(raw)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(rendered + "\n")
            else:
                print(rendered)
            return 0

        raw = _read_input(args.file, args.stdin)
        rendered = run(raw)
        summary = catalog_summary(decode(raw))
        print("servers: %d (free %d, vip %d)" % (
            summary["servers"], summary["free"], summary["vip"]),
            file=sys.stderr)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered + "\n")
        else:
            print(rendered)
        return 0
    except CatalogError as exc:
        print("error: %s" % (exc,), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
