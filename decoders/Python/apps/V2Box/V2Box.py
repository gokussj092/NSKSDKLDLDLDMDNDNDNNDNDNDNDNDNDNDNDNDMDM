#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V2Box - V2ray Client (dev.hexasoftware.v2box) 6.2.3, build 88 — descarga
de suscripciones y decodificación de enlaces v2box://, formato de proveedor
de SP-DECODE. Solo biblioteca estándar de Python 3.10+.

HALLAZGO CLAVE: esta app NO tiene catálogo propio del vendedor. Es un
cliente V2Ray genérico: el usuario añade sus propias URLs de suscripción
y la app las descarga y las convierte en perfiles. El único endpoint del
vendedor es https://services.hexasoftware.dev/app-settings, que SOLO
devuelve promociones (verificado en vivo: 200, 932 B, 2 promociones iOS
+ 1 Android, updated_at 2026-10-31T23:22:32+00:00; 0 servidores, 0
payloads). El otro endpoint es https://services.hexasoftware.dev/
payment/api/ (verificación de compras, POST verify-subscription) y
https://api.ip.sb/geoip (geolocalización de la IP). No hay ninguna URL
de catálogo en el DEX. Por eso este script NO descarga de una URL fija:
descarga cualquier URL de suscripción EXACTAMENTE como lo hace la app
(misma petición, mismas cabeceras) y la parsea igual que ella.

Petición de suscripción (v6.s + xy0.d, OkHttp 5.3.2):
  GET <url de suscripción> (la URL la pone el usuario, no la app)
    Connection: close
    User-Agent: okhttp/5.3.2 (valor por defecto de OkHttp; la app no
      pone un UA propio en esta petición)
    Proxy-Authorization: Basic <...> (solo si hay proxy configurado)
  Timeout 15 s (UrlContentRequest(url, 15000, ...)); sigue redirecciones
  (followRedirects/followSslRedirects = true). Si el primer intento
  devuelve cuerpo vacío, la app reintenta con otro cliente (mismo GET).
  Límite de importación de archivos: 10 MB (xg2.d); se aplica el mismo
  límite aquí. La app lee la cabecera subscription-userinfo
  (upload/download/total/expire) y los campos del proveedor
  (announcement, update interval, support URL, web page URL).

Parseo del cuerpo (v6.l + v6.p + v6.n):
  1. Divide en líneas, quita espacios y líneas vacías, deduplica.
  2. Si ninguna línea es un enlace, intenta Base64 de todo el cuerpo
     (e23.b) y vuelve a dividir en líneas.
  3. Parsea cada línea: vmess://, vless://, trojan://, ss://, socks://,
     hysteria2://, hy2:// (los 7 esquemas del mapa de v6 / a4) y
     v2box://locked= (Base64 del texto de perfiles, v6.d/v6.h).
  4. Si el cuerpo es un JSON de config V2Ray con "outbounds", extrae
     cada outbound como perfil.
  5. Filtra por dispositivo: si hay un user_uuid configurado, solo
     quedan los perfiles cuyo deviceID coincide (v6.h).

Enlaces v2box:// (v6.d / v6.h, sin cambios respecto al repo):
  v2box://locked=<Base64>  donde el Base64 es el texto de los perfiles
  (uno por línea, normalmente enlaces vmess:// etc., con el deviceID
  aplicado). Además el manifest registra v2box://install-config y
  v2box://install-sub, y los archivos .v2box (ver V2Box_archivos.py).

Lo que NO se puede obtener offline: los perfiles "sealed" o
bloqueados por dispositivo, y cualquier suscripción cuya URL no se
conozca (la app no trae ninguna por defecto).

Uso:
  python3 V2Box.py --url <url de suscripción o app-settings>
  python3 V2Box.py --url <url> --json
  python3 V2Box.py --text 'vmess://...'   (decodifica enlaces en texto)
  python3 V2Box.py --self-test
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

PROVIDER = "V2Box"
APP_VERSION = "6.2.3"
APP_BUILD = 88
APP_SETTINGS_URL = "https://services.hexasoftware.dev/app-settings"
PAYMENT_API_URL = "https://services.hexasoftware.dev/payment/api/"
GEOIP_URL = "https://api.ip.sb/geoip"

USER_AGENT = "okhttp/5.3.2"
TIMEOUT = 15
MAX_BYTES = 10 * 1024 * 1024  # límite de importación de la app (xg2.d)
MAX_REDIRECTS = 20  # OkHttp por defecto

LINK_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "socks://",
                "hysteria2://", "hy2://")


# ------------------------------------------------------------------ utilidades
def _b64d_padded(text):
    """Base64 (estándar o URL-safe) con padding tolerante."""
    if text is None:
        return None
    s = "".join(str(text).split())
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except (binascii.Error, ValueError):
        return base64.b64decode(s)


def _b64_text(text):
    try:
        return _b64d_padded(text).decode("utf-8")
    except Exception:
        return None


def _stable_id(*parts):
    """id estable tipo UUID v3 de la app (UUID.nameUUIDFromBytes)."""
    import uuid
    data = "\x00".join("" if p is None else str(p) for p in parts).encode("utf-8")
    digest = hashlib.md5(data).digest()
    b = bytearray(digest)
    b[6] = (b[6] & 0x0f) | 0x30
    b[8] = (b[8] & 0x3f) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


# ------------------------------------------------------------- parseo enlaces
def parse_vmess(link):
    try:
        payload = json.loads(_b64_text(link[len("vmess://"):]))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    server = payload.get("add") or ""
    port = str(payload.get("port") or "")
    return {
        "type": "vmess", "name": payload.get("ps") or "",
        "server": server, "port": port,
        "uuid": payload.get("id") or "",
        "alter_id": payload.get("aid") or "",
        "network": payload.get("net") or "",
        "tls": payload.get("tls") or "",
        "sni": payload.get("sni") or payload.get("host") or "",
        "host": payload.get("host") or "",
        "path": payload.get("path") or "",
        "alpn": payload.get("alpn") or "",
        "fingerprint": payload.get("fp") or "",
        "raw": link,
    }


def parse_vless_trojan(link, scheme):
    try:
        u = urllib.parse.urlparse(link)
    except Exception:
        return None
    if not u.hostname:
        return None
    q = urllib.parse.parse_qs(u.query)
    one = lambda k, d="": (q.get(k) or [d])[0]
    user = urllib.parse.unquote(u.username or "")
    return {
        "type": scheme, "name": urllib.parse.unquote(u.fragment or ""),
        "server": u.hostname, "port": str(u.port or ""),
        "uuid": user if scheme == "vless" else "",
        "password": user if scheme == "trojan" else "",
        "network": one("type"), "tls": one("security"),
        "sni": one("sni"), "host": one("host"), "path": one("path"),
        "alpn": one("alpn"), "fingerprint": one("fp"),
        "flow": one("flow"), "raw": link,
    }


def parse_ss(link):
    try:
        body = link[len("ss://"):]
        frag = ""
        if "#" in body:
            body, frag = body.split("#", 1)
        if "@" not in body:
            decoded = _b64_text(body)
            if decoded is None or "@" not in decoded:
                return None
            body = decoded
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = _b64_text(userinfo) or ""
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        return {
            "type": "ss", "name": urllib.parse.unquote(frag),
            "server": host, "port": port,
            "method": method, "password": urllib.parse.unquote(password),
            "raw": link,
        }
    except Exception:
        return None


def parse_socks_hysteria(link, scheme):
    try:
        u = urllib.parse.urlparse(link)
    except Exception:
        return None
    if not u.hostname:
        return None
    q = urllib.parse.parse_qs(u.query)
    one = lambda k, d="": (q.get(k) or [d])[0]
    return {
        "type": scheme, "name": urllib.parse.unquote(u.fragment or ""),
        "server": u.hostname, "port": str(u.port or ""),
        "username": urllib.parse.unquote(u.username or ""),
        "password": urllib.parse.unquote(u.password or ""),
        "sni": one("sni"), "insecure": one("insecure"),
        "raw": link,
    }


def parse_v2box_link(link):
    """v2box://locked=<Base64> -> texto de perfiles (v6.d/v6.h)."""
    try:
        encoded = link.split("locked=", 1)[1]
        text = _b64_text(encoded)
    except Exception:
        return None
    if text is None:
        return None
    return parse_subscription_text(text)


def parse_link(line):
    line = line.strip()
    if not line:
        return None
    low = line.lower()
    if low.startswith("vmess://"):
        return parse_vmess(line)
    if low.startswith("vless://"):
        return parse_vless_trojan(line, "vless")
    if low.startswith("trojan://"):
        return parse_vless_trojan(line, "trojan")
    if low.startswith("ss://"):
        return parse_ss(line)
    if low.startswith("socks://"):
        return parse_socks_hysteria(line, "socks")
    if low.startswith("hysteria2://"):
        return parse_socks_hysteria(line, "hysteria2")
    if low.startswith("hy2://"):
        return parse_socks_hysteria(line, "hy2")
    if low.startswith("v2box://locked="):
        return {"type": "v2box_locked", "link": line,
                "profiles": parse_v2box_link(line) or []}
    return None


def parse_subscription_text(text):
    """Parses el cuerpo de una suscripción como lo hace v6.l/v6.n."""
    if not text:
        return []
    lines = [ln.strip() for ln in text.replace("\r\n", "\n").split("\n")]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    seen = set()
    uniq = []
    for ln in lines:
        if ln not in seen:
            seen.add(ln)
            uniq.append(ln)
    profiles = []
    for ln in uniq:
        parsed = parse_link(ln)
        if isinstance(parsed, dict) and parsed.get("type") == "v2box_locked":
            profiles.extend(parsed.get("profiles") or [])
        elif parsed is not None:
            profiles.append(parsed)
    if profiles:
        return profiles
    # Sin enlaces: intenta Base64 de todo el cuerpo (e23.b) y reparsea.
    decoded = _b64_text("".join(uniq))
    if decoded and decoded != text:
        return parse_subscription_text(decoded)
    # JSON de config V2Ray con "outbounds".
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get("outbounds"), list):
            for ob in obj["outbounds"]:
                if not isinstance(ob, dict):
                    continue
                settings = ob.get("settings") or {}
                servers = settings.get("servers") or settings.get("vnext") or []
                for srv in servers if isinstance(servers, list) else []:
                    if isinstance(srv, dict):
                        profiles.append({
                            "type": ob.get("protocol") or "",
                            "name": ob.get("tag") or "",
                            "server": srv.get("address") or "",
                            "port": str(srv.get("port") or ""),
                            "uuid": srv.get("id") or "",
                            "raw": json.dumps(ob, ensure_ascii=False),
                        })
    except Exception:
        pass
    return profiles


def parse_userinfo(value):
    """Cabecera subscription-userinfo: upload=..; download=..; total=..;
    expire=.. (la app la lee en v6.a)."""
    info = {}
    if not value:
        return info
    for part in str(value).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            info[k.strip()] = v.strip()
    return info


# ----------------------------------------------------------------- descarga
def fetch_url(url):
    """Descarga una URL EXACTAMENTE como la app (v6.s + xy0.d, OkHttp):
    GET, Connection: close, UA okhttp/5.3.2, 15 s, sigue redirecciones.
    Devuelve (cuerpo_bytes, cabeceras_dict, url_final, status)."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("Connection", "close")
    req.add_header("User-Agent", USER_AGENT)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    opener.addheaders = []
    with opener.open(req, timeout=TIMEOUT) as resp:
        body = resp.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            body = body[:MAX_BYTES]
        return (body, dict(resp.headers), resp.geturl(), resp.status)


def decode(text_or_url, url=None, device_uuid=None):
    """Decodifica una suscripción (texto o URL) o el app-settings.
    Devuelve el dict de resultado del proveedor (nunca None)."""
    warnings = []
    body = None
    headers = {}
    final_url = None
    status = None
    if url is not None:
        try:
            body, headers, final_url, status = fetch_url(url)
        except Exception as exc:
            return {
                "provider": PROVIDER, "app_version": APP_VERSION,
                "app_build": APP_BUILD, "status": "error",
                "error": "No se pudo descargar la suscripción: %s" % exc,
                "url": url,
            }
        if status != 200:
            return {
                "provider": PROVIDER, "app_version": APP_VERSION,
                "app_build": APP_BUILD, "status": "error",
                "error": "HTTP %s al descargar la suscripción" % status,
                "url": url, "final_url": final_url,
            }
    elif text_or_url is not None:
        body = text_or_url.encode("utf-8") if isinstance(text_or_url, str) else text_or_url
        final_url = None
    else:
        return {
            "provider": PROVIDER, "app_version": APP_VERSION,
            "app_build": APP_BUILD, "status": "error",
            "error": "Falta --url o --text",
        }

    result = {
        "provider": PROVIDER, "app_version": APP_VERSION,
        "app_build": APP_BUILD, "status": "ok",
        "url": url, "final_url": final_url,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    userinfo = parse_userinfo(headers.get("subscription-userinfo") or
                             headers.get("Subscription-Userinfo"))
    if userinfo:
        result["subscription_userinfo"] = userinfo

    text = body.decode("utf-8", "replace")

    # app-settings: JSON con "promotions", SIN servidores.
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and "promotions" in obj:
            promos = list(obj.get("promotions") or [])
            for p in promos:
                if isinstance(p, dict):
                    p.setdefault("platform", "ios")
            promos_android = list(obj.get("promotions_android") or [])
            for p in promos_android:
                if isinstance(p, dict):
                    p.setdefault("platform", "android")
            promos = promos + promos_android
            result.update({
                "type": "app_settings",
                "promotions": promos,
                "promotion_chance": obj.get("promotion_chance"),
                "promotion_chance_android": obj.get("promotion_chance_android"),
                "updated_at": obj.get("updated_at"),
                "servers": [],
                "profiles": [],
                "free_servers": 0,
                "payloads": 0,
                "note": "app-settings SOLO devuelve promociones; NO es "
                        "un catálogo de servidores (verificado en vivo). "
                        "V2Box es un cliente genérico: los servidores "
                        "vienen de las suscripciones del usuario.",
            })
            return result

    profiles = parse_subscription_text(text)
    if device_uuid:
        filtered = []
        for prof in profiles:
            if prof.get("device_id") in (None, device_uuid):
                filtered.append(prof)
        profiles = filtered
    result.update({
        "type": "subscription",
        "servers": [{"name": p.get("name"), "type": p.get("type"),
                     "server": p.get("server"), "port": p.get("port")}
                    for p in profiles],
        "profiles": profiles,
        "free_servers": len(profiles),
        "payloads": 0,
    })
    if not profiles:
        warnings.append("La suscripción no devolvió ningún perfil "
                        "reconocible (cuerpo vacío o formato no soportado).")
    result["warnings"] = warnings
    return result


def run(url=None, text=None):
    return json.dumps(decode(text, url=url), ensure_ascii=False, indent=2)


# -------------------------------------------------------------------- CLI
def _selftest():
    checks = []
    # 1. Parseo de enlaces de los 7 esquemas.
    sample = "\n".join([
        "vmess://" + base64.b64encode(json.dumps({
            "v": "2", "ps": "Test VMess", "add": "1.2.3.4", "port": "443",
            "id": "11111111-2222-3333-4444-555555555555", "aid": "0",
            "net": "ws", "type": "none", "host": "example.com",
            "path": "/ws", "tls": "tls", "sni": "example.com",
        }).encode()).decode(),
        "vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443"
        "?security=tls&sni=example.com&type=ws#Test VLESS",
        "trojan://pass123@9.9.9.9:443?sni=example.com#Test Trojan",
        "ss://YWVzLTI1Ni1nY206cGFzczEyMw@10.0.0.1:8388#Test SS",
        "hysteria2://user:pass@11.11.11.11:443?sni=example.com#Test HY2",
        "socks://user:pass@12.12.12.12:1080#Test SOCKS",
    ])
    profs = parse_subscription_text(sample)
    checks.append(("parseo 6 esquemas", len(profs) == 6))
    checks.append(("vmess campos", profs[0].get("server") == "1.2.3.4"
                   and profs[0].get("name") == "Test VMess"))
    checks.append(("vless campos", profs[1].get("type") == "vless"
                   and profs[1].get("server") == "5.6.7.8"))
    # 2. Suscripción en Base64 de cuerpo entero.
    b64 = base64.b64encode(sample.encode()).decode()
    profs2 = parse_subscription_text(b64)
    checks.append(("suscripción Base64 entera", len(profs2) == 6))
    # 3. v2box://locked= (Base64 del texto de perfiles).
    locked = ("v2box://locked="
              + base64.b64encode(sample.encode()).decode())
    profs3 = parse_subscription_text(locked)
    checks.append(("v2box://locked=", len(profs3) == 6))
    # 4. JSON de config V2Ray con outbounds.
    cfg = json.dumps({"outbounds": [{
        "protocol": "vmess", "tag": "Proxy",
        "settings": {"vnext": [{"address": "13.14.15.16", "port": 443,
                                "users": [{"id": "x"}]}]}}]})
    profs4 = parse_subscription_text(cfg)
    checks.append(("config V2Ray JSON", len(profs4) == 1
                   and profs4[0].get("server") == "13.14.15.16"))
    # 5. app-settings en vivo: promociones, 0 servidores.
    try:
        r = decode(None, url=APP_SETTINGS_URL)
        checks.append(("app-settings en vivo", r["status"] == "ok"
                       and r.get("type") == "app_settings"
                       and r.get("free_servers") == 0
                       and len(r.get("promotions") or []) == 3))
    except Exception as exc:
        checks.append(("app-settings en vivo", "ERROR: %s" % exc))
    # 6. userinfo de suscripción.
    checks.append(("subscription-userinfo",
                   parse_userinfo("upload=0; download=100; total=1000; "
                                  "expire=1790000000")["total"] == "1000"))
    failed = [n for n, ok in checks if ok is not True]
    for name, ok in checks:
        print(("OK  " if ok is True else "FAIL") + " " + name
              + ("" if ok is True else " -> %s" % ok))
    print("self-test: %d/%d OK" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="V2Box 6.2.3 — suscripciones y enlaces v2box:// "
                    "(sin catálogo propio del vendedor).")
    ap.add_argument("--url", default=None,
                    help="URL de suscripción (o %s)" % APP_SETTINGS_URL)
    ap.add_argument("--text", default=None,
                    help="Texto con enlaces a decodificar")
    ap.add_argument("--device-uuid", default=None,
                    help="UUID del dispositivo para filtrar perfiles")
    ap.add_argument("--json", action="store_true",
                    help="Imprimir el resultado como JSON")
    ap.add_argument("--self-test", action="store_true",
                    help="Pruebas sintéticas + app-settings en vivo")
    args = ap.parse_args(argv)
    if args.self_test:
        return _selftest()
    if not args.url and not args.text:
        ap.error("falta --url o --text (o usa --self-test)")
    result = decode(args.text, url=args.url, device_uuid=args.device_uuid)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("status") == "ok" else 1
    if result.get("status") != "ok":
        print("ERROR: %s" % result.get("error"))
        return 1
    if result.get("type") == "app_settings":
        print("V2Box app-settings: %d promociones, 0 servidores"
              % len(result.get("promotions") or []))
        for p in result.get("promotions") or []:
            print(" - %s (%s)" % (p.get("title") or p.get("id"),
                                  p.get("platform") or "?"))
        print("NOTA: app-settings NO es un catálogo de servidores.")
        return 0
    print("V2Box suscripción: %d perfiles" % len(result.get("profiles", [])))
    for s in result.get("servers", []):
        print(" - %s | %s | %s:%s" % (s.get("name"), s.get("type"),
                                      s.get("server"), s.get("port")))
    for w in result.get("warnings", []):
        print("AVISO: " + w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
