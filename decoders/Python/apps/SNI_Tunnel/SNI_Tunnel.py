#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNI Tunnel - V2Ray VPN Client (com.asnly.snitunnel) 1.3.0 — subscription
fetcher + parser, formato de proveedor de SP-DECODE.

HALLAZGO CLAVE: esta app NO tiene catálogo propio del vendedor. Es un
cliente V2Ray genérico (Flutter + núcleo xray en Go): el usuario añade
sus propias URLs de suscripción y la app las descarga y las convierte
en perfiles. Por eso este script NO descarga de una URL fija: descarga
cualquier URL de suscripción EXACTAMENTE como lo hace la app (misma
petición, mismas cabeceras, mismos límites) y la parsea igual que ella.

Método recuperado del DEX (Kotlin, paquete com.asnly.snitunnel.subscription):
  GET <url de suscripción> (la URL la pone el usuario, no la app)
    Accept: text/plain, application/octet-stream, */*
    User-Agent: SNI-Tunnel/1.3.0 (Android)
    x-hwid: <UUID aleatorio en minúsculas, persistente por dispositivo>
    x-device-os: Android
    x-ver-os: <versión de Android, p. ej. 14>
    x-device-model: <FABRICANTE MODELO, o "Android Device">
  Solo HTTPS (rechaza http y URLs con credenciales). Sin redirección
  automática: sigue Location a mano, hasta 5 saltos. Timeouts 20 s
  conectar / 60 s leer. Límite 16 MB (16777216 B), tanto por
  Content-Length como durante la lectura. Si el panel exige HWID, el
  servidor responde x-hwid-max-devices-reached / x-hwid-limit = true
  (límite de dispositivos) o 404 + x-hwid-not-supported = true.
  Cabecera subscription-userinfo (y alias x-subscription-userinfo,
  subscription-user-info, x-user-info, user-info, profile-userinfo):
  upload / download / total / expire.

Parseo del cuerpo (SubscriptionContent.parse):
  1. Quita líneas de comentario (# ...) y el BOM.
  2. Si ninguna línea trae "://", intenta Base64 URL-safe de todo el
     cuerpo (sin espacios) y vuelve a quitar comentarios.
  3. Parsea líneas de enlaces vmess://, vless://, trojan://, ss://,
     hy2://, hysteria2://, tuic://, socks://.
  4. Si no sale ningún perfil, intenta Clash YAML: sección "proxies:"
     (bloque "clave: valor" o diccionario en línea "{...}"), tipos
     vmess / vless / trojan / ss / shadowsocks / hysteria2.
  5. Directivas del proveedor en las líneas "# clave: valor" del cuerpo
     (crudo y decodificado): profile-title, support-url,
     profile-web-page-url, announce, profile-update-interval,
     hide-settings, providerid, subscriptions-sort-type, sub-expire,
     sub-expire-button-link, notification-subs-expire, fallback-url,
     new-url, new-domain (los valores pueden venir con prefijo base64:).
  6. Dedup por stableKey = SHA-256 hex de
     tipo, servidor, puerto, uuid, usuario, contraseña, método, red,
     seguridad, sni, wsHost, wsPath, grpcServiceName, realityPublicKey,
     realityShortId unidos con NUL. id = UUID v3 (MD5) de
     "<subscriptionId>:<stableKey>" (igual que UUID.nameUUIDFromBytes).

Lo que NO se puede decodificar offline (vive en el Dart AOT, sin
literales en el binario): los enlaces v2rc:// (con contraseña),
v2rcloud:// (cloud link) y los perfiles "sealed" (cifrados por
dispositivo). Ver SNI_Tunnel_archivos.py, que los reporta como
UNSUPPORTED_SEALED / UNSUPPORTED_CLOUD en vez de inventar un descifrado.

Solo biblioteca estándar de Python 3.10+.
"""

import base64
import hashlib
import http.client
import json
import re
import ssl
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

USER_AGENT = "SNI-Tunnel/1.3.0 (Android)"
ACCEPT = "text/plain, application/octet-stream, */*"
MAX_BYTES = 16777216  # ImportLimits.MAX_BYTES
MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 20
READ_TIMEOUT = 60
DEFAULT_UPDATE_INTERVAL_HOURS = 6
TOO_LARGE_MESSAGE = "The subscription or file exceeds the 16 MB limit."

USERINFO_HEADER = "subscription-userinfo"
USERINFO_ALIASES = (
    "x-subscription-userinfo",
    "subscription-user-info",
    "x-user-info",
    "user-info",
    "profile-userinfo",
)

DIRECTIVE_KEYS = (
    "profile-title", "support-url", "profile-web-page-url", "announce",
    "profile-update-interval", "hide-settings", "providerid",
    "subscriptions-sort-type", "sub-expire", "sub-expire-button-link",
    "notification-subs-expire", "fallback-url", "new-url", "new-domain",
)
COMMENT_LINE_RE = re.compile(r"^#\s*([A-Za-z0-9-]+)\s*(?::\s*|\s+)(.*)$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
SORT_TYPES = ("without", "ping", "alphabet")

# ---------------------------------------------------------------- URL / fetch


def require_https(url):
    """Igual que SubscriptionHttpClient.Companion.requireHttps."""
    try:
        u = urllib.parse.urlparse(url.strip())
    except Exception:
        raise ValueError("Invalid subscription URL.")
    if u.scheme != "https" or not u.hostname:
        raise ValueError("Subscription URL must use HTTPS.")
    if u.username or u.password:
        raise ValueError("Subscription URL must not contain credentials.")
    return url.strip()


def new_hwid():
    """Igual que HwidProvider: UUID aleatorio en minúsculas."""
    return str(uuid.uuid4()).lower()


def fetch(url, hwid=None, device_model="Android Device", os_version="14",
          extra_headers=None):
    """Descarga una suscripción exactamente como la app.

    Devuelve (body_text, userinfo_dict_o_None, final_url, headers_dict).
    Lanza ValueError con los mensajes de la app cuando algo falla.
    """
    current = require_https(url)
    hwid = hwid or new_hwid()
    headers = {
        "Accept": ACCEPT,
        "User-Agent": USER_AGENT,
        "x-hwid": hwid,
        "x-device-os": "Android",
        "x-ver-os": os_version or "14",
        "x-device-model": device_model or "Android Device",
    }
    if extra_headers:
        for k, v in extra_headers.items():
            if k and v:
                headers[k] = v
    collected_userinfo = None
    for hop in range(MAX_REDIRECTS + 1):
        u = urllib.parse.urlparse(current)
        conn = http.client.HTTPSConnection(
            u.hostname, u.port or 443,
            timeout=CONNECT_TIMEOUT, context=ssl.create_default_context())
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            raw_headers = {}
            for k, v in resp.getheaders():
                raw_headers.setdefault(k.lower(), []).append(v)

            def header(name):
                vals = raw_headers.get(name.lower())
                return vals[0] if vals else None

            ui = extract_userinfo(raw_headers)
            if ui is not None:
                collected_userinfo = ui
            hwid_limit = header("x-hwid-max-devices-reached") or header("x-hwid-limit")
            if hwid_limit and hwid_limit.lower() == "true":
                raise ValueError(
                    "Bu abonelikte maksimum cihaz sınırına ulaşıldı. "
                    "Lütfen eski bir cihazı panelden kaldırın.")
            if 300 <= status < 400:
                if hop == MAX_REDIRECTS:
                    raise ValueError("Too many subscription redirects.")
                loc = header("location")
                if not loc:
                    raise ValueError("Subscription redirect has no location.")
                current = resolve_redirect(current, loc)
                conn.close()
                continue
            if status == 404:
                not_supported = header("x-hwid-not-supported")
                if not_supported and not_supported.lower() == "true":
                    raise ValueError(
                        "Bu abonelik paneli HWID cihaz kimliği "
                        "doğrulaması gerektiriyor veya desteklemiyor.")
            if status < 200 or status >= 300:
                raise ValueError(
                    "Subscription request failed with HTTP %d." % status)
            declared = resp.getheader("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > MAX_BYTES:
                        raise ValueError(TOO_LARGE_MESSAGE)
                except ValueError as e:
                    if str(e) == TOO_LARGE_MESSAGE:
                        raise
            body = read_body_limited(resp)
            if collected_userinfo is None:
                collected_userinfo = ui
            flat_headers = {k: v[0] for k, v in raw_headers.items()}
            return body, collected_userinfo, current, flat_headers
        finally:
            conn.close()
    raise ValueError("Too many subscription redirects.")


def resolve_redirect(current, location):
    """Igual que SubscriptionKt.resolveSubscriptionRedirect."""
    loc = location.replace(" ", "%20")
    try:
        resolved = urllib.parse.urljoin(current, loc)
    except Exception:
        resolved = loc
    return require_https(resolved)


def read_body_limited(resp, limit=MAX_BYTES):
    """Igual que SubscriptionKt.readSubscriptionBody (límite en lectura)."""
    chunks = []
    total = 0
    while True:
        data = resp.read(8192)
        if not data:
            break
        total += len(data)
        if total > limit:
            raise ValueError(TOO_LARGE_MESSAGE)
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


# ---------------------------------------------------------------- userinfo


def _parse_number_or_bytes(raw):
    s = raw.strip().strip("\"'`")
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        v = float(s)
        if 0 <= v <= 9.223372036854776e18:
            return int(v)
    except ValueError:
        pass
    low = s.lower()
    mult = None
    for suffix, m in (("tib", 1099511627776), ("tb", 1099511627776),
                      ("t", 1099511627776), ("gib", 1073741824),
                      ("gb", 1073741824), ("g", 1073741824),
                      ("mib", 1048576), ("mb", 1048576), ("m", 1048576),
                      ("kib", 1024), ("kb", 1024), ("k", 1024),
                      ("b", 1)):
        if low.endswith(suffix):
            mult = m
            break
    if mult is None:
        return None
    num = "".join(c for c in low if c.isdigit() or c == ".")
    try:
        return int(float(num) * mult)
    except ValueError:
        return None


def _parse_expiry(raw):
    s = raw.strip().strip("\"'`")
    if not s:
        return None
    n = _parse_number_or_bytes(s)
    if n is not None and n > 0:
        return n * 1000 if n < 100000000000 else n
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    return None


def parse_userinfo(value):
    """Igual que SubscriptionUserInfoParser.parse."""
    if value is None or len(value) > 2048:
        return None
    upload = download = total = unused = used = expire = None
    for part in re.split(r"[;,]", value):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip().lower()
        val = val.strip().strip("\"'`")
        if not val:
            continue
        if key in ("upload", "uploadbytes", "u", "up"):
            n = _parse_number_or_bytes(val)
            if n is not None and n >= 0:
                upload = n
        elif key in ("download", "downloadbytes", "down", "d"):
            n = _parse_number_or_bytes(val)
            if n is not None and n >= 0:
                download = n
        elif key in ("total", "totalbytes", "quota", "max", "allowance"):
            n = _parse_number_or_bytes(val)
            if n is not None and n > 0:
                total = n
        elif key in ("unused", "left", "remaining"):
            n = _parse_number_or_bytes(val)
            if n is not None and n >= 0:
                unused = n
        elif key in ("used", "spent"):
            n = _parse_number_or_bytes(val)
            if n is not None and n >= 0:
                used = n
        elif key in ("expire", "expires", "expiry", "expiration",
                     "expires_at", "expire_time"):
            e = _parse_expiry(val)
            if e is not None and e > 0:
                expire = e
    if upload is None and download is None:
        if total is not None and unused is not None:
            download = max(0, total - unused)
        elif used is not None:
            download = used
    info = {"upload": upload, "download": download, "total": total,
            "expire": expire}
    info = {k: v for k, v in info.items() if v is not None}
    return info or None


def extract_userinfo(raw_headers):
    """Busca subscription-userinfo y sus alias (insensible a mayúsculas)."""
    wanted = (USERINFO_HEADER,) + USERINFO_ALIASES
    for name in wanted:
        vals = raw_headers.get(name.lower())
        if vals:
            for v in vals:
                parsed = parse_userinfo(v)
                if parsed is not None:
                    return parsed
    return None


# ---------------------------------------------------------------- provider directives


def _clean(value, max_chars):
    s = "".join(c for c in value if ord(c) >= 32 or c == "\n")
    s = s.strip()
    if not s:
        return None
    if len(s) <= max_chars:
        return s
    cut = s[:max_chars].rstrip()
    return cut or None


def _single_line(value, max_chars):
    return _clean(re.sub(r"[\r\n\t]+", " ", value), max_chars)


def _multi_line(value, max_chars):
    return _clean(value.replace("\r\n", "\n").replace("\r", "\n")
                  .replace("\t", " "), max_chars)


def _decode_base64_utf8(value):
    s = "".join(c for c in value if not c.isspace())
    if not s:
        return None
    try:
        raw = base64.b64decode(
            s.replace("-", "+").replace("_", "/")
            + "=" * ((4 - len(s) % 4) % 4))
        return raw.decode("utf-8")
    except Exception:
        return None


def _decode_value(raw):
    s = raw.strip()
    if s.lower().startswith("base64:"):
        return _decode_base64_utf8(s[7:])
    return s or None


def _is_enabled(value):
    return value is not None and value.strip().lower() in ("true", "1")


def _link_or_null(value):
    s = value.strip()
    try:
        u = urllib.parse.urlparse(s)
    except Exception:
        return None
    scheme = (u.scheme or "").lower()
    if scheme == "https" and u.hostname and not u.username:
        return s
    if scheme == "tg" and u.path:
        return s
    return None


def _subscription_url_or_null(value):
    try:
        return require_https(value.strip())
    except ValueError:
        return None


def comment_fields(text):
    """Igual que ProviderMetadataParser.commentFields."""
    fields = {}
    for line in text.splitlines():
        m = COMMENT_LINE_RE.match(line.strip())
        if not m:
            continue
        key = m.group(1).lower()
        if key in DIRECTIVE_KEYS and key not in fields:
            fields[key] = m.group(2).strip()
    return fields


def parse_provider_directives(texts):
    """Igual que ProviderMetadataParser.parse."""
    merged = {}
    for text in texts:
        for k, v in comment_fields(text).items():
            merged.setdefault(k, v)

    def raw(key):
        return merged.get(key)

    title = _single_line(_decode_value(raw("profile-title")), 25) \
        if raw("profile-title") else None
    support = _link_or_null(_decode_value(raw("support-url"))) \
        if raw("support-url") else None
    webpage = _link_or_null(_decode_value(raw("profile-web-page-url"))) \
        if raw("profile-web-page-url") else None
    announce = _multi_line(_decode_value(raw("announce")), 200) \
        if raw("announce") else None
    interval = None
    if raw("profile-update-interval"):
        try:
            n = int(raw("profile-update-interval").strip())
            if n >= 1:
                interval = min(n, 720)
        except ValueError:
            pass
    hide = _is_enabled(raw("hide-settings"))
    provider_id = _single_line(_decode_value(raw("providerid")), 128) \
        if raw("providerid") else None
    sort_type = None
    if raw("subscriptions-sort-type"):
        s = raw("subscriptions-sort-type").strip().lower()
        if s in SORT_TYPES:
            sort_type = s
    sub_expire = _is_enabled(raw("sub-expire"))
    sub_expire_link = _link_or_null(
        _decode_value(raw("sub-expire-button-link"))) \
        if raw("sub-expire-button-link") else None
    notify = _is_enabled(raw("notification-subs-expire"))
    fallback = _subscription_url_or_null(
        _decode_value(raw("fallback-url"))) \
        if raw("fallback-url") else None
    new_url = _subscription_url_or_null(
        _decode_value(raw("new-url"))) \
        if raw("new-url") else None
    new_domain = None
    if raw("new-domain"):
        d = _decode_value(raw("new-domain"))
        if d:
            d = d.strip().lower()
            if DOMAIN_RE.match(d):
                new_domain = d
    metadata = {
        "title": title, "supportUrl": support, "webPageUrl": webpage,
        "announce": announce, "updateIntervalHours": interval,
        "hideSettings": hide, "providerId": provider_id,
        "sortType": sort_type, "subExpire": sub_expire,
        "subExpireButtonLink": sub_expire_link,
        "notifySubsExpire": notify, "fallbackUrl": fallback,
    }
    metadata = {k: v for k, v in metadata.items() if v is not None}
    return {"provider": metadata or None, "newUrl": new_url,
            "newDomain": new_domain}


# ---------------------------------------------------------------- link parsing


def _b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def _split_name(link):
    if "#" in link:
        link, frag = link.split("#", 1)
        return link, urllib.parse.unquote(frag)
    return link, ""


def _parse_query(qs):
    out = {}
    for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=True):
        out[k.lower()] = v
    return out


def parse_vmess(link):
    body, name = _split_name(link[len("vmess://"):])
    try:
        data = json.loads(_b64d(body).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("add"):
        return None
    p = {
        "type": "vmess",
        "remark": data.get("ps") or name or "",
        "server": str(data.get("add", "")),
        "port": int(data.get("port") or 0),
        "uuid": str(data.get("id") or ""),
        "alterId": int(data.get("aid") or 0),
        "vmessSecurity": str(data.get("scy") or data.get("security") or "auto"),
        "network": str(data.get("net") or "tcp"),
        "wsPath": str(data.get("path") or ""),
        "wsHost": str(data.get("host") or ""),
        "grpcServiceName": str(data.get("serviceName") or ""),
        "security": str(data.get("tls") or "none"),
        "sni": str(data.get("sni") or ""),
        "alpn": str(data.get("alpn") or ""),
        "fingerprint": str(data.get("fp") or ""),
        "realityPublicKey": str(data.get("pbk") or ""),
        "realityShortId": str(data.get("sid") or ""),
        "flow": str(data.get("flow") or ""),
    }
    return _clean_profile(p)


def parse_vless(link):
    rest, name = _split_name(link[len("vless://"):])
    m = re.match(r"^([^@]+)@([^:/?#]+):(\d+)(?:/([^?#]*))?(?:\?([^#]*))?$", rest)
    if not m:
        return None
    q = _parse_query(m.group(5) or "")
    p = {
        "type": "vless",
        "remark": name,
        "server": m.group(2),
        "port": int(m.group(3)),
        "uuid": urllib.parse.unquote(m.group(1)),
        "flow": q.get("flow", ""),
        "vlessEncryption": q.get("encryption", "none"),
        "security": q.get("security", "none"),
        "sni": q.get("sni", ""),
        "alpn": q.get("alpn", ""),
        "fingerprint": q.get("fp", ""),
        "realityPublicKey": q.get("pbk", ""),
        "realityShortId": q.get("sid", ""),
        "network": q.get("type", "tcp"),
        "wsPath": q.get("path", ""),
        "wsHost": q.get("host", ""),
        "grpcServiceName": q.get("servicename", ""),
        "xhttpMode": q.get("mode", ""),
    }
    return _clean_profile(p)


def parse_trojan(link):
    rest, name = _split_name(link[len("trojan://"):])
    m = re.match(r"^([^@]+)@([^:/?#]+):(\d+)(?:\?([^#]*))?$", rest)
    if not m:
        return None
    q = _parse_query(m.group(4) or "")
    p = {
        "type": "trojan",
        "remark": name,
        "server": m.group(2),
        "port": int(m.group(3)),
        "password": urllib.parse.unquote(m.group(1)),
        "security": "tls",
        "sni": q.get("sni", ""),
        "alpn": q.get("alpn", ""),
        "fingerprint": q.get("fp", ""),
        "network": q.get("type", "tcp"),
        "wsPath": q.get("path", ""),
        "wsHost": q.get("host", ""),
        "grpcServiceName": q.get("servicename", ""),
    }
    return _clean_profile(p)


def parse_ss(link):
    rest, name = _split_name(link[len("ss://"):])
    if "@" not in rest:
        try:
            rest = _b64d(rest).decode("utf-8")
        except Exception:
            return None
    if "@" not in rest:
        return None
    userinfo, _, hostport = rest.rpartition("@")
    try:
        userinfo = _b64d(userinfo).decode("utf-8")
    except Exception:
        pass
    if ":" not in userinfo:
        return None
    method, _, password = userinfo.partition(":")
    m = re.match(r"^([^:]+):(\d+)(?:/.*)?$", hostport)
    if not m:
        return None
    p = {
        "type": "shadowsocks",
        "remark": name,
        "server": m.group(1),
        "port": int(m.group(2)),
        "method": method,
        "password": urllib.parse.unquote(password),
    }
    return _clean_profile(p)


def parse_hy2(link):
    scheme = "hysteria2://" if link.startswith("hysteria2://") \
        else "hy2://"
    rest, name = _split_name(link[len(scheme):])
    m = re.match(r"^([^@]+)@([^:/?#]+):(\d+)(?:\?([^#]*))?$", rest)
    if not m:
        return None
    q = _parse_query(m.group(4) or "")
    p = {
        "type": "hysteria2",
        "remark": name,
        "server": m.group(2),
        "port": int(m.group(3)),
        "password": urllib.parse.unquote(m.group(1)),
        "sni": q.get("sni", ""),
        "alpn": q.get("alpn", ""),
        "obfs": q.get("obfs", ""),
        "obfsPassword": q.get("obfs-password", ""),
        "congestionControl": q.get("cc", ""),
    }
    return _clean_profile(p)


def parse_socks(link):
    rest, name = _split_name(link[len("socks://"):])
    m = re.match(r"^(?:([^@]+)@)?([^:/?#]+):(\d+)$", rest)
    if not m:
        return None
    username = password = ""
    if m.group(1):
        u = urllib.parse.unquote(m.group(1))
        username, _, password = u.partition(":")
    p = {
        "type": "socks",
        "remark": name,
        "server": m.group(2),
        "port": int(m.group(3)),
        "username": username,
        "password": password,
    }
    return _clean_profile(p)


def parse_tuic(link):
    rest, name = _split_name(link[len("tuic://"):])
    m = re.match(r"^([^:]+):([^@]+)@([^:/?#]+):(\d+)(?:\?([^#]*))?$", rest)
    if not m:
        return None
    q = _parse_query(m.group(5) or "")
    p = {
        "type": "tuic",
        "remark": name,
        "server": m.group(3),
        "port": int(m.group(4)),
        "uuid": urllib.parse.unquote(m.group(1)),
        "password": urllib.parse.unquote(m.group(2)),
        "sni": q.get("sni", ""),
        "alpn": q.get("alpn", ""),
        "congestionControl": q.get("congestion_control", ""),
    }
    return _clean_profile(p)


LINK_PARSERS = (
    ("vmess://", parse_vmess),
    ("vless://", parse_vless),
    ("trojan://", parse_trojan),
    ("ss://", parse_ss),
    ("hysteria2://", parse_hy2),
    ("hy2://", parse_hy2),
    ("tuic://", parse_tuic),
    ("socks://", parse_socks),
    ("socks5://", parse_socks),
)


def parse_link(line):
    line = line.strip()
    low = line.lower()
    for prefix, fn in LINK_PARSERS:
        if low.startswith(prefix):
            return fn(line)
    return None


def _clean_profile(p):
    p.setdefault("uuid", "")
    p.setdefault("username", "")
    p.setdefault("password", "")
    p.setdefault("method", "")
    p.setdefault("network", "tcp")
    p.setdefault("security", "none")
    p.setdefault("sni", "")
    p.setdefault("wsPath", "")
    p.setdefault("wsHost", "")
    p.setdefault("grpcServiceName", "")
    p.setdefault("realityPublicKey", "")
    p.setdefault("realityShortId", "")
    p = {k: v for k, v in p.items() if v not in ("", None)}
    p.setdefault("remark", "")
    if not p.get("server") or not p.get("port"):
        return None
    return p


# ---------------------------------------------------------------- Clash YAML


def parse_clash_yaml(text):
    """Igual que SubscriptionContent.parseClashYamlResult (subset YAML)."""
    text = text.replace("\ufeff", "")
    m = re.search(r"(?im)^[ \t]*proxies[ \t]*:", text)
    if not m:
        return [], 0
    body = text[m.end():]
    m2 = re.search(r"(?im)^[ \t]*proxy-groups[ \t]*:", body)
    if m2:
        body = body[:m2.start()]
    entries = []
    current = None
    for line in body.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            if current is not None:
                entries.append(current)
            current = {}
            rest = s[1:].strip()
            if rest.startswith("{") and rest.endswith("}"):
                _parse_inline_yaml(rest, current)
            elif ":" in rest:
                k, _, v = rest.partition(":")
                current[k.strip().lower()] = _yaml_value(v.strip())
        elif current is not None and ":" in s:
            k, _, v = s.partition(":")
            current[k.strip().lower()] = _yaml_value(v.strip())
    if current is not None:
        entries.append(current)
    profiles = []
    failures = 0
    for entry in entries:
        p = _clash_entry_to_profile(entry)
        if p is None:
            failures += 1
        else:
            profiles.append(p)
    return profiles, failures


def _yaml_value(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _parse_inline_yaml(s, out):
    inner = s[1:-1]
    for part in inner.split(","):
        if ":" not in part:
            continue
        k, _, v = part.partition(":")
        out[k.strip().lower()] = _yaml_value(v.strip())


def _clash_entry_to_profile(entry):
    t = (entry.get("type") or "").lower()
    type_map = {"vmess": "vmess", "vless": "vless", "trojan": "trojan",
                "ss": "shadowsocks", "shadowsocks": "shadowsocks",
                "hysteria2": "hysteria2", "hy2": "hysteria2"}
    ptype = type_map.get(t)
    if ptype is None:
        return None
    name = entry.get("name") or ""
    server = entry.get("server") or ""
    try:
        port = int(str(entry.get("port") or 0))
    except ValueError:
        return None
    if not name or not server or not port:
        return None
    if not re.match(r"^[A-Za-z0-9.\-_:\[\]]+$", server):
        return None
    uuid = entry.get("uuid") or entry.get("password") or ""
    password = entry.get("password") or ""
    if ptype == "hysteria2":
        password = (entry.get("password") or entry.get("auth") or
                    entry.get("auth-str") or entry.get("auth_str") or "")
    cipher = entry.get("cipher")
    if cipher is None:
        cipher = "aes-256-gcm" if ptype == "shadowsocks" else "none"
    sni = entry.get("sni") or entry.get("servername") or ""
    network = (entry.get("network") or "tcp").lower()
    ws_path = entry.get("ws-path") or entry.get("path") or "/"
    ws_host = entry.get("ws-headers") or sni
    tls = str(entry.get("tls") or "").lower()
    security = "tls" if (tls in ("true", "1") or sni) else "none"
    p = {
        "type": ptype, "remark": name, "server": server, "port": port,
        "uuid": uuid, "password": password, "method": cipher,
        "network": network, "wsPath": ws_path, "wsHost": ws_host,
        "security": security, "sni": sni,
    }
    return _clean_profile(p)


# ---------------------------------------------------------------- body parse


def strip_comments(text):
    out = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def decode_if_base64(text):
    """Igual que SubscriptionContent.decodeIfBase64."""
    s = text.replace("\ufeff", "")
    for line in s.splitlines():
        if "://" in line:
            return s
    compact = "".join(s.split())
    if not compact:
        return s
    try:
        raw = base64.b64decode(
            compact.replace("-", "+").replace("_", "/")
            + "=" * ((4 - len(compact) % 4) % 4))
        return raw.decode("utf-8")
    except Exception:
        return s


def stable_key(profile):
    """Igual que SubscriptionContent.stableKey (SHA-256 hex)."""
    parts = [
        (profile.get("type") or ""),
        (profile.get("server") or "").lower(),
        str(profile.get("port") or ""),
        profile.get("uuid") or "",
        profile.get("username") or "",
        profile.get("password") or "",
        (profile.get("method") or "").lower(),
        (profile.get("network") or "").lower(),
        (profile.get("security") or "").lower(),
        (profile.get("sni") or "").lower(),
        (profile.get("wsHost") or "").lower(),
        profile.get("wsPath") or "",
        profile.get("grpcServiceName") or "",
        profile.get("realityPublicKey") or "",
        profile.get("realityShortId") or "",
    ]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def name_uuid_from_bytes(data):
    """Igual que UUID.nameUUIDFromBytes (MD5, versión 3)."""
    digest = bytearray(hashlib.md5(data).digest())
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))


def parse_subscription_body(body, subscription_id="subscription",
                            url=None):
    """Igual que SubscriptionContent.parse (sin la parte de red)."""
    stripped = strip_comments(decode_if_base64(strip_comments(body)))
    profiles = []
    failures = 0
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        p = parse_link(line)
        if p is None:
            failures += 1
        else:
            profiles.append(p)
    if not profiles:
        failures = 0
        for text in (body, stripped):
            sub_profiles, sub_failures = parse_clash_yaml(text)
            failures += sub_failures
            if sub_profiles:
                profiles = sub_profiles
                break
    seen = set()
    out = []
    for p in profiles:
        key = stable_key(p)
        if key in seen:
            continue
        seen.add(key)
        pid = name_uuid_from_bytes(
            ("%s:%s" % (subscription_id, key)).encode("utf-8"))
        p = dict(p)
        p["id"] = pid
        p["sourceKey"] = key
        p["sourceKind"] = "subscription"
        p["subscriptionId"] = subscription_id
        out.append(p)
    return out, failures


def metadata_texts(body):
    """Igual que SubscriptionContent.metadataTexts."""
    return [body, decode_if_base64(strip_comments(body))]


def decode(body, url=None, headers=None, subscription_id="subscription"):
    """Entrada estilo SP-DECODE: cuerpo de suscripción -> dict JSON."""
    profiles, failures = parse_subscription_body(
        body, subscription_id=subscription_id, url=url)
    directives = parse_provider_directives(metadata_texts(body))
    userinfo = None
    if headers:
        userinfo = extract_userinfo(
            {k.lower(): [v] for k, v in headers.items()})
    return {
        "url": url,
        "subscriptionId": subscription_id,
        "profiles": profiles,
        "failures": failures,
        "userinfo": userinfo,
        "provider": directives.get("provider"),
        "newUrl": directives.get("newUrl"),
        "newDomain": directives.get("newDomain"),
    }


def run(url=None, data=None, output=None, hwid=None, device_model=None,
        os_version=None):
    if url is not None:
        body, userinfo, final_url, headers = fetch(
            url, hwid=hwid, device_model=device_model, os_version=os_version)
        result = decode(body, url=final_url, headers=headers)
        result["userinfo"] = userinfo or result.get("userinfo")
        result["fetchedUrl"] = url
    elif data is not None:
        result = decode(data)
    else:
        raise ValueError("Falta --url o un archivo con el cuerpo.")
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    return result


# ---------------------------------------------------------------- CLI / self-test


def _self_test():
    ok = total = 0

    def check(name, cond):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        else:
            print("FAIL:", name)

    # 1. Lista de enlaces en Base64 + directivas + userinfo
    vmess = {"v": "2", "ps": "VM-1", "add": "vm.example.com",
             "port": "443", "id": "11111111-2222-3333-4444-555555555555",
             "aid": "0", "scy": "auto", "net": "ws", "type": "none",
             "host": "cdn.example.com", "path": "/ws", "tls": "tls",
             "sni": "vm.example.com", "alpn": "h2", "fp": "chrome"}
    vless = ("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@vl.example.com"
             ":443?encryption=none&security=tls&sni=vl.example.com"
             "&fp=chrome&type=ws&path=%2Fvless&host=vl.example.com#VL-1")
    trojan = ("trojan://secreto@tj.example.com:443?sni=tj.example.com"
              "&alpn=h2#TJ-1")
    ss = ("ss://YWVzLTI1Ni1nY206Y2xhdmU=@ss.example.com:8388#SS-1")
    hy2 = "hy2://clave@hy.example.com:443?sni=hy.example.com#HY-1"
    lines = [
        "vmess://" + base64.b64encode(
            json.dumps(vmess).encode()).decode(),
        vless, trojan, ss, hy2,
    ]
    body_b64 = base64.b64encode("\n".join(lines).encode()).decode()
    body = ("# profile-title: Prueba SNI\n"
            "# profile-web-page-url: https://example.com/panel\n"
            "# announce: Hola suscriptor\n" + body_b64)
    res = decode(body)
    check("b64: 5 perfiles", len(res["profiles"]) == 5)
    types = sorted(p["type"] for p in res["profiles"])
    check("b64: tipos", types == ["hysteria2", "shadowsocks", "trojan",
                                   "vless", "vmess"])
    check("b64: vmess server", any(
        p["type"] == "vmess" and p["server"] == "vm.example.com"
        and p["wsPath"] == "/ws" for p in res["profiles"]))
    check("b64: vless uuid", any(
        p["type"] == "vless" and
        p["uuid"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        for p in res["profiles"]))
    check("b64: provider title", res["provider"] and
          res["provider"].get("title") == "Prueba SNI")
    check("b64: provider webpage", res["provider"] and
          res["provider"].get("webPageUrl") == "https://example.com/panel")
    check("b64: provider announce", res["provider"] and
          res["provider"].get("announce") == "Hola suscriptor")
    check("b64: dedup id estable", len({p["id"] for p in res["profiles"]}) == 5
          and all(p["id"] for p in res["profiles"]))
    # el mismo cuerpo sin Base64 exterior también abre
    res2 = decode("\n".join(lines))
    check("plano: 5 perfiles", len(res2["profiles"]) == 5)
    # dedup: la misma línea dos veces = 1 perfil
    res3 = decode(lines[1] + "\n" + lines[1])
    check("dedup", len(res3["profiles"]) == 1)

    # 2. Clash YAML
    clash = """
port: 7890
proxies:
  - name: "CL-1"
    type: vmess
    server: cl.example.com
    port: 443
    uuid: 22222222-3333-4444-5555-666666666666
    alterId: 0
    cipher: auto
    tls: true
    servername: cl.example.com
    network: ws
    ws-path: /clash
    ws-headers:
      Host: cl.example.com
  - {name: CL-2, type: trojan, server: tj2.example.com, port: 443, password: pw2, sni: tj2.example.com}
  - name: MALO
    type: socks
    server: x.example.com
    port: 1080
proxy-groups:
  - name: PROXY
    type: select
"""
    res4 = decode(clash)
    check("clash: 2 perfiles", len(res4["profiles"]) == 2)
    check("clash: vmess", any(
        p["type"] == "vmess" and p["server"] == "cl.example.com"
        and p["wsPath"] == "/clash" for p in res4["profiles"]))
    check("clash: trojan inline", any(
        p["type"] == "trojan" and p["server"] == "tj2.example.com"
        for p in res4["profiles"]))

    # 3. userinfo
    ui = parse_userinfo(
        "upload=123; download=456; total=10737418240; expire=1893456000")
    check("userinfo", ui == {"upload": 123, "download": 456,
                             "total": 10737418240,
                             "expire": 1893456000000})
    ui2 = parse_userinfo("total=10GB; unused=2GB")
    check("userinfo total-unused", ui2 and ui2.get("download") == 8 * 1024**3)
    ui3 = parse_userinfo("upload=1.5KB; download=2MB")
    check("userinfo sufijos", ui3 and ui3.get("upload") == 1536
          and ui3.get("download") == 2 * 1024 * 1024)
    check("userinfo fecha", parse_userinfo("expire=2027-01-15") and
          parse_userinfo("expire=2027-01-15")["expire"] == 1799971200000)

    # 4. require_https
    for bad in ("http://example.com/sub", "https://user:pass@example.com/x",
                "https://", "ftp://example.com/x"):
        try:
            require_https(bad)
            check("require_https rechaza " + bad, False)
        except ValueError:
            check("require_https rechaza " + bad, True)
    check("require_https acepta", require_https(
        "https://example.com/sub") == "https://example.com/sub")

    # 5. directivas: base64: y límites
    d = parse_provider_directives([
        "# profile-title: " + "X" * 40 + "\n"
        "# support-url: https://example.com/soporte\n"
        "# profile-update-interval: 9999\n"
        "# subscriptions-sort-type: ping\n"
        "# new-domain: SUB.EXAMPLE.COM\n"
        "# new-url: http://example.com/nuevo\n"])
    check("directivas title 25", d["provider"]["title"] == "X" * 25)
    check("directivas interval 720", d["provider"]["updateIntervalHours"] == 720)
    check("directivas sort", d["provider"]["sortType"] == "ping")
    check("directivas domain", d["newDomain"] == "sub.example.com")
    check("directivas new-url http rechazado", d["newUrl"] is None)
    d2 = parse_provider_directives([
        "# profile-title: base64:" + base64.b64encode(
            "Título B64".encode()).decode() + "\n"])
    check("directivas base64:", d2["provider"]["title"] == "Título B64")

    # 6. stableKey / UUID v3
    p = {"type": "vless", "server": "VL.EXAMPLE.COM", "port": 443,
         "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "username": "",
         "password": "", "method": "", "network": "ws",
         "security": "tls", "sni": "vl.example.com", "wsHost": "",
         "wsPath": "/vless", "grpcServiceName": "",
         "realityPublicKey": "", "realityShortId": ""}
    k1 = stable_key(p)
    p2 = dict(p, server="vl.example.com")
    check("stableKey minúsculas", stable_key(p2) == k1)
    check("stableKey hex", len(k1) == 64)
    u = name_uuid_from_bytes(b"subscription:" + k1.encode())
    check("uuid v3", re.match(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-3[0-9a-f]{3}-[89ab][0-9a-f]{3}-"
        r"[0-9a-f]{12}$", u) is not None)

    # 7. errores limpios
    for bad in ("", "basura sin enlaces ni yaml", "####\n####\n"):
        r = decode(bad)
        check("vacío/basura -> 0 perfiles", len(r["profiles"]) == 0)
    print("SELF-TEST %d/%d" % (ok, total))
    return ok == total


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        description="SNI Tunnel 1.3.0: descarga y parsea una suscripción "
                    "exactamente como la app.")
    ap.add_argument("--url", nargs="?", const="", help="URL de suscripción")
    ap.add_argument("--hwid", help="HWID del dispositivo (UUID); si no "
                    "se da, se genera uno aleatorio por ejecución")
    ap.add_argument("--device-model", default="Android Device")
    ap.add_argument("--os-version", default="14")
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("-o", "--output")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("file", nargs="?")
    args = ap.parse_args(argv)
    if args.self_test:
        sys.exit(0 if _self_test() else 1)
    if args.url is not None:
        result = run(url=args.url, output=args.output, hwid=args.hwid,
                     device_model=args.device_model,
                     os_version=args.os_version)
    elif args.stdin:
        result = run(data=sys.stdin.read(), output=args.output)
    elif args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            result = run(data=f.read(), output=args.output)
    else:
        ap.print_help()
        sys.exit(2)
    if not args.output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        n = len(result["profiles"])
        print("OK: %d perfiles, %d fallos, url=%s"
              % (n, result["failures"], result.get("url")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
