#!/usr/bin/env python3
"""PNT VPN - decodificador del catalogo (v28Api.json -> v28Config).

App: PNT VPN, com.pntvpn.net, version 1.2.8 (versionCode 28), minSdk 23.
Version de Google Play (actualizada 8 nov 2026), verificada en el APK de
APKPure (XAPK 44.488.808 B, SHA-256
125d2aaf31be126bdd1da3fdc357b125417110403547a65b7aff9c8cde93f909).
Sin cobertura previa en el repo SP-DECODE (rama feat/nuevas-integraciones,
86 carpetas de apps, ninguna de PNT).

Metodo (verificado en vivo 2026-11-14):
  Etapa 1 - la app pide el indice con Volley JsonObjectRequest GET, sin
  cabeceras propias, a la URL que devuelve NativeSec.getApiUrl()
  (libnative-sec.so, emulada con Unicorn):
      GET https://raw.githubusercontent.com/sansoe2022/new_pntvpn/refs/heads/main/v28Api.json
    -> JSON: {"version": 32, "message": ..., "fileUrl": "<url del catalogo>",
              "messageWarning": ..., "title": ..., "link": <Play Store>,
              "website": "https://pntvpn.netlify.app/", "versionCode": 28}
    Si la version guardada es menor que "version", descarga el catalogo.
  Etapa 2 - la app descarga "fileUrl" con PRDownloader (GET plano, sin auth)
  a <filesDir>/SVPN/Config.json (si no existe, lee el asset pntvpn.json):
      GET https://raw.githubusercontent.com/sansoe2022/new_pntvpn/refs/heads/main/v28Config
    -> cuerpo: una linea Base64 estandar
    -> Base64 -> XXTEA (clase SVPNDex, DELTA fijo -772015605 = 0xD1FBFA0B,
       clave = NativeSec.getAesKey() = "pntvpn4455")
    -> JSON: {"FileName", "InterUnit", "RewardUnit", "premiumKey",
              "BannerUnit", "OpenAppUnit", "WebUrl", "ContactUrl",
              "FacebookUrl", "TelegramUrl", "BgUrl",
              "Servers": [...], "HTTPNetworks": [...], "SSLNetworks": [],
              "Ovpn_Cert": "<plantilla OpenVPN>"}
  Campos cifrados de cada servidor/red (FileUtils.showJson):
    Base64 -> XXTEA (clase XxTea, DELTA = NativeSec.getDelta() = 0x3B2959AF,
    clave = FileUtils.getPass() = primeros 4 caracteres de
    NativeSec.getAuthHash() = "5741")
    -> texto UTF-8 con caracteres portadores (rango U+2C00-U+2DFF)
    -> cada caracter -= 5741, dos veces (FileUtils._De aplica
       De2.decryptString dos veces; total -11482 por caracter)
    -> texto plano. Campos: ServerIP, ServerCloudFront, ServerHTTP, V2ray,
       SlowIP, PublicKey, Username, Password, NetworkPayload, SquidProxy,
       WSHost, Address, NetworkFrontQuery, NetworkBackQuery.
  Contador de usuarios en linea (ServerStatus/ServerCount, Volley
  StringRequest GET plano al campo "Info" de cada servidor):
      GET http://<host>:81/server/online_app
    -> {"onlines": "64", "limite": "2500"} (o un numero plano).

Valores nativos recuperados de libnative-sec.so (arm64, emulacion Unicorn
de los JNI: getApiUrl/getAesKey/getAuthHash/getDelta; el .so tambien
contiene las dos cadenas hex de 64 caracteres en .rodata que getDelta
usa para una comprobacion anti-manipulacion, no necesarias para decodificar):
    getApiUrl()  = la URL de v28Api.json de arriba
    getAesKey()  = "pntvpn4455"   (clave XXTEA del catalogo)
    getAuthHash()= "5741"         (clave XXTEA de los campos)
    getDelta()   = 0x3B2959AF     (DELTA de XxTea / campos)

Resultado en vivo (2026-11-14): API version 32, FileName "v28Config",
8 servidores, todos gratuitos (Category 0: 3 Singapore + 5 Thailand),
12 redes HTTP (9 con payload: 1 config JSON de Hysteria + 8 payloads
HTTP injector), 0 redes SSL. Servidores vless:// por WS en el puerto
8080; SSH en 22, SSL en 443, proxy en 8080. El asset incluido en el APK
(pntvpn.json, FileName "newConfig") abre con el mismo metodo: 8
servidores y 11 redes (le falta la red "Star Link" del vivo).
En linea verificado: Singapore - 1 tenia 64 usuarios de un limite de 300.

No hay formato propio de archivo de perfil ni esquema URI de texto:
el manifiesto solo declara MAIN/LAUNCHER (sin ACTION_VIEW ni esquemas);
la app importa enlaces estandar vmess/vless/trojan/ss por portapapeles
(como el fork de v2rayNG que es) y su unico "archivo" es el catalogo
mismo (SVPN/Config.json o el asset pntvpn.json), que abre --file.
No hay archivos .sks.

Solo Python estandar. Sin dependencias. El resumen NO imprime
credenciales de servidor (usuarios, contrasenas ni UUID de los enlaces
vless): decode() devuelve el JSON completo con los campos ya
descifrados para integrarlo en SP-DECODE; el resumen muestra solo
estructura (host, puertos, protocolo, tipo de red).

Uso:
    python3 PNT_VPN.py --url              # descarga API + catalogo en vivo
    python3 PNT_VPN.py --url <URL_API>    # otro indice con el mismo formato
    python3 PNT_VPN.py --config-url <URL> # catalogo directo, sin etapa 1
    python3 PNT_VPN.py --file <f>         # descifra un cuerpo guardado
                                           # (Config.json o pntvpn.json)
    python3 PNT_VPN.py --url --online     # incluye usuarios en linea
    python3 PNT_VPN.py --self-test        # pruebas (round-trip + muestras)
    python3 PNT_VPN.py --url -o out.json  # guarda el catalogo descifrado
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

API_URL = "https://raw.githubusercontent.com/sansoe2022/new_pntvpn/refs/heads/main/v28Api.json"
# Constantes del formato (ver docstring): la clave del catalogo es
# NativeSec.getAesKey(); la clave de los campos es FileUtils.getPass()
# (primeros 4 caracteres de NativeSec.getAuthHash()).
CATALOG_KEY = b"pntvpn4455"
FIELD_PASS = "5741"
FIELD_KEY = b"5741"
# SVPNDex.DELTA (fijo en la clase); XxTea usa NativeSec.getDelta().
DELTA_CATALOG = 0xD1FBFA0B
DELTA_FIELD = 0x3B2959AF
# La app usa Volley (etapa 1) y PRDownloader (etapa 2), ambos GET planos
# sin cabeceras propias; el User-Agent es el de HttpURLConnection en
# Android. GitHub raw responde igual con cualquier UA.
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Redmi 14C Build/UP1A.231005.007)"
TIMEOUT = 30
MAX_BYTES = 8 * 1024 * 1024

# Campos de servidor/red que van cifrados con FileUtils.showJson.
ENCRYPTED_FIELDS = (
    "ServerIP", "ServerCloudFront", "ServerHTTP", "V2ray", "SlowIP",
    "PublicKey", "Username", "Password", "NetworkPayload", "SquidProxy",
    "WSHost", "Address", "NetworkFrontQuery", "NetworkBackQuery",
)


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------ XXTEA
# XXTEA modificado, identico a SVPNDex/XxTea de la app: la ultima palabra
# guarda la longitud del texto plano; el delta es parametro (cada clase
# usa uno distinto). Núcleo verificado con round-trip.

def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _mx(total: int, y: int, z: int, p: int, e: int, k: list) -> int:
    a = _u32(((_u32(z >> 5) ^ _u32(y << 2)) + _u32(_u32(y >> 3) ^ _u32(z << 4))))
    b = _u32(_u32(total ^ y) + _u32(k[(p & 3) ^ e] ^ z))
    return _u32(a ^ b)


def _to_words(data: bytes, include_length: bool) -> list:
    n = (len(data) + 3) // 4
    words = list(__import__("struct").unpack("<%dI" % n, data + b"\x00" * (n * 4 - len(data))))
    if include_length:
        words.append(len(data))
    return words


def _from_words(words: list, use_length: bool):
    import struct
    total = len(words) << 2
    if use_length:
        length = words[-1]
        if length < total - 7 or length > total - 4:
            return None
        total = length
    out = struct.pack("<%dI" % len(words), *words)
    return out[:total]


def _fix_key(key: bytes) -> bytes:
    if len(key) == 16:
        return key
    if len(key) < 16:
        return key + b"\x00" * (16 - len(key))
    return key[:16]


def xxtea_encrypt(data: bytes, key: bytes, delta: int) -> bytes:
    import struct
    v = _to_words(data, True)
    k = list(struct.unpack("<4I", _fix_key(key)))
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    z = v[n - 1]
    for _ in range(rounds):
        total = _u32(total + delta)
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = _u32(v[p] + _mx(total, y, z, p, e, k))
            v[p] = z
        y = v[0]
        z = _u32(v[n - 1] + _mx(total, y, z, n - 1, e, k))
        v[n - 1] = z
    return struct.pack("<%dI" % n, *v)


def xxtea_decrypt(data: bytes, key: bytes, delta: int):
    import struct
    if not data:
        return b""
    v = _to_words(data, False)
    k = list(struct.unpack("<4I", _fix_key(key)))
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    total = _u32(rounds * delta)
    y = v[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = _u32(v[p] - _mx(total, y, z, p, e, k))
            v[p] = y
        z = v[n - 1]
        y = _u32(v[0] - _mx(total, y, z, 0, e, k))
        v[0] = y
        total = _u32(total - delta)
    return _from_words(v, True)


def _b64decode(text: str) -> bytes:
    """TeaBase64.decode de la app: Base64 estandar, ignora caracteres
    fuera del alfabeto y corta en el primer '='."""
    cleaned = "".join(ch for ch in text.strip() if ch in
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    cleaned = cleaned.split("=", 1)[0]
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned)


# ------------------------------------------------------- campos (showJson)
def show_json(value: str) -> str:
    """FileUtils.showJson: XXTEA (delta de campo, clave "5741") + cada
    caracter -= 5741 dos veces (De2.decryptString aplicado dos veces)."""
    if not value:
        return ""
    raw = xxtea_decrypt(_b64decode(value), FIELD_KEY, DELTA_FIELD)
    if raw is None:
        raise DecodeError("FIELD_XXTEA", "el campo no abre con XXTEA (clave 5741)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("FIELD_UTF8", "el campo descifrado no es UTF-8: %s" % exc)
    return "".join(chr(ord(ch) - 2 * 5741) for ch in text)


def hide_json(value: str) -> str:
    """FileUtils.hideJson (inverso de show_json, solo para --self-test):
    cada caracter += 5741 dos veces y XXTEA + Base64 con la clave "5741"."""
    shifted = "".join(chr(ord(ch) + 2 * 5741) for ch in value)
    blob = xxtea_encrypt(shifted.encode("utf-8"), FIELD_KEY, DELTA_FIELD)
    return base64.b64encode(blob).decode("ascii")


def decrypt_fields(catalog: dict) -> dict:
    """Devuelve una copia del catalogo con los campos cifrados ya
    descifrados en su sitio (los campos vacios quedan vacios; los que
    no abren quedan con el valor original y se marcan en _field_errors)."""
    out = json.loads(json.dumps(catalog))
    errors = {}
    for server in out.get("Servers", []) or []:
        if not isinstance(server, dict):
            continue
        for field in ENCRYPTED_FIELDS:
            value = server.get(field)
            if isinstance(value, str) and value:
                try:
                    server[field] = show_json(value)
                except DecodeError as exc:
                    errors.setdefault(server.get("Name", "?"), []).append(field + ":" + exc.code)
    for net in (out.get("HTTPNetworks", []) or []) + (out.get("SSLNetworks", []) or []):
        if not isinstance(net, dict):
            continue
        for field in ENCRYPTED_FIELDS:
            value = net.get(field)
            if isinstance(value, str) and value:
                try:
                    net[field] = show_json(value)
                except DecodeError as exc:
                    errors.setdefault(net.get("Name", "?"), []).append(field + ":" + exc.code)
    if errors:
        out["_field_errors"] = errors
    return out


# ---------------------------------------------------------------- catalogo
def decode(data) -> dict:
    """Descifra un cuerpo de catalogo (texto Base64 de Config.json o
    pntvpn.json) y devuelve el JSON. Es la misma operacion que
    SVPNDex.decryptBase64StringToString(cuerpo, getAesKey()) en la app."""
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8", "replace")
    else:
        text = str(data)
    text = text.strip()
    if not text:
        raise DecodeError("EMPTY", "cuerpo vacio")
    try:
        blob = _b64decode(text)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("BASE64", "el cuerpo no es Base64: %s" % exc)
    raw = xxtea_decrypt(blob, CATALOG_KEY, DELTA_CATALOG)
    if raw is None:
        raise DecodeError("XXTEA", "el catalogo no abre con XXTEA (delta 0xD1FBFA0B, clave pntvpn4455)")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("JSON", "el catalogo descifrado no es JSON: %s" % exc)


def _http_get(url: str, accept: str = "*/*") -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": accept,
    }, method="GET")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise DecodeError("TOO_LARGE", "respuesta mayor de %d bytes" % MAX_BYTES)
    return body


def fetch_api(api_url: str = API_URL) -> dict:
    """Etapa 1: GET al indice (Volley JsonObjectRequest en la app)."""
    try:
        body = _http_get(api_url, accept="application/json")
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("API_HTTP", "no se pudo descargar el indice %s: %s" % (api_url, exc))
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecodeError("API_JSON", "el indice no es JSON: %s" % exc)


def fetch_config(config_url: str) -> dict:
    """Etapa 2: GET al catalogo (PRDownloader en la app) + descifrado."""
    try:
        body = _http_get(config_url)
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("CONFIG_HTTP", "no se pudo descargar el catalogo %s: %s" % (config_url, exc))
    return decode(body.decode("utf-8", "replace"))


def fetch_online(info_url: str):
    """Contador de usuarios en linea (ServerCount.parseCount): el campo
    "Info" es una URL que devuelve {"onlines": "N", "limite": "M"} o un
    numero plano. Devuelve el entero o None si no se puede leer."""
    try:
        body = _http_get(info_url, accept="application/json").decode("utf-8", "replace")
    except Exception:
        return None
    text = body.strip().lstrip("\ufeff")
    try:
        if text.startswith("{"):
            value = json.loads(text).get("onlines", "")
        else:
            value = text
        value = str(value).strip()
        if value.isdigit():
            return int(value)
    except Exception:
        return None
    return None


def summarize(catalog: dict, api: dict | None = None, online: dict | None = None) -> str:
    """Resumen sin credenciales: no imprime usuarios, contrasenas ni
    UUID de enlaces vless (solo esquema/host/puerto/tipo)."""
    servers = catalog.get("Servers", []) or []
    http_nets = catalog.get("HTTPNetworks", []) or []
    ssl_nets = catalog.get("SSLNetworks", []) or []
    free = sum(1 for s in servers if isinstance(s, dict) and s.get("Category", 0) == 0)
    with_payload = 0
    lines = []
    if api is not None:
        lines.append("PNT VPN - catalogo en vivo")
        lines.append("  API version: %s (FileName: %s)" % (api.get("version"), catalog.get("FileName")))
    else:
        lines.append("PNT VPN - catalogo (FileName: %s)" % catalog.get("FileName"))
    lines.append("  Servidores: %d (%d gratuitos, Category 0)" % (len(servers), free))
    lines.append("  Redes: %d HTTP + %d SSL" % (len(http_nets), len(ssl_nets)))
    plain = decrypt_fields(catalog)
    for server in plain.get("Servers", []) or []:
        name = server.get("Name")
        host = server.get("ServerIP") or ""
        vless = server.get("V2ray") or ""
        vless_info = ""
        if vless:
            try:
                parsed = urllib.parse.urlparse(vless)
                query = urllib.parse.parse_qs(parsed.query)
                vless_info = " | vless %s:%s type=%s" % (
                    parsed.hostname, parsed.port, (query.get("type") or ["?"])[0])
            except Exception:
                vless_info = " | vless (sin analizar)"
        on = ""
        if online is not None:
            count = online.get(server.get("Info"))
            if count is not None:
                on = " | en linea: %s/%s" % (count, server.get("Limit"))
        lines.append("  - %s [%s] Cat=%s Limite=%s host=%s CF=%s HTTP=%s TCP=%s SSL=%s Proxy=%s%s%s" % (
            name, server.get("FLAG"), server.get("Category"), server.get("Limit"),
            host, server.get("ServerCloudFront"), server.get("ServerHTTP"),
            server.get("TcpPort"), server.get("SSLPort"), server.get("ProxyPort"),
            vless_info, on))
    for net in plain.get("HTTPNetworks", []) or []:
        payload = net.get("NetworkPayload") or ""
        if payload:
            with_payload += 1
        lines.append("  Red: %s [tipo=%s spType=%s payload=%d B squid=%s]" % (
            net.get("Name"), net.get("server_type"), net.get("serverSPType"),
            len(payload), net.get("SquidProxy") or "-"))
    lines.append("  Redes con payload: %d de %d" % (with_payload, len(http_nets)))
    if plain.get("_field_errors"):
        lines.append("  Campos que no abrieron: %s" % plain["_field_errors"])
    return "\n".join(lines)


# ------------------------------------------------------------------- CLI
def _self_test() -> int:
    failures = []

    def check(name, cond):
        print(("ok  " if cond else "FAIL") + " " + name)
        if not cond:
            failures.append(name)

    sample = {"FileName": "selftest", "Servers": [{"Name": "T-1", "Category": 0}],
              "HTTPNetworks": [], "SSLNetworks": []}
    plain = json.dumps(sample)
    blob = xxtea_encrypt(plain.encode("utf-8"), CATALOG_KEY, DELTA_CATALOG)
    encoded = base64.b64encode(blob).decode("ascii")
    check("catalogo XXTEA round-trip", decode(encoded) == sample)
    check("campo XXTEA round-trip",
          xxtea_decrypt(xxtea_encrypt(b"hola", FIELD_KEY, DELTA_FIELD),
                        FIELD_KEY, DELTA_FIELD) == b"hola")
    check("campo show/hide round-trip",
          show_json(hide_json("free6june.sksvpn.shop")) == "free6june.sksvpn.shop")
    check("campo show/hide round-trip (payload)",
          show_json(hide_json("GET / HTTP/1.1\r\nHost: [host]\r\n\r\n")) ==
          "GET / HTTP/1.1\r\nHost: [host]\r\n\r\n")
    check("campo vacio", show_json("") == "")

    here = Path(__file__).resolve().parent
    for sample_file, expected_name in (("catalog_sample.b64", "v28Config"),
                                       ("pntvpn.json", "newConfig")):
        path = here / sample_file
        if not path.exists():
            print("skip " + sample_file + " (no esta junto al script)")
            continue
        try:
            cat = decode(path.read_text(encoding="utf-8", errors="replace"))
            check("%s abre (FileName=%s, %d servidores)" % (
                sample_file, cat.get("FileName"), len(cat.get("Servers", []))),
                cat.get("FileName") == expected_name and len(cat.get("Servers", [])) == 8)
            plain_cat = decrypt_fields(cat)
            first = plain_cat["Servers"][0]
            check("%s: ServerIP descifrado" % sample_file,
                  isinstance(first.get("ServerIP"), str) and "." in first["ServerIP"])
            check("%s: V2ray descifrado" % sample_file,
                  isinstance(first.get("V2ray"), str) and first["V2ray"].startswith("vless://"))
        except DecodeError as exc:
            check(sample_file + " abre", False)
            print("     " + exc.code + ": " + str(exc))
    if failures:
        print("SELF-TEST: %d fallo(s): %s" % (len(failures), failures))
        return 1
    print("SELF-TEST: todo ok")
    return 0


def run(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", nargs="?", const=API_URL, default=None,
                        help="descarga el indice de la API y luego el catalogo "
                             "(por defecto: %s)" % API_URL)
    parser.add_argument("--config-url", default=None,
                        help="URL directa del catalogo (salta la etapa 1)")
    parser.add_argument("--file", type=Path, default=None,
                        help="descifra un cuerpo guardado (Config.json o "
                             "el asset pntvpn.json)")
    parser.add_argument("--online", action="store_true",
                        help="consulta los contadores de usuarios en linea")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="guarda el catalogo descifrado (con campos "
                             "descifrados) en JSON")
    parser.add_argument("--self-test", action="store_true",
                        help="pruebas locales (round-trip + muestras)")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    api = None
    catalog = None
    try:
        if args.file is not None:
            catalog = decode(args.file.read_text(encoding="utf-8", errors="replace"))
        elif args.config_url:
            catalog = fetch_config(args.config_url)
        elif args.url is not None:
            api = fetch_api(args.url)
            config_url = api.get("fileUrl")
            if not config_url:
                print("LIVE_API_SIN_FILEURL: el indice no trae fileUrl: %s" % api,
                      file=sys.stderr)
                return 2
            catalog = fetch_config(config_url)
        else:
            parser.error("usa --url, --config-url, --file o --self-test")
    except DecodeError as exc:
        print("%s: %s" % (exc.code, exc), file=sys.stderr)
        return 2

    online = None
    if args.online:
        online = {}
        for server in catalog.get("Servers", []) or []:
            info = server.get("Info")
            if isinstance(info, str) and info.startswith("http"):
                online[info] = fetch_online(info)
    print(summarize(catalog, api=api, online=online))
    if args.output is not None:
        args.output.write_text(
            json.dumps(decrypt_fields(catalog), ensure_ascii=False, indent=1),
            encoding="utf-8")
        print("Guardado en %s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
