#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMT VPN (com.rsphvpnofficial.v2) - catalogo en vivo para SP-DECODE.
Version de la app: 65-16kb-page-size (versionCode 65), arm64-v8a.

Catalogo en vivo
---------------
GET https://api.github.com/repos/johnberic/Panel_files/contents/fmt-vpn.json
Headers exactos de la app (thread/checkUpdate, OkHttp):
    User-Agent: Alexis-VPN-App
    Authorization: Bearer <token GitHub incrustado en libboyapper.so>
    Accept: application/vnd.github.v3.raw
La respuesta es el contenido crudo del archivo (Base64, 104128 caracteres).
Descifrado del catalogo (igual que AESHelper.decrypt de la app):
    1. Base64 -> bytes
    2. AES-256-CBC, clave = SHA-256("fmt1987"), IV = 16 bytes cero,
       padding PKCS#7 (modo AES/CBC/PKCS7Padding de la app)
    3. JSON con Version / Servers[] / Networks[] (+ Username, Password,
       Notes, color_type, contactSupport, config_url, account_api,
       AdvanceSettings)
Los campos sensibles del catalogo (ServerIPHost, ServerCloudFrontHost,
ServerHTTPHost, ServerUser, ServerPass, vaddress, vhost, etServerAddress,
etEndpoint, etPublicKey, etPrivateKey, etPreSharedKey, etAllowedIPs,
SNIHost, Payload, Squid, vsni) son a su vez Base64 del mismo
AES-256-CBC con la misma clave e IV, y su texto plano lleva una
sustitucion de caracteres: 25 caracteres CJK / hangul / kana sustituyen
letras y digitos ASCII (ver _UNOBFUSCATE).
La salida del script es el JSON de resultado limpio (clean_catalog):
todos los campos anteriores descifrados y desofuscados; config_url y
account_api NO se incluyen (son APIs de descarga/cuentas, regla
2026-11-15); no se emiten campos *_raw con el Base64 original; los
valores que no se pueden resolver (U+65E5 sin valor fijado, o un campo
que no abre con AES) se dejan tal cual y se avisan por stderr (ver
clean_catalog_report); el JSON de resultado lleva solo datos del
catalogo, sin metadatos del proceso.
La app tambien trae un catalogo incluido (fallback) en la libreria
nativa: Tk.getConfig() devuelve un blob Base64 que descifra con la
misma clave a un JSON v1.0 con 1 servidor y 1 red.

Kill-switch (no es el catalogo): la app consulta
https://pastebin.com/raw/LDEnpzU2 (JSON con lista de apps
deshabilitadas por el desarrollador RENZ). FMT VPN no esta en la lista.

Python stdlib puro (sin PyCryptodome): el AES-256 es implementacion
propia en Python puro, reutilizada del lote MNR. Descifrar el catalogo
en vivo (~78 KB) tarda ~4 s en este entorno.

Uso:
    python3 FMT_VPN.py --url            # descarga en vivo y muestra resumen
    python3 FMT_VPN.py --url --json-out catalog.json
    python3 FMT_VPN.py --raw catalog_raw.txt [--json-out catalog.json]
    python3 FMT_VPN.py --self-test      # vectores incluidos, sin red
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

APP_PACKAGE = "com.rsphvpnofficial.v2"
APP_VERSION = "65-16kb-page-size"
APP_VERSION_CODE = 65
CATALOG_URL = "https://api.github.com/repos/johnberic/Panel_files/contents/fmt-vpn.json"
CATALOG_UA = "Alexis-VPN-App"
# Token de GitHub de la propia app (libboyapper.so, Tk.getGitToken()).
# NUNCA en Git (AGENTS.md regla 4; el secret scanning de GitHub lo bloquea).
# Vive en SPDECODE_FMT_VPN_GITHUB_TOKEN, la misma variable que usa el
# secretHeader del registro (supplied-integrations.json). Las copias ZIP
# operativas conservan el token incrustado para uso local.
GITHUB_TOKEN = os.environ.get("SPDECODE_FMT_VPN_GITHUB_TOKEN", "")

# Clave del catalogo y de los campos: UtilsKey.getSecretKey() = "fmt1987".
# AESHelper.generateKey() = SHA-256 de la clave como UTF-8; IV = 16 ceros.
CATALOG_KEY = hashlib.sha256(b"fmt1987").digest()
ZERO_IV = b"\x00" * 16

# Sustitucion CJK -> ASCII de los campos del catalogo. Cada caracter
# CJK/hangul/kana sustituye UNA letra o digito ASCII. Verificada contra
# cientos de ocurrencias del catalogo en vivo (hosts, SNI, payloads HTTP,
# JSON de configuracion, IPs, UUIDs vless, config WireGuard).
# Pendiente: U+65E5 (日) aparece 5 veces y no se pudo fijar su valor
# (una clave publica WireGuard en Base64, un host Fastly y un host Squid);
# se deja pasar tal cual y se avisa por stderr (clean_catalog_report).
_UNOBFUSCATE = {
    "\u4e8c": "e",  # 二
    "\u4e3b": "h",  # 主
    "\u4e3a": "n",  # 为
    "\u7684": "o",  # 的
    "\u756b": "p",  # 畫
    "\u6ca1": "i",  # 沒
    "\u5c31": "l",  # 就
    "\ub463": "a",  # 둣
    "\ub528": "c",  # 딨
    "\ub56c": "d",  # 땬
    "\u5927": "1",  # 大
    "\u5973": "2",  # 女
    "\ub4e4": "7",  # 들
    "\u5929": "0",  # 天
    "\u5c71": "8",  # 山
    "\ub540": "9",  # 땀
    "\u4e2d": "6",  # 中
    "\u56fd": "m",  # 国
    "\ub538": "b",  # 딸
    "\u5c0f": "f",  # 小
    "\u5f53": "k",  # 当
    "\u4e0e": "g",  # 与
    "\ub4cc": "5",  # 듌
    "\ub4fd": "3",  # 듽
    "\u304f": "4",  # く
}
_UNOBFUSCATE_TABLE = str.maketrans(_UNOBFUSCATE)


def deobfuscate(text):
    """Quita la sustitucion CJK de un campo del catalogo."""
    if not text:
        return text
    return text.translate(_UNOBFUSCATE_TABLE)


def aes_decrypt_field(b64text):
    """Descifra un campo Base64 del catalogo y lo desofusca.

    Devuelve el texto plano (str). Lanza ValueError si no abre.
    """
    raw = base64.b64decode(b64text)
    pt = _pkcs7_unpad(_aes_cbc_decrypt(CATALOG_KEY, ZERO_IV, raw))
    return deobfuscate(pt.decode("utf-8"))


def decrypt_catalog_blob(blob_b64):
    """Descifra el blob Base64 del catalogo (crudo o de la API) a dict."""
    raw = base64.b64decode("".join(blob_b64.split()))
    pt = _pkcs7_unpad(_aes_cbc_decrypt(CATALOG_KEY, ZERO_IV, raw))
    return json.loads(pt.decode("utf-8"))


# Campos cifrados del catalogo (AES-256-CBC + sustitucion CJK).
_SERVER_FIELDS = ("ServerIPHost", "ServerCloudFrontHost", "ServerHTTPHost",
                  "ServerUser", "ServerPass",
                  "vaddress", "vhost",
                  "etServerAddress", "etEndpoint", "etPublicKey",
                  "etPrivateKey", "etPreSharedKey", "etAllowedIPs")
_NETWORK_FIELDS = ("SNIHost", "Payload", "Squid", "vsni")
# APIs del catalogo: NO van en el JSON de resultado (regla 2026-11-15).
_API_FIELDS = ("config_url", "account_api")


def _clean_catalog(cat):
    """Limpieza interna: devuelve (catalogo_limpio, [sin_resolver]).

    Todos los campos de _SERVER_FIELDS / _NETWORK_FIELDS se reemplazan
    por su texto plano desofuscado. El valor Base64 que cifra un campo
    vacio descifra a "" (marcador de campo vacio, no un valor real).
    Los campos de _API_FIELDS se eliminan: son APIs de descarga del
    catalogo / de cuentas, no datos del catalogo. No se emiten campos
    *_raw con el Base64 original (el blob crudo queda como evidencia
    en el archivo --raw-out / samples/catalog_raw.txt).
    Los valores que no se pueden resolver se dejan tal cual y se
    devuelven en la lista: un campo que no abre con AES, o un valor que
    aun contiene U+65E5 (日), cuyo valor ASCII no esta fijado. Nada se
    inventa. El JSON de resultado NO lleva la lista (solo datos del
    catalogo); quien la necesite usa clean_catalog_report().
    No toca Version / Names / puertos / flags / AdvanceSettings.
    """
    out = json.loads(json.dumps(cat, ensure_ascii=False))
    unresolved = []

    def _open(obj, path, name):
        value = obj.get(name)
        if not value:
            return
        try:
            plain = aes_decrypt_field(value)
        except Exception:
            unresolved.append(
                "%s: no abre con AES-256-CBC, se deja tal cual" % path)
            return
        obj[name] = plain
        if "\u65e5" in plain:
            unresolved.append(
                "%s: contiene U+65E5 (日) sin valor fijado" % path)

    for i, server in enumerate(out.get("Servers", [])):
        for name in _SERVER_FIELDS:
            _open(server, "Servers[%d].%s" % (i, name), name)
    for i, net in enumerate(out.get("Networks", [])):
        for name in _NETWORK_FIELDS:
            _open(net, "Networks[%d].%s" % (i, name), name)
    for name in _API_FIELDS:
        out.pop(name, None)
    return out, unresolved


def clean_catalog(cat):
    """Devuelve una copia del catalogo totalmente descifrada y limpia
    (solo datos del catalogo, sin metadatos del proceso)."""
    return _clean_catalog(cat)[0]


def clean_catalog_report(cat):
    """Como clean_catalog, pero devuelve (catalogo_limpio, [sin_resolver])
    para avisar por stderr de los valores que no se pudieron resolver."""
    return _clean_catalog(cat)


def deobfuscate_catalog(cat):
    """Alias historico de clean_catalog (misma salida limpia)."""
    return clean_catalog(cat)


def fetch_catalog_raw(url=CATALOG_URL, token=None, timeout=30):
    """Replica la peticion EXACTA de la app (checkUpdate / OkHttp).

    Devuelve el cuerpo crudo (el blob Base64 del archivo fmt-vpn.json).
    """
    token = token or GITHUB_TOKEN
    if not token:
        raise ValueError("Falta SPDECODE_FMT_VPN_GITHUB_TOKEN (token GitHub de la app, por entorno; nunca en Git)")
    req = urllib.request.Request(url)
    req.add_header("User-Agent", CATALOG_UA)
    req.add_header("Authorization", "Bearer " + token.strip())
    req.add_header("Accept", "application/vnd.github.v3.raw")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return body.decode("utf-8")


def summarize(cat):
    """Resumen legible del catalogo (version, servidores, redes)."""
    lines = []
    lines.append("FMT VPN %s (versionCode %d) - catalogo v%s" % (
        APP_VERSION, APP_VERSION_CODE, cat.get("Version")))
    servers = cat.get("Servers", [])
    nets = cat.get("Networks", [])
    lines.append("Servidores: %d   Redes: %d" % (len(servers), len(nets)))
    type_names = {0: "OpenVPN", 1: "SSH", 2: "OCS?", 3: "VLESS",
                  4: "UDP", 5: "OCS?", 7: "WireGuard"}
    for s in servers:
        host = (s.get("ServerIPHost", "") or "").replace("\n", " ")
        host = host if len(host) <= 90 else host[:87] + "..."
        lines.append("  [%s] %s (type %s, %s) host=%s" % (
            s.get("serverType"), s.get("Name"),
            s.get("serverType"),
            type_names.get(s.get("serverType"), "?"), host))
    with_payload = sum(1 for n in nets if n.get("Payload"))
    with_sni = sum(1 for n in nets if n.get("SNIHost"))
    lines.append("Redes con Payload: %d/%d   con SNI: %d/%d" % (
        with_payload, len(nets), with_sni, len(nets)))
    for n in nets[:12]:
        lines.append("  - %s (tunnel %s, %s)" % (
            n.get("Name"), n.get("TunnelType"), n.get("payload_type")))
    if len(nets) > 12:
        lines.append("  ... y %d mas" % (len(nets) - 12))
    return "\n".join(lines)


# --- self-test -------------------------------------------------------------
# Vector incluido: un JSON pequeno cifrado exactamente como lo hace la app
# (AES-256-CBC, clave SHA-256("fmt1987"), IV ceros, Base64). Su campo
# Host desofuscado debe ser ip1.minitun26.xyz.
_SELFTEST_B64 = (
    "89UQXVDC03NVxAA9cdY6o/8cdmDraOk3vVX/WxnATnaHCj8C2pAvbyXG5u5f2Drf"
    "TZaxo+wf52CZ2oqrPOhfb6W8Yi9oIMRRXjrc4kcSdqYmI4J+ngCM/2PCxwlYr2OJ"
)
_SELFTEST_HOST = "ip1.minitun26.xyz"


def self_test():
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, ok, detail))
        print(("OK  " if ok else "FAIL") + " " + name + (" - " + detail if detail else ""))
        return ok

    ok = True
    # 1. AES-256 contra vector verificado con PyCryptodome (clave 256 bits).
    nist_key = bytes.fromhex(
        "d3b169fdc1f1f91dfd43c7bab79ed47c2f98727f78a57bd26fb2ef36118076fd")
    nist_pt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nist_ct = bytes.fromhex("10358a77f21a5c335f9cfb2b926fabf6")
    got = _aes_encrypt_block(nist_key, nist_pt)
    ok &= check("AES-256 bloque (vector NIST)", got == nist_ct,
                got.hex() if got != nist_ct else "")
    got = _aes_decrypt_block(nist_key, nist_ct)
    ok &= check("AES-256 desbloqueo (vector NIST)", got == nist_pt)

    # 2. Cadena completa: Base64 -> AES -> JSON -> desofuscado.
    try:
        cat = decrypt_catalog_blob(_SELFTEST_B64)
        host = deobfuscate(cat["Host"])
        ok &= check("blob de prueba abre y desofusca",
                    host == _SELFTEST_HOST, "host=%s" % host)
        ok &= check("SNI de prueba intacto",
                    cat.get("SNI") == "m.youtube.com")
    except Exception as exc:  # noqa: BLE001
        ok &= check("blob de prueba abre y desofusca", False, str(exc))

    # 3. Sustitucion CJK en casos conocidos.
    ok &= check("CJK: server/host/port/https/HTTP/1.1",
                deobfuscate("s\u4e8crv\u4e8cr") == "server"
                and deobfuscate("\u4e3b\u7684st") == "host"
                and deobfuscate("\u756b\u7684rt") == "port"
                and deobfuscate("\u4e3btt\u756bs") == "https"
                and deobfuscate("HTTP/\u5927.\u5927") == "HTTP/1.1")
    ok &= check("CJK: 127.0.0.1:1080",
                deobfuscate("\u5927\u5973\ub4e4.\u5929.\u5929.\u5927:\u5927\u5929\u5c71\u5929")
                == "127.0.0.1:1080")
    ok &= check("CJK: vless sin tocar literales",
                deobfuscate("vless://x@167.82.49.91:80") == "vless://x@167.82.49.91:80")

    # 4. Clave derivada como la app (SHA-256 de "fmt1987").
    ok &= check("clave = SHA-256('fmt1987')",
                CATALOG_KEY == hashlib.sha256(b"fmt1987").digest())

    # 5. Segunda capa completa: TODOS los campos de servidor se abren.
    #    El marcador de campo vacio (AES de "") descifra a "".
    try:
        def _ct(text):
            return base64.b64encode(
                _aes_cbc_encrypt(CATALOG_KEY, ZERO_IV,
                                 text.encode("utf-8"))).decode("ascii")

        empty_ct = _ct("")
        mini = {"Version": "x",
                "Servers": [{"Name": "t",
                             "ServerIPHost": _ct("ip1.minitun26.xyz"),
                             "ServerUser": _ct("user1"),
                             "ServerPass": _ct("user1"),
                             "vaddress": empty_ct,
                             "vhost": empty_ct,
                             "etServerAddress": empty_ct,
                             "etEndpoint": empty_ct,
                             "etPublicKey": empty_ct,
                             "etPrivateKey": empty_ct,
                             "etPreSharedKey": empty_ct,
                             "etAllowedIPs": empty_ct}],
                "Networks": [{"Name": "n", "Squid": _ct("[Default]"),
                              "vsni": empty_ct}],
                "config_url": _ct("fmt-vpn.json"),
                "account_api": _ct("https://example.invalid/api")}
        clean = clean_catalog(mini)
        srv = clean["Servers"][0]
        ok &= check("campos v*/et* y ServerUser/Pass se abren",
                    srv["ServerIPHost"] == "ip1.minitun26.xyz"
                    and srv["ServerUser"] == "user1"
                    and srv["ServerPass"] == "user1"
                    and srv["vaddress"] == ""
                    and srv["etPublicKey"] == ""
                    and clean["Networks"][0]["Squid"] == "[Default]"
                    and clean["Networks"][0]["vsni"] == "")
        ok &= check("marcador de vacio cifra '' y descifra ''",
                    aes_decrypt_field(empty_ct) == "")
        ok &= check("limpieza: sin config_url/account_api ni *_raw",
                    "config_url" not in clean
                    and "account_api" not in clean
                    and not any(k.endswith("_raw")
                                for s in clean["Servers"]
                                for k in s)
                    and not any(k.endswith("_raw")
                                for n in clean["Networks"]
                                for k in n))
    except Exception as exc:  # noqa: BLE001
        ok &= check("campos v*/et* y ServerUser/Pass se abren", False, str(exc))
        ok &= check("marcador de vacio cifra '' y descifra ''", False, str(exc))
        ok &= check("limpieza: sin config_url/account_api ni *_raw", False, str(exc))

    # 6. U+65E5: se deja tal cual y se avisa por stderr, sin inventar
    # (el JSON de resultado no lleva metadatos: la lista sale por
    # clean_catalog_report, no en el JSON).
    try:
        def _ct2(text):
            return base64.b64encode(
                _aes_cbc_encrypt(CATALOG_KEY, ZERO_IV,
                                 text.encode("utf-8"))).decode("ascii")

        mini2 = {"Version": "x",
                 "Servers": [{"Name": "t",
                              "ServerIPHost": _ct2("G\u65e5test.example")}],
                 "Networks": []}
        clean2, unresolved2 = clean_catalog_report(mini2)
        ok &= check("U+65E5 se deja tal cual y se avisa (sin _unresolved en el JSON)",
                    clean2["Servers"][0]["ServerIPHost"] == "G\u65e5test.example"
                    and "_unresolved" not in clean2
                    and unresolved2 == [
                        "Servers[0].ServerIPHost: "
                        "contiene U+65E5 (\u65e5) sin valor fijado"])
    except Exception as exc:  # noqa: BLE001
        ok &= check("U+65E5 se deja tal cual y se avisa (sin _unresolved en el JSON)", False, str(exc))

    print()
    print("self-test: %d/%d checks OK" % (
        sum(1 for _, good, _ in checks if good), len(checks)))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="FMT VPN - descarga y abre el catalogo en vivo.")
    ap.add_argument("--url", action="store_true",
                    help="descargar el catalogo en vivo con la peticion exacta de la app")
    ap.add_argument("--raw", metavar="FILE",
                    help="leer el blob Base64 crudo desde un archivo local")
    ap.add_argument("--json-out", metavar="FILE",
                    help="guardar el catalogo descifrado (desofuscado) en JSON")
    ap.add_argument("--raw-out", metavar="FILE",
                    help="guardar el blob crudo descargado en un archivo")
    ap.add_argument("--self-test", action="store_true",
                    help="vectores incluidos, sin red")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.url:
        t0 = time.time()
        try:
            blob = fetch_catalog_raw()
        except urllib.error.HTTPError as exc:
            print("HTTP %s al descargar el catalogo" % exc.code, file=sys.stderr)
            return 2
        except Exception as exc:  # noqa: BLE001
            print("error al descargar el catalogo: %s" % exc, file=sys.stderr)
            return 2
        print("descargado: %d caracteres en %.1f s" % (len(blob), time.time() - t0),
              file=sys.stderr)
        if args.raw_out:
            with open(args.raw_out, "w", encoding="utf-8") as fh:
                fh.write(blob)
    elif args.raw:
        with open(args.raw, "r", encoding="utf-8") as fh:
            blob = fh.read()
    else:
        ap.error("usa --url para descargar en vivo o --raw FILE con un blob local")

    t0 = time.time()
    try:
        cat = decrypt_catalog_blob(blob)
    except Exception as exc:  # noqa: BLE001
        print("no abre el catalogo: %s" % exc, file=sys.stderr)
        return 3
    print("descifrado en %.1f s" % (time.time() - t0), file=sys.stderr)
    cat, unresolved = clean_catalog_report(cat)
    for item in unresolved:
        print("sin resolver: %s" % item, file=sys.stderr)
    print(summarize(cat))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(cat, fh, ensure_ascii=False, indent=1)
        print("guardado: %s" % args.json_out, file=sys.stderr)
    return 0



# --- AES-256 en Python puro (stdlib) ---
_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
)
_INV_SBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // nk - 1], _SBOX[t[2]],
                 _SBOX[t[3]], _SBOX[t[0]]]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_rk(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[4 * rnd + c][r]


def _sub(s, inv=False):
    box = _INV_SBOX if inv else _SBOX
    for i in range(16):
        s[i] = box[s[i]]


def _shift(s, inv=False):
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        sh = (4 - r) if inv else r
        row = row[sh:] + row[:sh]
        for c in range(4):
            s[4 * c + r] = row[c]


def _mix(s, inv=False):
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        if inv:
            s[4 * c + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            s[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            s[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            s[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
        else:
            s[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            s[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            s[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            s[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _aes_decrypt_block(key, block):
    w, nr = _key_expansion(key)
    return _aes_decrypt_block_w(w, nr, block)


def _aes_decrypt_block_w(w, nr, block):
    s = list(block)
    _add_rk(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _sub(s, True)
        _shift(s, True)
        _add_rk(s, w, rnd)
        _mix(s, True)
    _sub(s, True)
    _shift(s, True)
    _add_rk(s, w, 0)
    return bytes(s)


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("ciphertext length must be a multiple of 16")
    w, nr = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _aes_decrypt_block_w(w, nr, blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]



# ---------------------------------------------------------------- AES encrypt (para la vuelta completa)

def _pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _aes_encrypt_block(key, block):
    w, nr = _key_expansion(key)
    return _aes_encrypt_block_w(w, nr, block)


def _aes_encrypt_block_w(w, nr, block):
    s = list(block)
    _add_rk(s, w, 0)
    for rnd in range(1, nr):
        _sub(s)
        _shift(s)
        _mix(s)
        _add_rk(s, w, rnd)
    _sub(s)
    _shift(s)
    _add_rk(s, w, nr)
    return bytes(s)


def _aes_cbc_encrypt(key, iv, data):
    data = _pkcs7_pad(data)
    w, nr = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _aes_encrypt_block_w(w, nr, blk)
        out += prev
    return bytes(out)


# ---------------------------------------------------------------- cifrado de la app (F5/a y F5/g)


if __name__ == "__main__":
    raise SystemExit(main())
