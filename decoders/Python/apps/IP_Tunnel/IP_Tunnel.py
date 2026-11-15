#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Tunnel — decodificador del catálogo para SP-DECODE.

App: IP Tunnel, com.iptunnel.tunnel, 1.4.8-alpha (versionCode 49).
Método verificado en el APK (jadx 1.5.3 + strings ofuscadas resueltas con
el descifrador od2/nd2) y probado EN VIVO contra el servidor.

Catálogo (app_config)
---------------------
GET https://iptunnel.internetshub.com/api/v2/index.php?action=app_config

Cabeceras exactas que envía la app (clase d71; la firma HMAC solo se usa
en el modo legacy_v1, el modo por defecto es session_v2 y NO lleva firma):
    User-Agent: Dalvik/2.1.0 (Linux; U; Android 14; ...)   (HttpURLConnection;
        sin un UA Dalvik, Cloudflare responde 403 "error code: 1010")
    X-App-Id: iptunnel-android
    X-App-Device: MD5(android_id) en 32 hex (w91.f); sin un dispositivo real
        se usa un id fabricado: MD5 de 16 bytes aleatorios en hex.
    X-App-Ts: segundos unix actuales
    X-App-Nonce: %016x de un aleatorio de 63 bits
    X-App-Auth-Mode: session_v2
    X-App-Version: 49
    X-App-Session: SOLO si la app ya tiene sesión (token Play Integrity,
        endpoint app_attest; no se puede obtener offline, y el endpoint
        app_config responde 200 sin él, verificado en vivo).

Respuesta: cuerpo = un blob Base64 (una sola línea) = cifrado XXTEA
(variante yy.l/yy.o, delta 0x9A7393B4 — la misma que AR PRO) del JSON del
catálogo, con clave = primeros 16 bytes UTF-8 de vc.z:
    8f3c7a1e6d2b4c9f0a5e1d7c3b8f6a2e9c4d1f7b0a3e6c2d5f8a1b9c7e4d2a6
El JSON tiene: Version, Message, Servers[], Tweaks[], AdsSettings,
TimerSettings. Cada servidor trae SSH/SSL/Proxy, credenciales, y los
enlaces Vmess / Vless / Trojan / Hysteria + UDPCertificate (config
OpenVPN completa del cliente).

El catálogo incluido en el APK (vc.y) es solo un marcador ("UPDATE APP",
Version 1.00, 1 servidor, 1 tweak); el catálogo real es el remoto.

Resultado en vivo (2026-11-13, --url):
    Version 1.91, Message "OTA Update to keep IP Tunnel Optimised."
    3 servidores (INDIA, UNITED STATES, USE WITH ORANGE TWEAK),
    366 tweaks, 151 con Payload no vacío.
    Sin marca free/premium (AccessTier vacío en los 3).

Uso:
    python3 IP_Tunnel.py --url [--device-id <md5-32hex>] [-o salida.json] [--summary]
    python3 IP_Tunnel.py --file catalogo.b64 [-o salida.json]
    python3 IP_Tunnel.py --asset        # catálogo incluido en el APK (v1.00)
    python3 IP_Tunnel.py --self-test

Solo stdlib de Python 3. No se sube nada a ningún servidor.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

APP_CONFIG_URL = (
    "https://iptunnel.internetshub.com/api/v2/index.php?action=app_config"
)
# vc.z (defpackage/vc): clave del catálogo; se usan sus primeros 16 bytes UTF-8.
CATALOG_KEY = (
    "8f3c7a1e6d2b4c9f0a5e1d7c3b8f6a2e9c4d1f7b0a3e6c2d5f8a1b9c7e4d2a6"
)
APP_ID = "iptunnel-android"
APP_VERSION = "49"
# UA Dalvik como el que envía HttpURLConnection en Android; sin él,
# Cloudflare bloquea con 403 "error code: 1010".
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Build/UQ1A.240105.004)"

_HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED_CONFIG = os.path.join(_HERE, "bundled_config.b64")
LIVE_SAMPLE = os.path.join(_HERE, "catalog_sample.b64")

DELTA = 0x9A7393B4
MASK = 0xFFFFFFFF


# ---------------------------------------------------------------- XXTEA
def _to_ints(data, include_length):
    n = len(data)
    length = (n >> 2) if (n & 3) == 0 else (n >> 2) + 1
    if include_length:
        v = [0] * (length + 1)
        v[length] = n
    else:
        v = [0] * length
    for i in range(n):
        v[i >> 2] |= (data[i] & 0xFF) << ((i & 3) << 3)
    return v


def _to_bytes(v, include_length):
    length = len(v) << 2
    if include_length:
        n = v[-1]
        if n < length - 7 or n > length - 4:
            return None
        length = n
    out = bytearray(length)
    for i in range(length):
        out[i] = (v[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def _mx(sum_, y, z, p, k, e):
    return (
        (((sum_ ^ y) + ((k[(p & 3) ^ e] ^ z) & MASK)) & MASK)
        ^ ((((z >> 5) ^ ((y << 2) & MASK)) + ((y >> 3) ^ ((z << 4) & MASK))) & MASK)
    )


def xxtea_decrypt(data, key16):
    """yy.l: XXTEA descifrado, delta 0x9A7393B4. key16 = 16 bytes."""
    if len(data) == 0:
        return data
    v = _to_ints(data, False)
    k = _to_ints(key16, False)
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    sum_ = (rounds * DELTA) & MASK
    y = v[0]
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = (v[p] - _mx(sum_, y, z, p, k, e)) & MASK
            v[p] = y
        z = v[n - 1]
        y = (v[0] - _mx(sum_, y, z, 0, k, e)) & MASK
        v[0] = y
        sum_ = (sum_ - DELTA) & MASK
    return _to_bytes(v, True)


def xxtea_encrypt(data, key16):
    """yy.o: XXTEA cifrado, inverso exacto de xxtea_decrypt."""
    if len(data) == 0:
        return data
    v = _to_ints(data, True)
    k = _to_ints(key16, False)
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    sum_ = 0
    z = v[n - 1]
    for _ in range(rounds):
        sum_ = (sum_ + DELTA) & MASK
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = (v[p] + _mx(sum_, y, z, p, k, e)) & MASK
            v[p] = z
        y = v[0]
        z = (v[n - 1] + _mx(sum_, y, z, n - 1, k, e)) & MASK
        v[n - 1] = z
    return _to_bytes(v, False)


def _key_bytes(keystr):
    key = keystr.encode("utf-8")
    if len(key) != 16:
        key = (key + b"\x00" * 16)[:16]
    return key


def yy_m(b64str, keystr=CATALOG_KEY):
    """yy.m: Base64 -> XXTEA -> texto UTF-8. None si no abre."""
    try:
        data = base64.b64decode("".join(b64str.split()))
    except Exception:
        return None
    pt = xxtea_decrypt(data, _key_bytes(keystr))
    if pt is None:
        return None
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        return None


def yy_p(text, keystr):
    """yy.p: texto UTF-8 -> XXTEA -> Base64 (exportación de la app)."""
    ct = xxtea_encrypt(text.encode("utf-8"), _key_bytes(keystr))
    if ct is None:
        return None
    return base64.b64encode(ct).decode("ascii")


# ---------------------------------------------------------------- catálogo
def decode_blob(blob):
    """Descifra un blob de catálogo (Base64 XXTEA) y devuelve el dict JSON."""
    text = yy_m(blob)
    if text is None:
        raise ValueError("DECODE_FAILED: el blob no abre con la clave del catálogo")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("JSON_INVALIDO tras descifrar: %s" % exc)


def make_device_id():
    """w91.f con un android_id fabricado: MD5 de 16 bytes aleatorios en hex."""
    return hashlib.md5(os.urandom(16).hex().encode()).hexdigest()


def fetch_catalog(url=APP_CONFIG_URL, device_id=None, timeout=25, tries=3):
    """GET app_config exactamente como la app (d71.d). Devuelve el blob crudo.

    Sin X-App-Session (no hay token offline) y sin X-App-Sign (el modo
    session_v2 no firma). Reintenta si el cuerpo no descifra (descarga
    truncada); el servidor no acepta Range.
    """
    device_id = device_id or make_device_id()
    last_err = None
    for attempt in range(1, tries + 1):
        ts = int(time.time())
        nonce = "%016x" % random.getrandbits(63)
        headers = {
            "User-Agent": USER_AGENT,
            "X-App-Id": APP_ID,
            "X-App-Device": device_id,
            "X-App-Ts": str(ts),
            "X-App-Nonce": nonce,
            "X-App-Auth-Mode": "session_v2",
            "X-App-Version": APP_VERSION,
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="strict")
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode("utf-8", errors="replace")
            raise RuntimeError(
                "HTTP %s en app_config: %s" % (exc.code, detail.strip())
            )
        except Exception as exc:  # noqa: BLE001 - reintento de red
            last_err = exc
            if attempt < tries:
                time.sleep(1)
                continue
            raise RuntimeError("Error de red en app_config: %s" % exc)
        # Validar que el cuerpo descifra antes de aceptarlo.
        try:
            decode_blob(body)
        except ValueError:
            last_err = ValueError("cuerpo truncado o no descifrable")
            if attempt < tries:
                time.sleep(1)
                continue
            raise RuntimeError(
                "app_config respondió pero el blob no descifra tras %d intentos"
                % tries
            )
        return body
    raise RuntimeError("fetch fallido: %s" % last_err)


def summarize(cat):
    """Resumen legible del catálogo (sin volcar credenciales)."""
    servers = cat.get("Servers", []) or []
    tweaks = cat.get("Tweaks", []) or []
    lines = [
        "Version: %s" % cat.get("Version"),
        "Message: %s" % (cat.get("Message") or ""),
        "Servidores: %d" % len(servers),
    ]
    for s in servers:
        lines.append(
            "  - %s [%s] SSH %s:%s SSL %s Proxy %s:%s Vmess=%s Vless=%s Trojan=%s"
            % (
                s.get("Name"),
                s.get("Flag"),
                s.get("SSHHost"),
                s.get("SSHPort"),
                s.get("SSLPort"),
                s.get("ProxyHost"),
                s.get("ProxyPort"),
                bool(s.get("Vmess")),
                bool(s.get("Vless")),
                bool(s.get("Trojan")),
            )
        )
    with_payload = sum(1 for t in tweaks if (t.get("Payload") or "").strip())
    lines.append(
        "Tweaks: %d (%d con Payload no vacío)" % (len(tweaks), with_payload)
    )
    types = Counter(t.get("Type") for t in tweaks)
    lines.append(
        "Tipos de tweak: %s"
        % ", ".join("%s:%d" % kv for kv in sorted(types.items()))
    )
    return "\n".join(lines)


def decode_blob_text(text):
    """Acepta blob crudo o JSON ya descifrado (por conveniencia)."""
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    return decode_blob(text)


# ---------------------------------------------------------------- CLI
def _read_input(args):
    if args.stdin:
        return sys.stdin.read()
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            return fh.read()
    if args.asset:
        with open(BUNDLED_CONFIG, "r", encoding="utf-8") as fh:
            return fh.read()
    return None


def self_test():
    ok = 0
    fails = []

    def check(name, cond):
        nonlocal ok
        if cond:
            ok += 1
            print("  OK   %s" % name)
        else:
            fails.append(name)
            print("  FAIL %s" % name)

    print("IP Tunnel --self-test")
    # 1. Catálogo incluido en el APK (vc.y): Version 1.00, 1 servidor, 1 tweak.
    with open(BUNDLED_CONFIG, "r", encoding="utf-8") as fh:
        bundled = decode_blob(fh.read())
    check("bundled Version 1.00", bundled.get("Version") == "1.00")
    check("bundled 1 servidor", len(bundled.get("Servers", [])) == 1)
    check("bundled 1 tweak", len(bundled.get("Tweaks", [])) == 1)
    # 2. Muestra viva guardada: Version 1.91, 3 servidores, 366 tweaks.
    with open(LIVE_SAMPLE, "r", encoding="utf-8") as fh:
        live = decode_blob(fh.read())
    check("live Version 1.91", live.get("Version") == "1.91")
    check("live 3 servidores", len(live.get("Servers", [])) == 3)
    check("live 366 tweaks", len(live.get("Tweaks", [])) == 366)
    check(
        "live 151 tweaks con Payload",
        sum(1 for t in live["Tweaks"] if (t.get("Payload") or "").strip()) == 151,
    )
    # 3. Round-trip XXTEA + re-cifrado byte a byte (vc.y y muestra viva).
    with open(BUNDLED_CONFIG, "r", encoding="utf-8") as fh:
        blob_b = fh.read().strip()
    pt = yy_m(blob_b)
    check(
        "re-cifrado bundled == original",
        base64.b64encode(xxtea_encrypt(pt.encode("utf-8"), _key_bytes(CATALOG_KEY))).decode()
        == blob_b,
    )
    with open(LIVE_SAMPLE, "r", encoding="utf-8") as fh:
        blob_l = fh.read().strip()
    pt_l = yy_m(blob_l)
    check(
        "re-cifrado live == original",
        base64.b64encode(xxtea_encrypt(pt_l.encode("utf-8"), _key_bytes(CATALOG_KEY))).decode()
        == blob_l,
    )
    # 4. Formato de exportación (clave "@Adedayo's WeTunnel") round-trip.
    sample = json.dumps({"PSInstall": False, "Server": "none"}, separators=(",", ":"))
    blob_e = yy_p(sample, "@Adedayo's WeTunnel")
    check("export round-trip", yy_m(blob_e, "@Adedayo's WeTunnel") == sample)
    print("%d/%d checks OK" % (ok, ok + len(fails)))
    return 0 if not fails else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decodificador del catálogo de IP Tunnel (com.iptunnel.tunnel 1.4.8-alpha)."
    )
    ap.add_argument("--url", nargs="?", const=APP_CONFIG_URL,
                    help="descarga el catálogo en vivo (URL opcional; por defecto app_config)")
    ap.add_argument("--file", help="blob de catálogo guardado (Base64 XXTEA)")
    ap.add_argument("--asset", action="store_true",
                    help="usa el catálogo incluido en el APK (bundled_config.b64, v1.00)")
    ap.add_argument("--stdin", action="store_true", help="lee el blob de stdin")
    ap.add_argument("--device-id", help="X-App-Device a enviar (MD5 32 hex); si no, se fabrica uno")
    ap.add_argument("-o", "--output", help="guarda el JSON descifrado en este archivo")
    ap.add_argument("--summary", action="store_true", help="muestra solo el resumen")
    ap.add_argument("--self-test", action="store_true", help="pruebas internas")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.url is not None:
        blob = fetch_catalog(args.url, device_id=args.device_id)
        cat = decode_blob(blob)
    else:
        text = _read_input(args)
        if text is None:
            ap.error("usa --url, --file, --asset o --stdin")
        cat = decode_blob_text(text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(cat, fh, ensure_ascii=False, indent=2)
        print("JSON guardado en %s" % args.output)
    if args.summary or args.output:
        print(summarize(cat))
    else:
        print(json.dumps(cat, ensure_ascii=False, indent=2))
    return 0


def decode():
    """Compatibilidad con el patrón SP-DECODE: decode() del catálogo en vivo."""
    return decode_blob(fetch_catalog())


def run():
    return main()


if __name__ == "__main__":
    sys.exit(main())
