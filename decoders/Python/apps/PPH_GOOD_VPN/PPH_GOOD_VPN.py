#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PPH GOOD VPN — catalogo de servidores (SP-DECODE)
==================================================
App: PPH GOOD VPN, com.skphvpn.mm, 1.7.2 / versionCode 75 (APKPure arm64-v8a).
Desarrollador: PPHDEV (Paing Paing Hein / pphdev).

Catalogo en vivo
----------------
GET https://raw.githubusercontent.com/chitsuma/pvpn2022/refs/heads/main/pvpn_up.json
Sin headers especiales: la app lo descarga con OkHttp 4.12.0 (clase C0166ei,
peticion Lo(5) = GET sin headers personalizados) y el servidor GitHub raw no
exige ninguno. User-Agent que envia la app: "okhttp/4.12.0".

La respuesta es una sola linea Base64. Es el sobre XXTEA de c_01.decryptMain
(clave principal, DELTA 0x2E0BA747, palabra de longitud al final, como en
XxTea.java de esta app y de la familia RoVPN/E-SAN/Siam/V2OVPN).
El JSON resultante tiene "FileName", "Version", "ReleaseNotes", "Servers"
(lista) y "HTTPNetworks" (lista). La app compara "Version" con la guardada
en la preferencia HRL_CONFIG_VERSION (defecto "0") y, si es mayor, muestra
el dialogo de actualizacion y guarda Servers/HTTPNetworks en su SQLite
(tabla Harlies_table / getServerData/getNetworkData); el catalogo NO se
guarda como archivo.

Campos cifrados dentro del JSON (clave secundaria XXTEA, la misma de
ConfigUtil/c_01.decrypt para los valores guardados):
  Servidores : ServerIP, ServerCloudFront, ServerHTTP, ProxyHost,
               sUdpObfs (contrasena obfs de Hysteria), Username, Password,
               ovpnCertificate (config OpenVPN del servidor)
  Redes      : NetworkPayload, SquidProxy, SSLSNI
  Nivel sup. : Ovpn_Cert (config OpenVPN, en el vivo; vacio en el incluido),
               ghUsername, ghRepoName, ghFilename, config_url.
  Los campos cortos en claro (TcpPort, ProxyPort, FLAG, etc.) NO se
  tocan: un valor corto en claro puede descodificar por casualidad
  con Base64+XXTEA y dar basura, asi que solo se descifran los campos
  de la lista de arriba, cuyo descifrado da texto valido y coherente
  en el vivo y en el incluido.

Limpieza del JSON de resultado (regla 2026-11-15): el JSON que escribe
el script NO lleva las APIs de descarga del catalogo. config_url,
ghUsername, ghRepoName y ghFilename son la URL de descarga y sus
coordenadas descompuestas (usuario/repo/archivo de GitHub) y se
ELIMINAN de la salida de decrypt_catalog_fields. Se quedan: WebUrl
(guia de la app, no es descarga), PremiumKey (verificacion premium),
Messenger/Facebook/Telegram, los IDs de anuncios, credenciales de
servidores, payloads, SNI, hosts, puertos y certificados: son datos
del catalogo, no APIs. Un valor que no abre con la clave secundaria
se deja tal cual (no se inventa su contenido).

Tipos de servidor (campo "serverType"):
  0 = OpenVPN/SSL (SSLPort 443), 1 = SSH (TcpPort 22),
  3 = Carrier/Game (sin IP directa; el usuario activa antes un paquete
      de datos con el codigo USSD de "Server_msg"),
  4 = UDP Hysteria (sUdpObfs, Server_msg ".../udpserver/online_app").

Catalogo incluido (assets/pphdev.json): Version 2.0, 60 servidores,
14 redes (11 con payload).
Catalogo en vivo verificado 2026-11-14: Version 6.6 ("pvpn_upall"),
15 servidores (5 Hysteria + 5 OVPN + 5 SSH, todos *.pphdevgoodvpn.shop),
7 redes, las 7 con payload.

Uso:
  PPH_GOOD_VPN.py --url            descarga y descifra el catalogo en vivo
  PPH_GOOD_VPN.py --file RAW       descifra un catalogo crudo (base64)
  PPH_GOOD_VPN.py --json DEC       lee un JSON ya descifrado
  PPH_GOOD_VPN.py --decrypted OUT  escribe el JSON con los campos descifrados
  PPH_GOOD_VPN.py --self-test      pruebas offline (sin red)

Python stdlib puro. Sin credenciales fuera de las constantes de formato
que la propia app incluye (claves XXTEA de c_01/XxTea).
"""
import argparse
import base64
import json
import struct
import sys
import urllib.request

LIVE_URL = "https://raw.githubusercontent.com/chitsuma/pvpn2022/refs/heads/main/pvpn_up.json"
USER_AGENT = "okhttp/4.12.0"
# Claves XXTEA de c_01.java (StringFog): decryptMain/encryptMain y decrypt/encrypt.
MAIN_KEY = b"pvpnfreevimlbbpubg2026"
FIELD_KEY = b"9488362782103982762188"
DELTA = 0x2E0BA747
MASK = 0xFFFFFFFF

SERVER_TYPES = {
    "0": "OpenVPN/SSL",
    "1": "SSH",
    "3": "Carrier/Game",
    "4": "UDP Hysteria",
}

# Campos cifrados con la clave secundaria (ver docstring del modulo).
SERVER_FIELD_KEYS = ("ServerIP", "ServerCloudFront", "ServerHTTP",
                     "ProxyHost", "sUdpObfs", "Username", "Password",
                     "ovpnCertificate")
NETWORK_FIELD_KEYS = ("NetworkPayload", "SquidProxy", "SSLSNI")
TOP_FIELD_KEYS = ("Ovpn_Cert",)
# APIs de descarga del catalogo: se ELIMINAN del JSON de resultado
# (regla 2026-11-15). No se descifran para la salida, solo se quitan.
DOWNLOAD_API_KEYS = ("config_url", "ghUsername", "ghRepoName", "ghFilename")
# Compatibilidad: todos los campos descifrables con la clave secundaria.
FIELD_KEYS = (SERVER_FIELD_KEYS + NETWORK_FIELD_KEYS + TOP_FIELD_KEYS
              + DOWNLOAD_API_KEYS)


def _mx(z, y, s, p, e, k):
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ \
        ((s ^ y) + (k[(p & 3) ^ e] ^ z))


def _fix_key(key):
    if len(key) < 16:
        return key + b"\0" * (16 - len(key))
    return key[:16]


def xxtea_decrypt(data, key):
    """XXTEA como XxTea.java: toIntArray(data, false) + longitud al final."""
    if not data:
        return b""
    kk = struct.unpack("<4I", _fix_key(key))
    n = (len(data) + 3) // 4
    v = list(struct.unpack("<%dI" % n, data + b"\0" * (n * 4 - len(data))))
    if n < 2:
        return data
    rounds = (52 // n) + 6
    s = (rounds * DELTA) & MASK
    y = v[0]
    while s:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = (v[p] - _mx(z, y, s, p, e, kk)) & MASK
            v[p] = y
        z = v[n - 1]
        y = (v[0] - _mx(z, y, s, 0, e, kk)) & MASK
        v[0] = y
        s = (s - DELTA) & MASK
    m = v[-1]
    if m < (n - 1) * 4 - 7 or m > (n - 1) * 4:
        return None
    return struct.pack("<%dI" % (n - 1), *v[:n - 1])[:m]


def xxtea_encrypt(data, key):
    """Inversa de xxtea_decrypt (XxTea.encrypt, toIntArray(data, true))."""
    kk = struct.unpack("<4I", _fix_key(key))
    n = (len(data) + 3) // 4
    v = list(struct.unpack("<%dI" % n, data + b"\0" * (n * 4 - len(data))))
    v.append(len(data))
    n = len(v)
    rounds = (52 // n) + 6
    s = 0
    z = v[n - 1]
    for _ in range(rounds):
        s = (s + DELTA) & MASK
        e = (s >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            z = (v[p] + _mx(z, y, s, p, e, kk)) & MASK
            v[p] = z
    return struct.pack("<%dI" % n, *v)


def decrypt_envelope(raw_b64):
    """Base64 -> XXTEA (clave principal) -> bytes JSON. None si no abre."""
    try:
        raw = base64.b64decode(raw_b64.strip())
    except Exception:
        return None
    return xxtea_decrypt(raw, MAIN_KEY)


def decrypt_field(value):
    """Un campo cifrado con la clave secundaria. Devuelve str o None."""
    if value is None or value == "":
        return value
    try:
        out = xxtea_decrypt(base64.b64decode(value), FIELD_KEY)
    except Exception:
        return None
    if out is None:
        return None
    return out.decode("utf-8", "replace")


def decrypt_catalog_fields(cat):
    """Copia del catalogo con los campos cifrados abiertos y LIMPIO.

    Descifra los campos de FIELD_KEYS con la clave secundaria y ELIMINA
    las APIs de descarga del catalogo (config_url, ghUsername, ghRepoName,
    ghFilename; regla 2026-11-15). Un valor que no abre se deja tal cual:
    nunca se sustituye por None ni se inventa su contenido.
    """
    import copy
    cat = copy.deepcopy(cat)
    for key in TOP_FIELD_KEYS:
        if cat.get(key):
            dec = decrypt_field(cat[key])
            if dec is not None:
                cat[key] = dec
    for srv in cat.get("Servers", []):
        for key in SERVER_FIELD_KEYS:
            if srv.get(key):
                dec = decrypt_field(srv[key])
                if dec is not None:
                    srv[key] = dec
    for net in cat.get("HTTPNetworks", []):
        for key in NETWORK_FIELD_KEYS:
            if net.get(key):
                dec = decrypt_field(net[key])
                if dec is not None:
                    net[key] = dec
    for key in DOWNLOAD_API_KEYS:
        cat.pop(key, None)
    return cat


def fetch_live(url=LIVE_URL):
    """GET exactamente como la app: OkHttp 4.12.0, sin headers extra."""
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, resp.read()


def summarize(cat):
    servers = cat.get("Servers", [])
    nets = cat.get("HTTPNetworks", [])
    by_type = {}
    for srv in servers:
        t = SERVER_TYPES.get(str(srv.get("serverType", "?")),
                             "tipo %s" % srv.get("serverType"))
        by_type[t] = by_type.get(t, 0) + 1
    with_payload = sum(1 for n in nets if n.get("NetworkPayload"))
    return {
        "FileName": cat.get("FileName"),
        "Version": cat.get("Version"),
        "servers": len(servers),
        "servers_by_type": by_type,
        "networks": len(nets),
        "networks_with_payload": with_payload,
        "flags": sorted({str(s.get("FLAG", "")) for s in servers if s.get("FLAG")}),
        "network_flags": sorted({str(n.get("FLAG", "")) for n in nets if n.get("FLAG")}),
    }


def load_catalog(args):
    """Devuelve (catalogo_descifrado, origen)."""
    if args.url:
        status, body = fetch_live(args.url)
        if status != 200:
            print("HTTP %s al descargar %s" % (status, args.url), file=sys.stderr)
            return None, "live HTTP %s" % status
        plain = decrypt_envelope(body)
        if plain is None:
            print("LIVE_DECRYPT_FAILED: el cuerpo no abre con la clave principal",
                  file=sys.stderr)
            return None, "live decrypt failed"
        return json.loads(plain.decode("utf-8")), "live %s" % args.url
    if args.file:
        with open(args.file, "rb") as fh:
            data = fh.read()
        plain = decrypt_envelope(data)
        if plain is None:
            print("DECRYPT_FAILED: %s no abre con la clave principal" % args.file,
                  file=sys.stderr)
            return None, "file decrypt failed"
        return json.loads(plain.decode("utf-8")), "file %s" % args.file
    if args.json:
        with open(args.json, "r", encoding="utf-8") as fh:
            return json.load(fh), "json %s" % args.json
    return None, "sin entrada"


def self_test():
    ok = True
    total = [0]
    passed = [0]

    def check(name, cond):
        nonlocal ok
        total[0] += 1
        passed[0] += bool(cond)
        print(("OK  " if cond else "FAIL") + " " + name)
        ok = ok and bool(cond)

    # 1. Round-trip XXTEA con ambas claves.
    for key, name in ((MAIN_KEY, "principal"), (FIELD_KEY, "secundaria")):
        msg = b"PPH GOOD VPN 1.7.2"
        check("xxtea round-trip (%s)" % name,
              xxtea_decrypt(xxtea_encrypt(msg, key), key) == msg)
    # 2. El sobre incluido (assets/pphdev.json) abre y es la v2.0 con 60/14.
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(here, "catalog_sample_bundled.json")
    if os.path.exists(bundled):
        with open(bundled, "rb") as fh:
            plain = decrypt_envelope(fh.read())
        check("sobre incluido abre", plain is not None)
        if plain is not None:
            cat = json.loads(plain.decode("utf-8"))
            check("sobre incluido Version == 2.0", cat.get("Version") == "2.0")
            check("sobre incluido 60 servidores", len(cat.get("Servers", [])) == 60)
            check("sobre incluido 14 redes", len(cat.get("HTTPNetworks", [])) == 14)
            dec = decrypt_catalog_fields(cat)
            check("campo ServerIP abre",
                  dec["Servers"][0].get("ServerIP") == "pphfree1.mvpnpvpn.de5.net")
            check("campo NetworkPayload abre",
                  dec["HTTPNetworks"][0].get("NetworkPayload", "").startswith("{"))
            check("campo ProxyHost abre",
                  dec["Servers"][10].get("ProxyHost") == "pphfree1.mvpnpvpn.de5.net")
            check("campo sUdpObfs abre",
                  dec["Servers"][0].get("sUdpObfs") == "prysqxgs")
            check("campo SSLSNI abre",
                  dec["HTTPNetworks"][10].get("SSLSNI") == "www.speedtest.net")
            check("salida limpia sin config_url",
                  "config_url" not in dec)
            check("salida limpia sin ghUsername/ghRepoName/ghFilename",
                  not any(k in dec for k in
                          ("ghUsername", "ghRepoName", "ghFilename")))
    else:
        print("SKIP sobre incluido (falta catalog_sample_bundled.json)")
    # 3. La muestra en vivo guardada abre y es la v6.6 con 15/7.
    live = os.path.join(here, "catalog_sample.b64")
    if os.path.exists(live):
        with open(live, "rb") as fh:
            plain = decrypt_envelope(fh.read())
        check("muestra en vivo abre", plain is not None)
        if plain is not None:
            cat = json.loads(plain.decode("utf-8"))
            check("muestra en vivo Version == 6.6", cat.get("Version") == "6.6")
            check("muestra en vivo 15 servidores", len(cat.get("Servers", [])) == 15)
            check("muestra en vivo 7 redes", len(cat.get("HTTPNetworks", [])) == 7)
            dec = decrypt_catalog_fields(cat)
            check("campo live ServerIP abre",
                  dec["Servers"][0].get("ServerIP") == "thfree1.pphdevgoodvpn.shop")
            check("campo live ProxyHost abre",
                  dec["Servers"][5].get("ProxyHost") == "thfree1.pphdevgoodvpn.shop")
            check("campo live sUdpObfs abre",
                  dec["Servers"][0].get("sUdpObfs") == "sskghyxgs")
            check("campo live Ovpn_Cert abre",
                  (dec.get("Ovpn_Cert") or "").startswith("client\n"))
            check("salida limpia sin config_url",
                  "config_url" not in dec)
            check("salida limpia sin ghUsername/ghRepoName/ghFilename",
                  not any(k in dec for k in
                          ("ghUsername", "ghRepoName", "ghFilename")))
            check("config_url cruda abre con clave secundaria",
                  (decrypt_field(cat.get("config_url")) or "").startswith(
                      "https://raw.githubusercontent.com/"))
    else:
        print("SKIP muestra en vivo (falta catalog_sample.b64)")
    # 4. Una clave incorrecta NO abre el sobre (no hay falsos positivos).
    if os.path.exists(live):
        with open(live, "rb") as fh:
            raw = base64.b64decode(fh.read().strip())
        check("clave incorrecta no abre", xxtea_decrypt(raw, b"clave-falsa-0000") is None)
    print("SELF-TEST: %s (%d/%d)" % ("OK" if ok else "FALLO",
                                      passed[0], total[0]))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Catalogo de PPH GOOD VPN")
    ap.add_argument("--url", nargs="?", const=LIVE_URL,
                    help="descargar el catalogo en vivo (URL por defecto)")
    ap.add_argument("--file", help="catalogo crudo (base64) en disco")
    ap.add_argument("--json", help="catalogo ya descifrado (JSON)")
    ap.add_argument("--decrypted", help="escribir el JSON limpio con campos "
                    "descifrados (sin APIs de descarga)")
    ap.add_argument("--raw-json", action="store_true",
                    help="imprimir el JSON tal cual (sin descifrar campos)")
    ap.add_argument("--self-test", action="store_true", help="pruebas offline")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not (args.url or args.file or args.json):
        ap.print_help()
        return 2

    cat, origin = load_catalog(args)
    if cat is None:
        return 1
    print("origen: %s" % origin)
    print(json.dumps(summarize(cat), indent=2, ensure_ascii=False))
    if args.decrypted:
        dec = decrypt_catalog_fields(cat)
        with open(args.decrypted, "w", encoding="utf-8") as fh:
            json.dump(dec, fh, indent=2, ensure_ascii=False)
        print("JSON limpio (campos descifrados, sin APIs de descarga) en: %s"
              % args.decrypted)
    elif args.raw_json:
        print(json.dumps(cat, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
