#!/usr/bin/env python3
"""MSY VPN TUNNEL 11.4.1 (build 151) — decodificador para SP-DECODE.

Paquete (manifest): com.stunnel.dev — clases de app: com.msyvpn.lite.*
versionName 11.4.1, versionCode 151, minSdk 32, targetSdk 36.
App pura Java/Kotlin: un solo classes.dex, SIN librerias nativas (.so: 0
en base.apk y en los dos splits).

Metodo (reconstruido de com/msyvpn/lite/Security + ServerList + Configs
+ TunnelConfig$Companion, verificado en vivo):

  * Catalogo: GET http://servers.jk5.fun/servers.json
    (HttpURLConnection, timeouts de conexion y lectura de 6.000 ms,
    setUseCaches(false), sin headers propios; exige HTTP 200).
    Fallback de la app: socket TCP directo a cada IP de servidor
    conocido, primer puerto TCP de la lista (o 80):
      GET /servers.json HTTP/1.1\\r\\nHost: servers.jk5.fun\\r\\n
      Connection: close\\r\\n\\r\\n   (exige "HTTP/1.1 200" o "HTTP/1.0 200")
    La respuesta es un blob AES-GCM (ver decrypt_blob) -> JSON.
    SIN auth: el catalogo es publico. La API de cuenta
    (https://ws.jk5.fun, R$string.api_base, /v1/acc/*, /v1/cfg, /v1/msg)
    SI exige cuenta de dispositivo (Bearer <uid>.<secret>, secreto
    generado al registrarse y guardado en AndroidKeyStore); no se usa
    para el catalogo y no se puede probar sin un dispositivo registrado.
  * Blob: nonce de 12 B + AES-GCM(ciphertext + tag de 16 B).
    Clave: SHA-256("MSY_VPN_SECURITY_SALT_2026_@JuanitoProSniff")[:16]
    (Security.decryptBlob). Mismo blob para el asset res/raw/servers.bin
    (catalogo empaquetado, v57/11.4.0) y para los "blob" Base64 de la
    comunidad (/v1/cfg, Community.parse).
  * Esquema del catalogo (ServerList.parse, claves ofuscadas con
    fallback en claro): v_k7 (version) / version, a_v3 / app_version,
    a_vn / app_version_name, a_ur / app_url, a_mg / app_msg,
    s_nd / servers: [{x_i/id, x_n/name, x_c/country, x_h/host,
    x_a/ip, x_tp/tcp, x_up/udp, x_dn/dns, x_cd/cdn}],
    c_mx / configs: [{z_*...}] (ver parse_tunnel_config).
  * Configs (TunnelConfig): la app NO define esquema URI propio ni
    asocia extensiones de archivo (el manifest solo tiene
    MAIN/LAUNCHER). Importar/exportar es JSON por portapapeles
    (Configs.parseImport/export): {"configs": [...]} o un solo objeto.
    parse acepta claves ofuscadas z_* y en claro; export escribe en
    claro (toJson, indent 2, barras sin escapar).

Verificacion en vivo (2026-11-25):
  GET http://servers.jk5.fun/servers.json -> HTTP 200, 3.514 B,
  application/octet-stream -> descifra a JSON de 3.415 B,
  catalogo v64, app 151/11.4.1, 3 servidores, 18 configuraciones.
  El asset res/raw/servers.bin (3.827 B) tambien descifra (v57).

Uso:
  python3 msyvpn.py --download [--out catalog.enc]
  python3 msyvpn.py --decrypt <blob> [--out catalog.json]
  python3 msyvpn.py --parse-config <config.json> [--out out.json]
  python3 msyvpn.py --community-blob <base64>   (blob de /v1/cfg)
  python3 msyvpn.py --self-test
"""

import base64
import hashlib
import json
import re
import socket
import sys
import urllib.request
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:  # pycryptodome tambien se instala como Cryptodome
    from Cryptodome.Cipher import AES

# ---------------------------------------------------------------- constantes
SALT = "MSY_VPN_SECURITY_SALT_2026_@JuanitoProSniff"
CATALOG_URLS = ["http://servers.jk5.fun/servers.json"]
CATALOG_HOST = "servers.jk5.fun"
ACCOUNT_API_BASE = "https://ws.jk5.fun"  # solo documentado; exige cuenta
TIMEOUT = 6  # segundos, como la app (6000 ms)

TRANSPORTS = [
    "tcp", "payload", "proxy", "ssl", "ssl_payload", "hcr", "ssl_hcr",
    "udp", "dns", "ws", "ssl_ws", "icmp", "udpc", "fdns", "picmp",
    "ssl_turbo",
]
TRANSPORT_ALIAS = {"tls": "ssl", "bhttp": "hcr", "ssl_bhttp": "ssl_hcr"}

_KEY = hashlib.sha256(SALT.encode("utf-8")).digest()[:16]


# ------------------------------------------------------------------ cripto
def decrypt_blob(data: bytes) -> str:
    """Security.decryptBlob: nonce(12) || AES-GCM(ct+tag16), clave SHA-256(sal)[:16]."""
    if len(data) < 12 + 16:
        raise ValueError("blob demasiado corto (%d B)" % len(data))
    nonce, rest = data[:12], data[12:]
    cipher = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(rest[:-16], rest[-16:])
    return plain.decode("utf-8")


def encrypt_blob(text: str, nonce: bytes = None) -> bytes:
    """Inversa de decrypt_blob (solo para --self-test / fixtures)."""
    import os

    nonce = nonce if nonce is not None else os.urandom(12)
    cipher = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(text.encode("utf-8"))
    return nonce + ct + tag


def looks_like_json(data: bytes) -> bool:
    """Security.looksLikeJson: el texto descifrado debe parecer JSON."""
    return data.lstrip()[:1] in (b"{", b"[")


def decrypt_raw_data(data: bytes) -> str:
    """Security.decryptRawData: decryptBlob + exige JSON, si no 'Datos corruptos'."""
    text = decrypt_blob(data)
    if not looks_like_json(text.encode("utf-8")):
        raise ValueError("Datos corruptos")
    return text


def decrypt_community_blob(b64: str) -> dict:
    """Community.parse: blob Base64 -> decryptBlob -> JSON de TunnelConfig."""
    return json.loads(decrypt_blob(base64.b64decode(b64)))


# ------------------------------------------------------------------ red
def download_catalog_bytes(url: str, timeout: int = TIMEOUT) -> bytes:
    """ServerList.download: GET sin headers propios, timeout 6 s, exige 200."""
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise IOError("HTTP %d en %s" % (resp.status, url))
        return resp.read()


def download_direct(ip: str, port: int, host: str,
                    timeout: int = TIMEOUT) -> str:
    """ServerList.downloadDirect: socket TCP crudo, GET /servers.json."""
    req = ("GET /servers.json HTTP/1.1\r\nHost: %s\r\n"
           "Connection: close\r\n\r\n" % host).encode("ascii")
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(req)
        chunks = []
        while True:
            try:
                b = sock.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
    raw = b"".join(chunks)
    head_end = raw.find(b"\r\n\r\n")
    if head_end < 0:
        raise IOError("Respuesta HTTP inválida")
    head = raw[:head_end].decode("ascii", "replace")
    if not (head.startswith("HTTP/1.1 200") or head.startswith("HTTP/1.0 200")):
        raise IOError("HTTP no-200: %s" % head.splitlines()[0] if head else "?")
    return decrypt_raw_data(raw[head_end + 4:])


def fetch_catalog() -> str:
    """ServerList.refresh: URLs, y si fallan, descarga directa por IP."""
    errors = []
    for url in CATALOG_URLS:
        try:
            return decrypt_raw_data(download_catalog_bytes(url))
        except Exception as e:  # noqa: BLE001 - probar la siguiente via
            errors.append("%s: %s" % (url, e))
    # Fallback: el asset empaquetado trae las IPs conocidas; sin el, no hay IPs.
    bundled = Path(__file__).with_name("servers.bin")
    if bundled.exists():
        try:
            cat = parse_catalog(json.loads(decrypt_raw_data(bundled.read_bytes())))
            for srv in cat["servers"]:
                for port in (srv["tcp"][:1] or [80]):
                    try:
                        return download_direct(srv["ip"], port, CATALOG_HOST)
                    except Exception as e:  # noqa: BLE001
                        errors.append("%s:%s: %s" % (srv["ip"], port, e))
        except Exception as e:  # noqa: BLE001
            errors.append("bundled: %s" % e)
    raise IOError("no se pudo descargar el catálogo: " + "; ".join(errors))


# ------------------------------------------------------------- catalogo
def _pick(obj: dict, *keys, default=None):
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return default


def parse_server(obj: dict):
    """ServerList.parse: un servidor de s_nd (o 'servers')."""
    host = (_pick(obj, "x_h", "host", default="") or "").strip()
    ip = (_pick(obj, "x_a", "ip", default="") or "").strip()
    sid = (_pick(obj, "x_i", "id", default="") or "").strip()
    if not (sid or host or ip):
        return None
    return {
        "id": sid,
        "name": (_pick(obj, "x_n", "name", default="") or "").strip(),
        "country": (_pick(obj, "x_c", "country", default="") or "").strip(),
        "host": host,
        "ip": ip,
        "tcp": [int(p) for p in (_pick(obj, "x_tp", "tcp", default=[]) or [])],
        "udp": [int(p) for p in (_pick(obj, "x_up", "udp", default=[]) or [])],
        "dns": ((_pick(obj, "x_dn", "dns", default="") or "").strip()).lower(),
        "cdn": ((_pick(obj, "x_cd", "cdn", default="") or "").strip()).lower(),
    }


def parse_catalog(obj: dict) -> dict:
    """ServerList.parse + Configs.parseArray. NO incluye las APIs de descarga."""
    servers = []
    for s in (_pick(obj, "s_nd", "servers", default=[]) or []):
        srv = parse_server(s)
        if srv is not None:
            servers.append(srv)
    configs = []
    for c in (_pick(obj, "c_mx", "configs", default=[]) or []):
        cfg = parse_tunnel_config(c)
        if cfg is not None:
            configs.append(cfg)
    return {
        "catalog_version": _pick(obj, "v_k7", "version", default=0),
        "app_version": _pick(obj, "a_v3", "app_version", default=0),
        "app_version_name": _pick(obj, "a_vn", "app_version_name", default=""),
        "app_url": _pick(obj, "a_ur", "app_url", default=""),
        "app_msg": _pick(obj, "a_mg", "app_msg", default=""),
        "servers": servers,
        "configs": configs,
    }


# -------------------------------------------------------------- configs
def transport_of(value, payload=""):
    """Transport.of: nombre o id numerico -> indice 0..15 (o -1)."""
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value or "").strip()
    if s == "tls":
        return 4 if payload else 3
    if s in TRANSPORT_ALIAS:
        s = TRANSPORT_ALIAS[s]
    return TRANSPORTS.index(s) if s in TRANSPORTS else -1


def _hostport_ok(value: str) -> bool:
    """HostPort.parse: host:puerto o [IPv6]:puerto (puerto 1..65535)."""
    if not value:
        return False
    m = re.match(r"^(?:\[([0-9a-fA-F:]+)\]|([^:\[\]]+)):(\d+)$", value.strip())
    if not m:
        return False
    return 1 <= int(m.group(3)) <= 65535


def _connections_default(transport: int) -> int:
    """Transport.connections(t, 0): 1 para UDP/DNS/ping/HCR/fdns, 4 resto."""
    if transport in (7, 8, 11, 12, 13, 14) or transport in (5, 6):
        return 1
    return 4


def parse_dns(obj: dict):
    """TunnelConfig$Companion.dnsOptions: z_dn{...} o claves dns_* en claro."""
    z = obj.get("z_dn") if isinstance(obj.get("z_dn"), dict) else None
    if z is not None:
        return {
            "mode": "direct" if z.get("d_dr") else "recursive",
            "domain": (z.get("d_dm") or "").strip(),
            "record": (z.get("d_rc") or "").strip().lower(),
            "window": int(z.get("d_wn") or 0),
            "resolver": (z.get("d_rs") or "").strip().lower(),
            "edns": int(z.get("d_ed") or 0),
        }
    return {
        "mode": (obj.get("dns_mode") or "").strip().lower(),
        "domain": (obj.get("dns_domain") or "").strip(),
        "record": (obj.get("dns_record") or "").strip().lower(),
        "window": int(obj.get("dns_window") or 0),
        "resolver": (obj.get("dns_resolver") or "").strip().lower(),
        "edns": int(obj.get("dns_edns") or 0),
    }


def parse_udpc(obj: dict, transport: int):
    """TunnelConfig$Companion.{udpc,udp,turbo}Options: claves u_*."""
    if transport == 12:  # udpc
        return {
            "down": int(obj.get("u_dn") if obj.get("u_dn") is not None else 100),
            "up": int(obj.get("u_up") if obj.get("u_up") is not None else 100),
            "range": (obj.get("u_pr") or "").strip(),
            "sockets": int(obj.get("u_hs") or 0),
            "fast_open": bool(obj.get("u_fo")),
            "sequential": bool(obj.get("u_sp")),
        }
    if transport in (7, 12) and obj.get("u_sp"):  # udp / udpc con salto
        return {"down": 0, "up": 0, "range": (obj.get("u_pr") or "").strip(),
                "sockets": 0, "fast_open": False, "sequential": True}
    if transport == 15 and obj.get("u_fo"):  # ssl_turbo
        return {"down": 0, "up": 0, "range": "", "sockets": 0,
                "fast_open": True, "sequential": False}
    if transport in (7, 8) and obj.get("u_sp"):
        return {"down": 0, "up": 0, "range": (obj.get("u_pr") or "").strip(),
                "sockets": 0, "fast_open": False, "sequential": True}
    return {"down": 0, "up": 0, "range": "", "sockets": 0,
            "fast_open": False, "sequential": False}


def parse_tunnel_config(obj: dict):
    """TunnelConfig$Companion.parse: claves z_* o en claro. None si invalida."""
    if not isinstance(obj, dict):
        return None
    cid = (_pick(obj, "z_i", "id", default="") or "").strip()
    payload = (_pick(obj, "z_b", "payload", default="") or "")
    transport = transport_of(_pick(obj, "z_t", "transport", default=""), payload)
    if not cid or transport < 0 or transport >= len(TRANSPORTS):
        return None
    remote = (_pick(obj, "z_r", "remote", default="") or "").strip()
    # Transport.isValid(t, payload, remote)
    if transport in (1, 4) and not payload.strip():
        return None
    if transport == 2 and not remote:
        return None
    if remote and not _hostport_ok(remote):
        return None
    port = int(_pick(obj, "z_p", "port", default=0) or 0)
    if transport in (5, 6) and port == 0:  # HCR: 8080 por defecto
        port = 8080
    cx = _pick(obj, "z_cx", "connections", default=None)
    connections = int(cx) if cx is not None else _connections_default(transport)
    if not (1 <= connections <= 8):
        connections = _connections_default(transport)
    slots = int(_pick(obj, "z_sl", "slots", default=0) or 0)
    if transport not in (5, 6):
        slots = 0
    elif not (1 <= slots <= 8):
        slots = 4
    chunk = int(_pick(obj, "z_ck", "chunk", default=0) or 0)
    if not (transport in (5, 6) and 256 <= chunk < 16385):
        chunk = 0
    icmp_window = int(_pick(obj, "z_iw", "icmp_window", default=0) or 0)
    if not (transport in (11, 14) and 2 <= icmp_window < 257):
        icmp_window = 0
    fdns_mode = int(_pick(obj, "z_fm", default=0) or 0)
    fdns_mode = 1 if (transport == 13 and fdns_mode == 1) else 0
    fdns_credits = int(_pick(obj, "z_fk", default=0) or 0)
    if not (transport == 13 and 4 <= fdns_credits < 257):
        fdns_credits = 0
    sni = (_pick(obj, "z_w", "sni", default="") or "").strip()
    if transport not in (3, 4, 6, 10, 15):  # solo TLS lleva SNI
        sni = ""
    recommended = _pick(obj, "z_rc", "recommended", default=None)
    if isinstance(recommended, list):
        recommended = sorted({str(c).strip().upper() for c in recommended
                              if len(str(c).strip()) == 2})
    elif recommended is True:
        recommended = []
    else:
        recommended = []
    return {
        "id": cid,
        "name": (_pick(obj, "z_n", "name", default="") or "").strip(),
        "group": (_pick(obj, "z_gp", "group", default="") or "").strip(),
        "server": (_pick(obj, "z_s", "server", default="") or "").strip(),
        "transport": TRANSPORTS[transport],
        "port": port,
        "remote": remote,
        "sni": sni,
        "payload": payload,
        "wait": bool(_pick(obj, "z_wt", "wait", default=False)),
        "connections": connections,
        "slots": slots,
        "note": (_pick(obj, "z_nt", "note", default="") or "").strip(),
        "chunk": chunk,
        "icmp_window": icmp_window,
        "dns": parse_dns(obj),
        "ws_path": (_pick(obj, "z_wp", "ws_path", default="") or "").strip(),
        "ws_host": (_pick(obj, "z_wh", "ws_host", default="") or "").strip(),
        "recommended": recommended,
        "fdns_mode": fdns_mode,
        "fdns_credits": fdns_credits,
        "udpc": parse_udpc(obj, transport),
    }


def export_config(cfg: dict) -> dict:
    """TunnelConfig.toJson: formato de exportacion (claves en claro)."""
    out = {
        "id": cfg["id"], "name": cfg["name"], "group": cfg["group"],
        "server": cfg["server"], "transport": cfg["transport"],
        "port": cfg["port"], "remote": cfg["remote"], "sni": cfg["sni"],
        "payload": cfg["payload"], "wait": cfg["wait"],
        "connections": cfg["connections"], "slots": cfg["slots"],
        "note": cfg["note"],
    }
    t = transport_of(cfg["transport"], cfg["payload"])
    if t in (5, 6) and cfg["chunk"]:
        out["chunk"] = cfg["chunk"]
    if t == 8:  # dns
        d = cfg["dns"]
        out.update({"dns_mode": d["mode"], "dns_domain": d["domain"],
                    "dns_record": d["record"], "dns_window": d["window"],
                    "dns_resolver": d["resolver"], "dns_edns": d["edns"]})
    if t in (9, 10):  # ws
        out.update({"ws_path": cfg["ws_path"], "ws_host": cfg["ws_host"]})
    if t in (11, 14) and cfg["icmp_window"]:
        out["icmp_window"] = cfg["icmp_window"]
    if t == 13:
        if cfg["fdns_mode"]:
            out["z_fm"] = cfg["fdns_mode"]
        if cfg["fdns_credits"]:
            out["z_fk"] = cfg["fdns_credits"]
    u = cfg["udpc"]
    if t == 12:
        out.update({"u_dn": u["down"], "u_up": u["up"]})
        if u["range"]:
            out["u_pr"] = u["range"]
        if u["sockets"]:
            out["u_hs"] = u["sockets"]
        if u["fast_open"]:
            out["u_fo"] = True
    if t == 15 and u["fast_open"]:
        out["u_fo"] = True
    if t in (7, 8, 12) and u["sequential"]:
        out["u_sp"] = True
    if t == 7 and u["sequential"]:
        out["u_pr"] = u["range"]
    return out


def parse_import(text: str):
    """Configs.parseImport: {"configs": [...]} o un solo objeto de config."""
    obj = json.loads(text)
    if isinstance(obj, dict) and "configs" in obj:
        arr = obj.get("configs") or []
        return [c for c in (parse_tunnel_config(x) for x in arr) if c is not None]
    cfg = parse_tunnel_config(obj)
    return [cfg] if cfg is not None else []


# ------------------------------------------------------------------ CLI
def self_test() -> int:
    """Round-trip SINTETICO (sin red): blob, catalogo, config, community."""
    # 1. blob: cifrar y descifrar
    sample = json.dumps({"v_k7": 64, "a_v3": 151, "a_vn": "11.4.1",
                         "s_nd": [], "c_mx": []}, ensure_ascii=False)
    assert decrypt_blob(encrypt_blob(sample, nonce=b"\x00" * 12)) == sample
    assert decrypt_raw_data(encrypt_blob(sample, nonce=b"\x01" * 12)) == sample
    try:
        decrypt_blob(b"demasiado corto")
        raise AssertionError("blob corto deberia fallar")
    except ValueError:
        pass
    # 2. catalogo: parse de la estructura viva (sintetica, sin credenciales)
    cat = parse_catalog({
        "v_k7": 64, "a_v3": 151, "a_vn": "11.4.1",
        "a_ur": "https://play.google.com/store/apps/details?id=com.msyvpn.lite",
        "a_mg": "msg",
        "s_nd": [{"x_i": "mia", "x_n": "Miami", "x_c": "US",
                  "x_h": "mia.jk5.fun", "x_a": "203.0.113.1",
                  "x_tp": [80, 443], "x_up": [80, 443],
                  "x_dn": "n.jk5.fun", "x_cd": "usws.jk5.fun"}],
        "c_mx": [{"z_i": "t1", "z_n": "Prueba", "z_t": "ssl_ws",
                  "z_p": 443, "z_r": "203.0.113.1:443",
                  "z_w": "usws.jk5.fun", "z_cx": 8}]})
    assert cat["catalog_version"] == 64 and len(cat["servers"]) == 1
    assert len(cat["configs"]) == 1
    assert cat["configs"][0]["transport"] == "ssl_ws"
    assert cat["servers"][0]["host"] == "mia.jk5.fun"
    # 3. config: export -> import -> export identico
    cfg = cat["configs"][0]
    assert parse_import(json.dumps({"configs": [export_config(cfg)]}))[0] == cfg
    single = parse_import(json.dumps(export_config(cfg)))
    assert len(single) == 1 and single[0] == cfg
    # 4. community blob: Base64 -> decrypt -> config
    blob = base64.b64encode(encrypt_blob(
        json.dumps(export_config(cfg)), nonce=b"\x02" * 12)).decode()
    assert decrypt_community_blob(blob)["id"] == "t1"
    print("OK self-test: blob AES-GCM, catalogo v64 sintetico, "
          "config export/import, community blob")
    return 0


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Decodificador MSY VPN TUNNEL")
    ap.add_argument("--download", action="store_true",
                    help="descargar el catalogo en vivo y mostrarlo")
    ap.add_argument("--out", help="archivo de salida")
    ap.add_argument("--decrypt", metavar="BLOB",
                    help="descifrar servers.bin / servers.json cifrado")
    ap.add_argument("--parse-config", metavar="JSON",
                    help="parsear export de configs (portapapeles)")
    ap.add_argument("--community-blob", metavar="B64",
                    help="descifrar un blob de comunidad (Base64)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.download:
        text = fetch_catalog()
        cat = parse_catalog(json.loads(text))
        out = json.dumps(cat, ensure_ascii=False, indent=2)
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
            print("catalogo v%d: %d servidores, %d configs -> %s"
                  % (cat["catalog_version"], len(cat["servers"]),
                     len(cat["configs"]), args.out))
        else:
            print(out)
        return 0
    if args.decrypt:
        data = Path(args.decrypt).read_bytes()
        text = decrypt_raw_data(data)
        cat = parse_catalog(json.loads(text))
        out = json.dumps(cat, ensure_ascii=False, indent=2)
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
        else:
            print(out)
        print("blob %d B -> catalogo v%d: %d servidores, %d configs"
              % (len(data), cat["catalog_version"], len(cat["servers"]),
                 len(cat["configs"])), file=sys.stderr)
        return 0
    if args.parse_config:
        cfgs = parse_import(Path(args.parse_config).read_text(encoding="utf-8"))
        out = json.dumps(cfgs, ensure_ascii=False, indent=2)
        if args.out:
            Path(args.out).write_text(out, encoding="utf-8")
        else:
            print(out)
        return 0
    if args.community_blob:
        print(json.dumps(decrypt_community_blob(args.community_blob),
                         ensure_ascii=False, indent=2))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
