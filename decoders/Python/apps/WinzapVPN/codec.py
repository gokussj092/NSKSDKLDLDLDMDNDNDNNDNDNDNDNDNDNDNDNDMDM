"""HTTP WinzapVPN 1.1.61 (76) live catalog and ``Winzap01`` config blobs.

No new crypto is invented here. Everything below was recovered from
the 1.1.61 APK and verified against the live API on 2026-11-22/23
(see ``~/workspace/catalogs/winzapvpn/README.md`` and the dossier
``analysis/com.winzap.winzap_vpn/76/``):

- Live catalog: ``GET /api/v1/bootstrap?device_id=<id>`` — plain JSON,
  no signature, no auth. Verified 2026-11-23: HTTP 200, 249,350 bytes,
  ``config_version`` 1, 19 countries, 177 servers, 0 VIP; two
  consecutive downloads byte-identical (only the volatile
  ``online_users`` counters move between windows). The raw bootstrap
  also carries a per-device ``session``, ads controls, notifications
  and a ``home_background`` asset URL — none of that is catalog data.
  ``decode_catalog`` keeps ONLY the redacted shape already published
  in ``~/workspace/catalogs/winzapvpn/catalog.json`` (app/package/
  version/version_code constants from the analyzed APK plus
  ``config_version`` and ``countries``), whitelisting per-country and
  per-server fields. Dropped on purpose: the whole ``session`` object,
  ``ads_enabled``/``ad_controls``, ``support_contact``,
  ``global_notification``, ``home_background`` (asset URL),
  ``device_banned``/``device_ban_reason``, ``update_available``/
  ``latest_version``, the duplicated flat top-level ``servers`` list,
  and the per-server ``ad_ip_*``, ``change_token``, ``country_id``
  and ``owner_display_name`` fields (``change_token`` is token-like
  and never leaves the server).
- Config blob (``Winzap01``, field ``encrypted_mobile_config`` of a
  server profile): ``base64("Winzap01"(8) || salt(8) ||
  AES-CBC-NoPadding(ct))``. Key/IV: OpenSSL EVP_BytesToKey with MD5
  (1 iteration) over the master key embedded in the app (class ``Lsa``),
  ``key = derived[0:32]``, ``iv = derived[32:48]``; plaintext is JSON
  with short keys and PKCS#7 padding. Sensitive fields (layer 3:
  ``pu, pw, su, sw, ua, sc, vj, oc``) are encrypted per field:
  ``base64(iv(16) || AES-CBC(ct))``, key
  ``SHA-256("<master>:<short-key>:field")``, ROT13 applied to the
  letters after decryption. Short keys are renamed to long names
  (see ``SHORT_TO_LONG``). Blob state: VERIFIED_SYNTHETIC (round-trip
  with the method recovered from the DEX); no real
  ``encrypted_mobile_config`` has been supplied yet.

The per-server profile endpoint
(``GET /api/v1/servers/{id}/profile``) requires the app's HMAC-SHA256
request signature (``X-Request-Timestamp``, ``X-Request-Nonce``,
``X-Request-Signature``), whose construction was NOT reproduced: the
server answers 401 without it and this module never forges it.
``download_server_profile`` therefore does not exist here — the
profile/blob path stays PENDING until a real signed session is
available. The catalog (bootstrap) needs no signature at all.

HMAC connection authentication: NOT_OBSERVED (see dossier
MANIFEST.json ``connection_authentication``). The bootstrap is plain
HTTPS JSON; the Winzap01 envelope is unauthenticated ciphertext.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES

MAX_BYTES = 8 * 1024 * 1024
CATALOG_URL = "https://vpnapi.winzapg.online:2083/api/v1/bootstrap?device_id=WINZAP-TEST0001"
DEVICE_ID = "WINZAP-TEST0001"

APP_NAME = "HTTP WinzapVPN"
PACKAGE = "com.winzap.winzap_vpn"
VERSION = "1.1.61"
VERSION_CODE = 76

# Master key embedded in the app (class Lsa, <clinit>: table of 28 ints).
# Same precedent as the Maya XTS key: the key is app-embedded material
# recovered from the analyzed APK, needed to open the catalog's blobs.
_MASTER_SECRET = "H.qe_oL,|jm,T,f<-/-*>G|MfOkP"

SHORT_TO_LONG = {
    "na": "Name", "fl": "FLAG", "sp": "sPais", "si": "ServerIP",
    "sr": "ServerPort", "su": "ServerUser", "sw": "ServerPass",
    "py": "Payload", "sn": "SNI", "pi": "ProxyIP", "pp": "ProxyPort",
    "pu": "ProxyUser", "pw": "ProxyPass", "sc": "Slowchave",
    "ns": "Nameserver", "sd": "Slowdns", "us": "udpserver",
    "ur": "udpPortRange", "ua": "udpauth", "uo": "udpobfs",
    "ud": "udpdown", "uu": "udpup", "ub": "udpbuffer",
    "vj": "v2rayJson", "d1": "isDirect", "d2": "isSSL",
    "d3": "isSSLRP", "d4": "isPayloadSSL", "d5": "isInject",
    "d6": "isBhttp", "d7": "isSlow", "d8": "isV2ray", "d9": "isudp",
    "da": "isUdpCustom", "db": "isOpenVpn", "oc": "ovpnConfig",
    "bv": "BhttpVersion", "bu": "BhttpUploadSlots",
    "bd": "BhttpDownloadSlots", "ed": "enableDns",
    "ew": "enableWakeLock", "dd": "disableDelay",
    "sc2": "sshCompression", "r1": "DNSResolver1",
    "r2": "DNSResolver2", "gw": "UDPGW", "id": "serverId",
    "tt": "tunnelType",
}

# Layer-3 (per-field encrypted) short keys.
LAYER3_FIELDS = {"pu", "pw", "su", "sw", "ua", "sc", "vj", "oc"}

# Whitelisted result fields: exactly the redacted catalog shape in
# ~/workspace/catalogs/winzapvpn/catalog.json. Anything else the
# bootstrap carries (session, ads, tokens) is dropped, never served.
_COUNTRY_FIELDS = {
    "id": str, "name": str, "flag_emoji": str, "sort_order": int,
    "is_active": bool, "server_count": int,
}
_SERVER_FIELDS = {
    "id": str, "name": str, "country": str, "subtitle": str,
    "flag_emoji": str, "is_active": bool, "is_vip_only": bool,
    "available_access_count": int, "online_users": int,
    "latency_host": str, "latency_port": int,
}


class DecodeError(ValueError):
    pass


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DecodeError("JSON ambiguo.")
        out[key] = value
    return out


def _invalid_constant(value):
    raise DecodeError("Constante JSON inválida.")


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _whitelist(record, fields):
    """Copy only whitelisted fields with the expected type; drop the rest."""
    out = {}
    for name, kind in fields.items():
        if name not in record:
            continue
        value = record[name]
        if kind is int:
            if _is_int(value):
                out[name] = value
        elif kind is bool:
            if isinstance(value, bool):
                out[name] = value
        elif kind is str:
            if isinstance(value, str):
                out[name] = value
    return out


def decode_catalog(data: bytes) -> dict:
    """Parse a raw bootstrap body and render the redacted catalog only.

    The bootstrap is plain JSON (no envelope, no decryption): the work
    here is validation plus stripping everything that is not catalog
    data (session, ads, notifications, asset URLs, per-server tokens).
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    if data.lstrip().startswith(b"<"):
        raise DecodeError("Respuesta remota inválida (HTML).")
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_unique,
                         parse_constant=_invalid_constant)
    except DecodeError:
        raise
    except (ValueError, UnicodeError):
        raise DecodeError("Catálogo inválido o incompatible con HTTP WinzapVPN 1.1.61.") from None
    if not isinstance(doc, dict):
        raise DecodeError("Catálogo sin JSON válido.")
    if not _is_int(doc.get("config_version")):
        raise DecodeError("Falta config_version en el catálogo.")
    countries = doc.get("countries")
    if not isinstance(countries, list) or not countries:
        raise DecodeError("Faltan países en el catálogo.")
    out_countries = []
    total_servers = 0
    for country in countries:
        if not isinstance(country, dict):
            raise DecodeError("País inválido en el catálogo.")
        servers = country.get("servers")
        if not isinstance(servers, list):
            raise DecodeError("Faltan servidores en un país del catálogo.")
        out_servers = []
        for server in servers:
            if not isinstance(server, dict):
                raise DecodeError("Servidor inválido en el catálogo.")
            if (not isinstance(server.get("id"), str) or not server["id"]
                    or not isinstance(server.get("name"), str) or not server["name"]):
                raise DecodeError("Servidor sin id o nombre en el catálogo.")
            out_servers.append(_whitelist(server, _SERVER_FIELDS))
        total_servers += len(out_servers)
        entry = _whitelist(country, _COUNTRY_FIELDS)
        entry["servers"] = out_servers
        out_countries.append(entry)
    if not total_servers:
        raise DecodeError("Catálogo sin servidores.")
    return {
        "app": APP_NAME,
        "package": PACKAGE,
        "version": VERSION,
        "version_code": VERSION_CODE,
        "config_version": doc["config_version"],
        "countries": out_countries,
    }


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


# ---------------------------------------------------------------- Winzap01

def _evp_bytes_to_key_md5(password: bytes, salt: bytes,
                          key_len: int = 32, iv_len: int = 16):
    """OpenSSL EVP_BytesToKey con MD5, 1 iteracion (como en Lsa;.a)."""
    out = b""
    prev = b""
    while len(out) < key_len + iv_len:
        d = hashlib.md5(prev + password + salt).digest()
        out += d
        prev = d
    return out[:key_len], out[key_len:key_len + iv_len]


def _pkcs7_pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Array is empty.")
    pad = data[-1]
    if pad < 1 or pad > 16:
        raise ValueError("padding invalido: %d" % pad)
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("padding PKCS#7 invalido")
    return data[:-pad]


def _rot13(text: str) -> str:
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(65 + (o - 65 + 13) % 26))
        elif 97 <= o <= 122:
            out.append(chr(97 + (o - 97 + 13) % 26))
        else:
            out.append(ch)
    return "".join(out)


def decode_field(short_key: str, value_b64: str) -> str:
    """Descifra un campo de capa 3 (Lsa;.b)."""
    raw = base64.b64decode(value_b64)
    if len(raw) < 16:
        raise ValueError("campo de capa 3 demasiado corto")
    iv, ct = raw[:16], raw[16:]
    key = hashlib.sha256(
        ("%s:%s:field" % (_MASTER_SECRET, short_key)).encode("utf-8")
    ).digest()
    pt = _pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct))
    return _rot13(pt.decode("utf-8"))


def encode_field(short_key: str, plaintext: str, iv: bytes = None) -> str:
    """Cifra un campo de capa 3 (inverso de decode_field; para pruebas)."""
    import os
    if iv is None:
        iv = os.urandom(16)
    key = hashlib.sha256(
        ("%s:%s:field" % (_MASTER_SECRET, short_key)).encode("utf-8")
    ).digest()
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(
        _pkcs7_pad(_rot13(plaintext).encode("utf-8")))
    return base64.b64encode(iv + ct).decode("ascii")


def decode_winzap01_blob(blob_b64: str) -> dict:
    """Descifra un blob Winzap01 (base64) a dict con claves largas.

    Lanza ValueError si el header no es 'Winzap01'. Los campos de capa 3
    que fallen al descifrar se dejan como estan (igual que hace la app:
    log y continua). VERIFIED_SYNTHETIC: falta un blob real.
    """
    raw = base64.b64decode(blob_b64)
    if len(raw) < 8 or raw[:8] != b"Winzap01":
        raise ValueError("Header invalido: no es un blob Winzap01")
    salt, ct = raw[8:16], raw[16:]
    if len(ct) == 0 or len(ct) % 16 != 0:
        raise ValueError("cuerpo del blob vacio o no multiplo de 16")
    key, iv = _evp_bytes_to_key_md5(_MASTER_SECRET.encode("utf-8"), salt)
    pt = _pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct))
    obj = json.loads(pt.decode("utf-8"))
    for short_key in list(LAYER3_FIELDS):
        if short_key in obj:
            val = obj.get(short_key)
            if isinstance(val, str) and val:
                try:
                    obj[short_key] = decode_field(short_key, val)
                except Exception:
                    # La app lo deja y sigue.
                    pass
    out = {}
    for k, v in obj.items():
        out[SHORT_TO_LONG.get(k, k)] = v
    return out


def encode_winzap01_blob(obj_short_keys: dict, salt: bytes = None) -> str:
    """Construye un blob Winzap01 (inverso de decode; para pruebas).

    obj_short_keys usa claves cortas; los campos de capa 3 deben ir
    ya cifrados con encode_field().
    """
    import os
    if salt is None:
        salt = os.urandom(8)
    key, iv = _evp_bytes_to_key_md5(_MASTER_SECRET.encode("utf-8"), salt)
    pt = _pkcs7_pad(json.dumps(
        obj_short_keys, ensure_ascii=False).encode("utf-8"))
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pt)
    return base64.b64encode(b"Winzap01" + salt + ct).decode("ascii")
