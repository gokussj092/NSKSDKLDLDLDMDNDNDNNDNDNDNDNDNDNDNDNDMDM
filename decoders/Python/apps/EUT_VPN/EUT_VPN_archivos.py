#!/usr/bin/env python3
"""EUT VPN (xyz.eutvpn.app) 2.4.1 - archivos, enlaces y nube (SP-DECODE).

La app NO tiene extension de archivo propia ni intent-filter de archivos:
"Import Config - QR, File, or Cloud Code" lee un TEXTO (de un QR, de un
archivo cualquiera elegido con el selector, o pegado) y lo pasa a tx8.b().
Hay dos formatos de texto, ambos verificados en el APK:

  1. Blob sza ("eut://" o "eut-settings://" o sin prefijo):
     sza.c / sza.b [defpackage/sza.java]: AES-128-CBC/PKCS5Padding, clave =
     primeros 16 caracteres de "fS^]a_DTTj>OU1h&rDx&RUf)-[DmY3Nv"
     (ISO-8859-1), IV = "YHLV8VX/+Tm3@N<y". Texto =
     Base64(ct) + ":" + Base64(iv) (Base64 DEFAULT de Android).
     Al descifrar es un JSON con, como minimo, "qr_expiration"
     ("yyyy-MM-dd HH:mm:ss", zona Asia/Manila; "1111-11-11 11:11:11" =
     nunca expira). La app guarda TODAS las claves del JSON en sus
     preferencias cifradas (a77.e). Segun el contenido muestra:
     "GCP service imported!" (si trae main_server_ws_host o
     temp_server_ws_host), "Custom payload imported!" (type =
     custom_payload) o "Configuration imported!".
     La exportacion de ajustes construye "eut-settings://" + sza.c(json)
     (g4a.java).

  2. Enlace eut-payload:// v1 (custom payload) [tx8.b + kp3.b]:
     "eut-payload://" + Base64URL_sin_padding_sin_saltos(envelope), donde
     envelope = 0x01 || salt16 || nonce12 || AES-256-GCM(ct||tag).
     La clave AES se deriva con PBKDF2-HmacSHA256(password, salt, 120000,
     256 bits). El JSON descifrado es:
       {"v": 1, "exported_at": "...", "expiration": "...", "locked": bool,
        "type": "custom_payload",
        "config": {"name", "details", "requestMethod", "protocolType",
                   "protocolMode", "sniHost", "targetHost", "targetPort",
                   "hostHeader", "routeHost", "websocketHandshake",
                   "websocketPreflightMethod", "wsPath", "v2rayTransport",
                   "v2rayProxyHost", "v2rayProxyPort",
                   "v2rayProxyPayloadTemplate", "payloadTemplate",
                   "rawPayloadTemplate", "uuid", "message"},
        "show_advanced": bool, "country": "", "carrier": "",
        "device_id": "", "app_version_code": int}
     Reglas de importacion: app_version_code > 370 -> "requiere una version
     mas nueva"; expiration vacia o vencida -> expirado; locked -> no
     muestra opciones avanzadas.

  Nube (necesita access_token de init-session; ver EUT_VPN.py):
     POST /payload-share/create  {blob, expiration, is_community_submission}
       -> {"code": "...", "expiration": "..."}
     GET  /payload-share/get?code=<code>  -> {"blob": "...", "expiration": "..."}
     El blob que se comparte es el texto de arriba (normalmente un
     eut-payload://). Sin token el servidor responde 401 Missing token.

  Otros datos locales (sin script de apertura, documentados):
     - Base de datos SQLCipher de recursos:
       yMGZ9sToUZMO3p1ZX7WVxFZVcNMzvdfv (tablas resources, etc.). La
       contrasena esta en el APK (a51.java). SQLCipher no es stdlib, asi
       que este script solo la identifica; para abrirla hace falta
       sqlcipher o la exportacion de la app.
     - Esquema eutwifihotspot://: solo abre el HotspotDispatchActivity,
       NO importa configuraciones.
     - Enlaces v2ray estandar (vmess://, vless://, trojan://, ss://, etc.)
       se pegan en la app; ya los cubre SP-DECODE de forma generica.

Uso:
  python3 EUT_VPN_archivos.py --file config.txt
  python3 EUT_VPN_archivos.py --link 'eut-payload://...'
  python3 EUT_VPN_archivos.py --link 'eut://...'
  python3 EUT_VPN_archivos.py --seal-settings config.json [--out out.txt]
  python3 EUT_VPN_archivos.py --seal-payload payload.json [--out out.txt]
  python3 EUT_VPN_archivos.py --cloud-get CODE --token ACCESS_TOKEN
  python3 EUT_VPN_archivos.py --cloud-create --blob 'eut-payload://...' \
      --expiration '2030-01-01 00:00:00' --token ACCESS_TOKEN [--community]
  python3 EUT_VPN_archivos.py --self-test

Solo Python stdlib.
"""
import argparse
import base64
import binascii
import datetime
import hashlib
import http.client
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.request

API_BASE = "https://api.eutvpn.com/v5/android/client"
APP_VERSION_CODE = 370
NEVER_EXPIRES = "1111-11-11 11:11:11"
MANILA = datetime.timezone(datetime.timedelta(hours=8))

# Constantes de formato de la app (ver docstring del modulo).
SZA_KEY = "fS^]a_DTTj>OU1h&rDx&RUf)-[DmY3Nv"
SZA_IV = "YHLV8VX/+Tm3@N<y"
PAYLOAD_PBKDF2_PASSWORD = (
    "CidAKLbw2vgKT6ckGKNG7aS11nmW9sg8g4l-YvBB_cyqsJDl5EnAffoY_7XpTRHC")
PAYLOAD_PBKDF2_ITERATIONS = 120000

# ------------------------------------------------------------- AES puro
# (mismo nucleo que EUT_VPN.py: AES-128/192/256 + CBC + GCM en stdlib)


def _make_sbox():
    sbox = []
    for i in range(256):
        if i == 0:
            inv = 0
        else:
            inv = 0
            for y in range(1, 256):
                p = 0
                aa, bb = i, y
                while bb:
                    if bb & 1:
                        p ^= aa
                    aa = ((aa << 1) ^ (0x1B if aa & 0x80 else 0)) & 0xFF
                    bb >>= 1
                if p == 1:
                    inv = y
                    break
        s = (inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6))
             ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63)
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(x):
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _aes_key_expand(key):
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            sub = ((_SBOX[(rot >> 24) & 0xFF] << 24)
                   | (_SBOX[(rot >> 16) & 0xFF] << 16)
                   | (_SBOX[(rot >> 8) & 0xFF] << 8)
                   | _SBOX[rot & 0xFF])
            temp = sub ^ (_RCON[i // nk - 1] << 24)
        elif nk > 6 and i % nk == 4:
            temp = ((_SBOX[(temp >> 24) & 0xFF] << 24)
                    | (_SBOX[(temp >> 16) & 0xFF] << 16)
                    | (_SBOX[(temp >> 8) & 0xFF] << 8)
                    | _SBOX[temp & 0xFF])
        w.append(w[i - nk] ^ temp)
    return w, nr


def _add_rk(state, w, rnd):
    for c in range(4):
        state[c] ^= w[4 * rnd + c]


def _sub_bytes(state):
    for c in range(4):
        v = state[c]
        state[c] = ((_SBOX[(v >> 24) & 0xFF] << 24)
                    | (_SBOX[(v >> 16) & 0xFF] << 16)
                    | (_SBOX[(v >> 8) & 0xFF] << 8)
                    | _SBOX[v & 0xFF])


def _inv_sub_bytes(state):
    for c in range(4):
        v = state[c]
        state[c] = ((_INV_SBOX[(v >> 24) & 0xFF] << 24)
                    | (_INV_SBOX[(v >> 16) & 0xFF] << 16)
                    | (_INV_SBOX[(v >> 8) & 0xFF] << 8)
                    | _INV_SBOX[v & 0xFF])


def _shift_rows(state):
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = (state[j] >> (24 - 8 * i)) & 0xFF
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
    return list(struct.unpack(">4I", bytes(sb)))


def _inv_shift_rows(state):
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = (state[j] >> (24 - 8 * i)) & 0xFF
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c - r) % 4) + r]
    return list(struct.unpack(">4I", bytes(sb)))


def _mix_columns(state):
    out = [0] * 4
    for c in range(4):
        v = state[c]
        a0, a1, a2, a3 = (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF
        out[c] = ((_gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3) << 24
                  | (a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3) << 16
                  | (a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)) << 8
                  | (_gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)))
    return out


def _inv_mix_columns(state):
    out = [0] * 4
    for c in range(4):
        v = state[c]
        a0, a1, a2, a3 = (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF
        out[c] = ((_gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)) << 24
                  | (_gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)) << 16
                  | (_gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)) << 8
                  | (_gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)))
    return out


def _aes_encrypt_block(key, block):
    w, nr = _aes_key_expand(key)
    s = list(struct.unpack(">4I", block))
    _add_rk(s, w, 0)
    for rnd in range(1, nr):
        _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        _add_rk(s, w, rnd)
    _sub_bytes(s)
    s = _shift_rows(s)
    _add_rk(s, w, nr)
    return struct.pack(">4I", *s)


def _aes_decrypt_block(key, block):
    w, nr = _aes_key_expand(key)
    s = list(struct.unpack(">4I", block))
    _add_rk(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        s = _inv_shift_rows(s)
        _inv_sub_bytes(s)
        _add_rk(s, w, rnd)
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_rk(s, w, 0)
    return struct.pack(">4I", *s)


def _pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("empty plaintext")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS7 padding")
    return data[:-n]


def _aes_cbc_encrypt(key, iv, data):
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _aes_encrypt_block(key, blk)
        out += enc
        prev = enc
    return bytes(out)


def _aes_cbc_decrypt(key, iv, data):
    if len(data) % 16:
        raise ValueError("ciphertext is not a multiple of 16 bytes")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _aes_decrypt_block(key, blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


_GCM_R = 0xE1000000000000000000000000000000


def _gf128_mul(x, y):
    z = 0
    v = y
    for _ in range(128):
        if (x >> 127) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
        x = (x << 1) & ((1 << 128) - 1)
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        chunk = chunk + b"\x00" * (16 - len(chunk))
        y = _gf128_mul(y ^ int.from_bytes(chunk, "big"), h)
    return y


def _gcm_crypt(key, nonce, data, tag=None, aad=b""):
    """AES-GCM (nonce 12 bytes). Sin tag -> cifra y devuelve (ct, tag);
    con tag -> descifra y verifica (ValueError si el tag no verifica)."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    h = int.from_bytes(_aes_encrypt_block(key, bytes(16)), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    # CTR con contador inicial 2.
    out = bytearray()
    counter = 2
    for i in range(0, len(data), 16):
        blk = nonce + struct.pack(">I", counter)
        ks = _aes_encrypt_block(key, blk)
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1
    # GHASH en una sola pasada: AAD || pad || C || pad || longitudes.
    # En cifrado C es la salida; en descifrado C es la entrada (data).
    ct_for_ghash = bytes(out) if tag is None else data
    def _pad16(b):
        return b + b"\x00" * ((-len(b)) % 16)
    ghash_in = (_pad16(aad) + _pad16(ct_for_ghash)
                + struct.pack(">QQ", len(aad) * 8, len(data) * 8))
    s = _ghash(h, ghash_in)
    calc_tag = _aes_encrypt_block(key, j0)
    calc_tag = bytes(a ^ b for a, b in zip(calc_tag, s.to_bytes(16, "big")))
    if tag is None:
        return bytes(out), calc_tag
    if tag != calc_tag:
        raise ValueError("GCM tag mismatch")
    return bytes(out)


# ------------------------------------------------------- Base64 de Android
def _b64_default_encode(raw):
    return base64.encodebytes(raw).decode("ascii")


def _b64_decode(text):
    return base64.b64decode(re.sub(r"\s+", "", text))


def _b64url_nopad_decode(text):
    compact = re.sub(r"\s+", "", text)
    return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))


def _b64url_nopad_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# ------------------------------------------------------------- sza.c / sza.b
def _sza_key_bytes(key_str):
    raw = key_str[:16].encode("iso-8859-1")
    return raw + b"\x00" * (16 - len(raw))


def sza_encrypt(key_str, iv_str, plaintext):
    key = _sza_key_bytes(key_str)
    iv = iv_str.encode("iso-8859-1")
    ct = _aes_cbc_encrypt(key, iv, _pkcs7_pad(plaintext.encode("utf-8")))
    return _b64_default_encode(ct) + ":" + _b64_default_encode(iv)


def sza_decrypt(key_str, text):
    if text is None:
        return ""
    clean = re.sub(r"^eut(-settings|-payload)?://", "",
                   text.strip(), flags=re.IGNORECASE)
    parts = clean.split(":")
    if len(parts) < 2:
        return ""
    try:
        ct = _b64_decode(parts[0])
        iv = _b64_decode(parts[1])
    except (binascii.Error, ValueError):
        return ""
    key = _sza_key_bytes(key_str)
    try:
        pt = _pkcs7_unpad(_aes_cbc_decrypt(key, iv, ct))
    except ValueError:
        return ""
    return pt.decode("utf-8", "replace")


# ------------------------------------------------------- eut-payload:// v1
def _payload_key(salt16):
    return hashlib.pbkdf2_hmac(
        "sha256", PAYLOAD_PBKDF2_PASSWORD.encode("ascii"), salt16,
        PAYLOAD_PBKDF2_ITERATIONS, dklen=32)


def payload_decrypt(link):
    """Descifra un enlace eut-payload:// v1 -> str JSON o None."""
    body = link.strip()
    if body.lower().startswith("eut-payload://"):
        body = body[len("eut-payload://"):]
    try:
        env = _b64url_nopad_decode(body)
    except (binascii.Error, ValueError):
        return None
    if len(env) < 45 or env[0] != 1:
        return None
    salt, nonce, cttag = env[1:17], env[17:29], env[29:]
    if len(cttag) < 17:
        return None
    key = _payload_key(salt)
    try:
        pt = _gcm_crypt(key, nonce, cttag[:-16], tag=cttag[-16:])
    except ValueError:
        return None
    return pt.decode("utf-8", "replace")


def payload_encrypt(payload_json_str, salt=None, nonce=None):
    """Construye un enlace eut-payload:// v1 (kp3.b)."""
    if salt is None:
        salt = os.urandom(16)
    if nonce is None:
        nonce = os.urandom(12)
    key = _payload_key(salt)
    ct, tag = _gcm_crypt(key, nonce, payload_json_str.encode("utf-8"))
    env = b"\x01" + salt + nonce + ct + tag
    return "eut-payload://" + _b64url_nopad_encode(env)


# ------------------------------------------------------------- expiracion
def is_expired(datestr):
    """b49.e: True si la fecha 'yyyy-MM-dd HH:mm:ss' (Asia/Manila) ya paso."""
    if not datestr:
        return False
    try:
        dt = datetime.datetime.strptime(datestr, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    dt = dt.replace(tzinfo=MANILA)
    return dt <= datetime.datetime.now(MANILA)


# ---------------------------------------------------------------- importar
def import_text(text):
    """Replica tx8.b() + a77.e()/a77.f(): abre un texto importado.

    Devuelve (kind, obj) donde kind es 'custom_payload', 'settings',
    'gcp' o 'config'; obj es el JSON descifrado (o None si no abre).
    """
    text = (text or "").strip()
    if not text:
        return "empty", None
    if text.lower().startswith("eut-payload://"):
        plain = payload_decrypt(text)
        if plain is not None:
            try:
                obj = json.loads(plain)
            except json.JSONDecodeError:
                return "corrupt", None
            return "custom_payload", obj
        # Si el sobre GCM no abre, la app cae al camino sza (a77.e).
    plain = sza_decrypt(SZA_KEY, text)
    if not plain:
        return "invalid", None
    try:
        obj = json.loads(plain)
    except json.JSONDecodeError:
        return "corrupt", None
    if isinstance(obj, dict):
        if obj.get("main_server_ws_host") or obj.get("temp_server_ws_host"):
            return "gcp", obj
        if obj.get("type") == "custom_payload":
            return "custom_payload", obj
        return "config", obj
    return "config", obj


def describe_import(kind, obj):
    """Resumen estilo app de un JSON importado."""
    if obj is None:
        return {"status": kind}
    out = {"status": kind}
    if isinstance(obj, dict):
        exp = obj.get("qr_expiration") or obj.get("expiration") or ""
        out["expiration"] = exp
        out["expired"] = (is_expired(exp) if exp and exp != NEVER_EXPIRES
                          else False)
        out["never_expires"] = exp == NEVER_EXPIRES
        out["keys"] = sorted(obj.keys())
        if kind == "custom_payload":
            cfg = obj.get("config") or {}
            out["config"] = {
                "name": cfg.get("name"),
                "protocolMode": cfg.get("protocolMode"),
                "protocolType": cfg.get("protocolType"),
                "requestMethod": cfg.get("requestMethod"),
                "targetHost": cfg.get("targetHost"),
                "targetPort": cfg.get("targetPort"),
                "sniHost": cfg.get("sniHost"),
                "hostHeader": cfg.get("hostHeader"),
                "routeHost": cfg.get("routeHost"),
                "v2rayTransport": cfg.get("v2rayTransport"),
                "v2rayProxyHost": cfg.get("v2rayProxyHost"),
                "v2rayProxyPort": cfg.get("v2rayProxyPort"),
                "locked": obj.get("locked"),
                "app_version_code": obj.get("app_version_code"),
                "version_too_new": bool(
                    isinstance(obj.get("app_version_code"), int)
                    and obj["app_version_code"] > APP_VERSION_CODE),
            }
    return out


# ------------------------------------------------------------------- nube
def _http_json(method, url, payload, token, timeout=30):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent",
                   "Dalvik/2.1.0 (Linux; U; Android 14; 2409BRN2CL "
                   "Build/UKQ1.240624.001)")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            try:
                body = resp.read()
            except http.client.IncompleteRead as ir:
                body = ir.partial
            return resp.status, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except http.client.IncompleteRead as ir:
            body = ir.partial
        except Exception:
            body = b""
        return e.code, body.decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError,
            http.client.HTTPException) as e:
        return None, "NETWORK_ERROR: %s" % e


def cloud_get(code, token):
    import urllib.parse
    url = (API_BASE + "/payload-share/get?code="
           + urllib.parse.quote(code, safe=""))
    status, text = _http_json("GET", url, None, token)
    if status is None:
        return None, text
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None, "HTTP %s: %s" % (status, text[:200])
    if status == 200 and isinstance(obj, dict) and obj.get("blob"):
        return obj, None
    return None, "HTTP %s: %s" % (
        status, obj.get("message") or obj.get("error") or text[:200])


def cloud_create(blob, expiration, token, community=False):
    status, text = _http_json(
        "POST", API_BASE + "/payload-share/create",
        {"blob": blob, "expiration": expiration,
         "is_community_submission": bool(community)}, token)
    if status is None:
        return None, text
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None, "HTTP %s: %s" % (status, text[:200])
    if status == 200 and isinstance(obj, dict) and obj.get("code"):
        return obj, None
    return None, "HTTP %s: %s" % (
        status, obj.get("message") or obj.get("error") or text[:200])


# -------------------------------------------------------------------- CLI
def _cmd_open(args):
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        source = args.file
    else:
        text = args.link
        source = "link"
    kind, obj = import_text(text)
    info = describe_import(kind, obj)
    if obj is not None:
        print("Fuente: %s" % source)
        print("Tipo: %s" % kind)
        print(json.dumps(info, ensure_ascii=False, indent=2))
        print("--- JSON descifrado ---")
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        if info.get("expired"):
            print("ADVERTENCIA: el contenido esta vencido "
                  "(qr_expiration/expiration).")
        if info.get("config", {}).get("version_too_new"):
            print("ADVERTENCIA: requiere una version de la app mas nueva "
                  "que 2.4.1 (app_version_code > 370).")
        return 0
    if kind == "empty":
        print("Vacio: no hay texto que importar.")
    elif kind == "invalid":
        print("INVALIDO: el texto no abre ni como eut-payload:// (GCM v1) "
              "ni como blob sza (eut:// / eut-settings:// / ct:iv).")
    else:
        print("CORRUPTO: descifro pero el JSON no es valido.")
    return 2


def _cmd_seal_settings(args):
    with open(args.seal_settings, "r", encoding="utf-8") as fh:
        obj = json.load(fh)
    if "qr_expiration" not in obj:
        print("ADVERTENCIA: el JSON no trae qr_expiration; la app lo "
              "rechazaria al importar (a77.e exige el campo).")
    blob = "eut-settings://" + sza_encrypt(
        SZA_KEY, SZA_IV, json.dumps(obj, ensure_ascii=False))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(blob)
        print("Enlace guardado en %s" % args.out)
    print(blob)
    return 0


def _cmd_seal_payload(args):
    with open(args.seal_payload, "r", encoding="utf-8") as fh:
        obj = json.load(fh)
    link = payload_encrypt(json.dumps(obj, ensure_ascii=False))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(link)
        print("Enlace guardado en %s" % args.out)
    print(link)
    return 0


def _cmd_cloud_get(args):
    if not args.token:
        print("CLOUD_TOKEN_REQUIRED: payload-share/get exige un "
              "access_token (init-session). Sin token el servidor responde "
              "401 Missing token.")
        return 3
    obj, err = cloud_get(args.cloud_get, args.token)
    if obj is None:
        print("CLOUD_GET_FAILED: %s" % err)
        return 2
    print("Nube: blob recibido (expiration=%s)" % obj.get("expiration"))
    kind, inner = import_text(obj["blob"])
    info = describe_import(kind, inner)
    print(json.dumps(info, ensure_ascii=False, indent=2))
    if inner is not None:
        print(json.dumps(inner, ensure_ascii=False, indent=2))
        return 0
    print("El blob de la nube no se pudo abrir con este script.")
    return 2


def _cmd_cloud_create(args):
    if not args.token:
        print("CLOUD_TOKEN_REQUIRED: payload-share/create exige un "
              "access_token (init-session). Sin token el servidor responde "
              "401 Missing token.")
        return 3
    if not args.blob:
        print("Falta --blob con el texto a compartir "
              "(normalmente un eut-payload://).")
        return 2
    if not args.expiration:
        print("Falta --expiration ('yyyy-MM-dd HH:mm:ss').")
        return 2
    obj, err = cloud_create(args.blob, args.expiration, args.token,
                            community=args.community)
    if obj is None:
        print("CLOUD_CREATE_FAILED: %s" % err)
        return 2
    print("Compartido en la nube: code=%s expiration=%s"
          % (obj.get("code"), obj.get("expiration")))
    return 0


def _cmd_self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("OK  " if cond else "FALLO ") + name)
        ok = ok and bool(cond)

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    check("AES-128 FIPS-197 cifrado", _aes_encrypt_block(key, pt) == ct)
    check("AES-128 FIPS-197 descifrado", _aes_decrypt_block(key, ct) == pt)
    key256 = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ct256 = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    check("AES-256 FIPS-197 cifrado",
          _aes_encrypt_block(key256, pt) == ct256)
    check("AES-256 FIPS-197 descifrado",
          _aes_decrypt_block(key256, ct256) == pt)
    # sza round-trip.
    sample = {"type": "config", "qr_expiration": NEVER_EXPIRES,
              "name": "prueba", "main_server_ws_host": "x.example.com"}
    blob = sza_encrypt(SZA_KEY, SZA_IV, json.dumps(sample))
    check("sza round-trip",
          json.loads(sza_decrypt(SZA_KEY, blob)) == sample)
    check("sza abre con prefijo eut-settings://",
          sza_decrypt(SZA_KEY, "eut-settings://" + blob) != "")
    # Import de un blob de ajustes (gcp por main_server_ws_host).
    kind, obj = import_text("eut-settings://" + blob)
    check("import_text: ajustes -> gcp",
          kind == "gcp" and obj["name"] == "prueba")
    info = describe_import(kind, obj)
    check("describe_import: never_expires",
          info["never_expires"] is True and info["expired"] is False)
    # Expiracion.
    check("is_expired: fecha pasada", is_expired("2020-01-01 00:00:00"))
    check("is_expired: fecha futura",
          not is_expired("2099-01-01 00:00:00"))
    check("is_expired: basura -> False", not is_expired("no-fecha"))
    # eut-payload:// v1: sellar y abrir (vectores fijos para determinismo).
    payload = {"v": 1, "exported_at": "2026-11-14 12:00:00",
               "expiration": NEVER_EXPIRES, "locked": False,
               "type": "custom_payload",
               "config": {"name": "Prueba", "details": "",
                          "requestMethod": "CONNECT",
                          "protocolType": "HTTP_PAYLOAD",
                          "protocolMode": "DIRECT",
                          "sniHost": "", "targetHost": "[host]",
                          "targetPort": 80, "hostHeader": "[host]",
                          "routeHost": "", "websocketHandshake":
                          "STANDARD_UPGRADE", "websocketPreflightMethod":
                          "GET", "wsPath": "", "v2rayTransport": "ws",
                          "v2rayProxyHost": "", "v2rayProxyPort": None,
                          "v2rayProxyPayloadTemplate": "",
                          "payloadTemplate": "GET / HTTP/1.1[crlf]Host: "
                          "[host][crlf][crlf]", "rawPayloadTemplate": "",
                          "uuid": "", "message": ""},
               "show_advanced": False, "country": "", "carrier": "",
               "device_id": "", "app_version_code": 370}
    link = payload_encrypt(json.dumps(payload),
                           salt=bytes(16), nonce=bytes(12))
    check("payload_encrypt: prefijo y version",
          link.startswith("eut-payload://"))
    plain = payload_decrypt(link)
    check("payload round-trip (sellado determinista)",
          plain is not None and json.loads(plain) == payload)
    kind2, obj2 = import_text(link)
    check("import_text: eut-payload:// -> custom_payload",
          kind2 == "custom_payload"
          and obj2["config"]["name"] == "Prueba")
    info2 = describe_import(kind2, obj2)
    check("describe_import: payload sin version nueva ni vencimiento",
          info2["config"]["version_too_new"] is False
          and info2["expired"] is False)
    # El sobre GCM con tag alterado no debe abrir.
    bad = payload_decrypt(link[:-4] + "AAAA")
    check("payload_decrypt: tag alterado -> None", bad is None)
    # Texto invalido.
    kind3, obj3 = import_text("esto no es un enlace ni un blob")
    check("import_text: basura -> invalid",
          kind3 == "invalid" and obj3 is None)
    # Blob sza sin qr_expiration: abre pero la app lo rechazaria (se avisa
    # en seal-settings; aqui solo se verifica que descifra).
    blob2 = sza_encrypt(SZA_KEY, SZA_IV, json.dumps({"type": "config"}))
    kind4, obj4 = import_text(blob2)
    check("import_text: blob sin qr_expiration abre (app lo rechazaria)",
          kind4 == "config" and obj4 == {"type": "config"})
    print("SELF-TEST: %s" % ("TODO OK" if ok else "HUBO FALLOS"))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EUT VPN 2.4.1 - archivos, enlaces y nube (SP-DECODE)")
    ap.add_argument("--file", help="archivo de texto con el enlace o blob")
    ap.add_argument("--link", help="enlace o blob pegado")
    ap.add_argument("--seal-settings", metavar="JSON",
                    help="crear un enlace eut-settings:// desde un JSON")
    ap.add_argument("--seal-payload", metavar="JSON",
                    help="crear un enlace eut-payload:// v1 desde un JSON "
                         "custom_payload")
    ap.add_argument("--cloud-get", metavar="CODE",
                    help="descargar un blob compartido por su codigo")
    ap.add_argument("--cloud-create", action="store_true",
                    help="compartir un blob en la nube (con --blob y "
                         "--expiration)")
    ap.add_argument("--blob", help="texto a compartir en la nube")
    ap.add_argument("--expiration",
                    help="expiracion del share ('yyyy-MM-dd HH:mm:ss')")
    ap.add_argument("--community", action="store_true",
                    help="marcar el share como community submission")
    ap.add_argument("--token", help="access_token (init-session)")
    ap.add_argument("--out", help="guardar el resultado en un archivo")
    ap.add_argument("--self-test", action="store_true",
                    help="pruebas internas")
    args = ap.parse_args(argv)
    if args.self_test:
        return _cmd_self_test()
    if args.seal_settings:
        return _cmd_seal_settings(args)
    if args.seal_payload:
        return _cmd_seal_payload(args)
    if args.cloud_get:
        return _cmd_cloud_get(args)
    if args.cloud_create:
        return _cmd_cloud_create(args)
    if args.file or args.link:
        return _cmd_open(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
