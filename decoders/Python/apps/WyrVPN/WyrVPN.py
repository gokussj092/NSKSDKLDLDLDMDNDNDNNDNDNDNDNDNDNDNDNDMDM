#!/usr/bin/env python3
"""WyrVPN - Free VPN Proxy (com.wyrhub.vpn) 2.6.9 (build 473) - catalogo en vivo.

Metodo (verificado en vivo 2026-11-14):
  POST https://wyrhub.xyz/wyrvpn/api/v1/
    cuerpo: {"data": <sobre v01>} con User-Agent Dalvik y Content-Type application/json.
    El sobre v01 es: Base64("v01" || nonce[12] || AES-128-GCM(ct || tag)).
    Peticion cifrada con REQ_KEY, respuesta cifrada con RESP_KEY (ambas de 16 B,
    constantes de formato de la app; viven solo en este script).
  Peticion JSON: {"action":"sync","schema":21,"app_version":473,
    "hardware_id":<32 hex en mayusculas>,"country_code":"ZZ","nonce":<uuid>,
    "timestamp":<unix>,"fetch":["SERVER","PAYLOAD"],
    "known":{"SERVER":[],"PAYLOAD":[]},
    "documents":{"SERVER":"","PAYLOAD":"","SETTING":"","ANNOUNCEMENT":"",
                 "BLOCK_APP":"","CUSTOM_PAYLOAD":""}}.
  Respuesta JSON: {"data": <sobre v01 con RESP_KEY>} -> {"ok":true,"schema":21,
    "status":"ok","resources":{"SERVER":{...},"PAYLOAD":{...}},
    "documents":{"ANNOUNCEMENT":...,"BLOCK_APP":...,"SETTING":...},
    "nonce":<uuid>,"update":null,"updates":{...}}.

En vivo (verificado 2026-11-14): schema 21, 523 servidores (meta v7.5.0.3) y
1.225 payloads/tweaks (meta v2.4.3.0). Casi todos los campos estan en claro
(hosts, configs OpenVPN, puertos, v2ray_json). Excepciones documentadas:
  - Sobres v01 internos: si una entrada del catalogo trae un campo cifrado
    como sobre v01 (Base64 que empieza por 'djAx'), readable_catalog() lo
    descifra (REQ_KEY y luego RESP_KEY) antes de escribir la salida; los
    que no abren se dejan tal cual y se cuentan en
    inner_envelopes_failed (regla SP-DECODE 2026-11-15: el JSON de
    resultado va totalmente descifrado). En el catalogo de 2026-11-14 no
    hay sobres v01 internos (0 en la muestra viva); los unicos valores
    Base64 largos sin abrir son 2 payloads http binarios (PAYLOAD 240 y
    466) que la propia app usa tal cual (custom=false) y que no abren
    como GCM con ninguna de las dos claves: se dejan tal cual, sin
    inventar su contenido.
  - ovpn_username / ovpn_password: 459 de 523 servidores los traen vacios y
    64 traen un valor de 32 caracteres hexadecimales. La app los usa tal cual
    (su getOvpn_password/getOvpn_username solo los transforma si empiezan por
    "_func" o si contienen los marcadores rand_upper/rand_lower/rand_num/
    rand_special; en este catalogo no hay ningun valor _func ni ningun
    marcador). Se presentan con estado AS_STORED. Si un catalogo futuro
    trajera valores "_func(...)", esos se resuelven por reflexion en la clase
    com.wyrhub.vpn.utils.Algo (paso nativo) y el script los marcaria
    FUNC_PENDING sin inventar su contenido.
  - ssh_username / ssh_password: 34 servidores traen el literal "PROTECTED"
    (credenciales del lado del servidor, no disponibles en el catalogo).

Python 3.10+, solo biblioteca estandar. AES-128/256-GCM en Python puro
(nucleo adaptado del script SP-DECODE de TSC VPN Proxy / RNV Tunnel VPN).
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid

REQ_KEY = b"84EE1C1019099C62"
RESP_KEY = b"5AC9D759DB6A3B60"
URL = "https://wyrhub.xyz/wyrvpn/api/v1/"
UA = "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8)"
APP_VERSION = 473
SCHEMA = 21


class DecodeError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- AES-128/256-GCM
# Python puro. Solo se necesita cifrado de bloques (GCM usa CTR + GHASH).
def _make_sbox():
    sbox = []
    for i in range(256):
        if i == 0:
            inv = 0
        else:
            inv = None
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
        s = inv ^ ((inv << 1) | (inv >> 7)) ^ ((inv << 2) | (inv >> 6)) \
            ^ ((inv << 3) | (inv >> 5)) ^ ((inv << 4) | (inv >> 4)) ^ 0x63
        sbox.append(s & 0xFF)
    return sbox


_SBOX = _make_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]
_GCM_R = 0xE1000000000000000000000000000000


def _aes_key_expand(key):
    """Expansion de clave AES. Devuelve (palabras, rondas). Acepta 16/24/32 B."""
    if len(key) not in (16, 24, 32):
        raise ValueError("clave AES de 16, 24 o 32 bytes")
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            sub = (_SBOX[(rot >> 24) & 0xFF] << 24) | (_SBOX[(rot >> 16) & 0xFF] << 16) \
                | (_SBOX[(rot >> 8) & 0xFF] << 8) | _SBOX[rot & 0xFF]
            temp = sub ^ (_RCON[i // nk - 1] << 24)
        elif nk > 6 and i % nk == 4:
            temp = (_SBOX[(temp >> 24) & 0xFF] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) \
                | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
        w.append(w[i - nk] ^ temp)
    return w, nr


def _aes_encrypt_block(key_words, nr, block):
    s = list(struct.unpack(">4I", block))
    rk = key_words
    for i in range(4):
        s[i] ^= rk[i]
    for rnd in range(1, nr):
        b = bytearray(16)
        for i in range(4):
            for j in range(4):
                b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
        sb = bytearray(16)
        for r in range(4):
            for c in range(4):
                sb[4 * c + r] = b[4 * ((c + r) % 4) + r]

        def xtime(x):
            return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF
        out = [0] * 4
        for c in range(4):
            a0, a1, a2, a3 = sb[4 * c], sb[4 * c + 1], sb[4 * c + 2], sb[4 * c + 3]
            out[c] = (xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3) << 24 \
                | (a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3) << 16 \
                | (a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)) << 8 \
                | ((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3))
        s = out
        for i in range(4):
            s[i] ^= rk[4 * rnd + i]
    b = bytearray(16)
    for i in range(4):
        for j in range(4):
            b[4 * j + i] = _SBOX[(s[j] >> (24 - 8 * i)) & 0xFF]
    sb = bytearray(16)
    for r in range(4):
        for c in range(4):
            sb[4 * c + r] = b[4 * ((c + r) % 4) + r]
    s = list(struct.unpack(">4I", bytes(sb)))
    for i in range(4):
        s[i] ^= rk[4 * nr + i]
    return struct.pack(">4I", *s)


def _gf_mul(x, y):
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
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def _aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    """AES-GCM decrypt (Python puro). nonce: 12 bytes. tag: 16 bytes."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    pt = bytearray()
    counter = 1
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        pt += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(ciphertext)
               + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    calc_tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if calc_tag != tag:
        raise ValueError("GCM tag mismatch")
    return bytes(pt)


def _aes_gcm_encrypt(key, nonce, plaintext, aad=b""):
    """AES-GCM encrypt (Python puro). Devuelve (ciphertext, tag)."""
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    kw, nr = _aes_key_expand(key)
    h = int.from_bytes(_aes_encrypt_block(kw, nr, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i + 16]
        ctr = nonce + struct.pack(">I", counter + 1)
        ks = _aes_encrypt_block(kw, nr, ctr)
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
        counter += 1

    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    s = _ghash(h, pad16(aad) + pad16(bytes(ct))
               + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
    ej0 = _aes_encrypt_block(kw, nr, j0)
    tag = (s ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    return bytes(ct), tag


# ------------------------------------------------------------ sobre v01
def v01_encrypt(plain, key):
    """Sobre v01: Base64("v01" || nonce[12] || AES-GCM(ct || tag))."""
    nonce = os.urandom(12)
    ct, tag = _aes_gcm_encrypt(key, nonce, plain)
    return base64.b64encode(b"v01" + nonce + ct + tag).decode()


def v01_decrypt(b64, key):
    """Abre un sobre v01 -> bytes. Lanza DecodeError si el tag no verifica."""
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception as exc:
        raise DecodeError("V01_BASE64", "sobre v01 con Base64 invalido") from exc
    if len(raw) < 3 + 12 + 16 or raw[:3] != b"v01":
        raise DecodeError("V01_MAGIC", "el sobre no empieza por 'v01'")
    try:
        return _aes_gcm_decrypt(key, raw[3:15], raw[15:-16], raw[-16:])
    except ValueError as exc:
        raise DecodeError("V01_TAG", "el tag GCM no verifica con esta clave") from exc


# ------------------------------------------------------------ peticion sync
def build_req(hwid):
    docs = {t: "" for t in ["SERVER", "PAYLOAD", "SETTING", "ANNOUNCEMENT",
                            "BLOCK_APP", "CUSTOM_PAYLOAD"]}
    return {
        "action": "sync", "schema": SCHEMA, "app_version": APP_VERSION,
        "hardware_id": hwid, "country_code": "ZZ", "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()), "fetch": ["SERVER", "PAYLOAD"],
        "known": {"SERVER": [], "PAYLOAD": []}, "documents": docs,
    }


def derive_hwid(android_id):
    """HWID como lo deriva la app: SHA-256 del Android ID, hex en mayusculas,
    primeros 32 caracteres."""
    return hashlib.sha256(android_id.encode()).hexdigest().upper()[:32]


def fetch_live(hwid, retries=3):
    """Descarga el catalogo en vivo. Devuelve (texto_crudo, dict_descifrado).
    Reintenta hasta 3 veces si la conexion se corta a mitad de la respuesta
    (el servidor a veces trunca el cuerpo; la peticion es idempotente)."""
    last_exc = None
    for attempt in range(1, retries + 1):
        req = build_req(hwid)
        body = json.dumps({"data": v01_encrypt(json.dumps(req).encode(), REQ_KEY)}).encode()
        request = urllib.request.Request(
            URL, data=body,
            headers={"User-Agent": UA, "Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(request, timeout=60) as resp:
                raw = resp.read().decode()
                status = resp.status
            break
        except urllib.error.HTTPError as exc:
            raise DecodeError("HTTP_%d" % exc.code,
                              "el servidor respondio HTTP %d" % exc.code) from exc
        except Exception as exc:  # IncompleteRead, URLError, timeout...
            last_exc = exc
            if attempt < retries:
                time.sleep(2 * attempt)
                continue
            raise DecodeError("RED",
                              "no se pudo descargar el catalogo tras %d intentos: %s"
                              % (retries, exc)) from exc
    if status != 200:
        raise DecodeError("HTTP_%d" % status, "el servidor respondio HTTP %d" % status)
    try:
        envelope = json.loads(raw)
        pt = v01_decrypt(envelope["data"], RESP_KEY)
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("RESPUESTA", "la respuesta no es el JSON esperado: %s" % exc) from exc
    return raw, json.loads(pt)


def decode_response(raw_text):
    """Descifra una respuesta guardada (texto JSON con {"data": sobre v01})."""
    envelope = json.loads(raw_text)
    return json.loads(v01_decrypt(envelope["data"], RESP_KEY))


# ------------------------------------------------------------ lectura
_FUNC_PREFIX = "_func"
_RAND_MARKERS = ("rand_upper", "rand_lower", "rand_num", "rand_special")


def _cred_status(value):
    """Estado de una credencial OVPN segun la logica de la app (Server.java):
    la app la usa tal cual salvo que empiece por "_func" (entonces la resuelve
    por reflexion en com.wyrhub.vpn.utils.Algo) o que contenga marcadores
    rand_* (entonces sustituye cada marcador por un caracter aleatorio)."""
    if value is None or value == "":
        return "EMPTY"
    if value.startswith(_FUNC_PREFIX):
        return "FUNC_PENDING"
    if any(m in value for m in _RAND_MARKERS):
        return "TEMPLATE_RANDOM"
    return "AS_STORED"


def _decrypt_inner(obj, stats):
    """Recorre un valor (dict/list/str) y descifra los sobres v01 internos
    (cadenas Base64 que empiezan por 'djAx', el Base64 de 'v01'). Prueba
    REQ_KEY y luego RESP_KEY. Los que no abren con ninguna clave se dejan
    tal cual y se cuentan en stats['failed'] (no se inventa su contenido).
    Regla SP-DECODE 2026-11-15: el JSON de resultado lleva los datos del
    catalogo totalmente descifrados, sin sobres cifrados dentro."""
    if isinstance(obj, dict):
        return {k: _decrypt_inner(v, stats) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decrypt_inner(v, stats) for v in obj]
    if isinstance(obj, str) and obj.startswith("djAx"):
        for key in (REQ_KEY, RESP_KEY):
            try:
                stats["decrypted"] += 1
                return v01_decrypt(obj, key).decode("utf-8")
            except DecodeError:
                continue
        stats["failed"] += 1
    return obj


def readable_catalog(data):
    """Catalogo descifrado -> forma legible con estados por servidor.
    Los sobres v01 internos de las entradas (si los hay) se descifran
    aqui: la salida ya sale totalmente descifrada."""
    stats = {"decrypted": 0, "failed": 0}
    out = {
        "ok": data.get("ok"),
        "schema": data.get("schema"),
        "status": data.get("status"),
        "nonce": data.get("nonce"),
        "update": data.get("update"),
        "updates": data.get("updates"),
        "documents": _decrypt_inner(data.get("documents"), stats),
        "resources": {},
    }
    func_pending = 0
    for kind, res in (data.get("resources") or {}).items():
        entries = []
        for item in res.get("add", []):
            item = _decrypt_inner(dict(item), stats)
            if kind == "SERVER":
                for field in ("ovpn_username", "ovpn_password"):
                    st = _cred_status(item.get(field))
                    item[field + "_status"] = st
                    if st == "FUNC_PENDING":
                        func_pending += 1
                if item.get("ssh_username") == "PROTECTED" \
                        or item.get("ssh_password") == "PROTECTED":
                    item["ssh_credentials_status"] = "PROTECTED_BY_VENDOR"
            entries.append(item)
        out["resources"][kind] = {
            "total": res.get("total"),
            "meta": res.get("meta"),
            "entries": entries,
            "removed": res.get("remove", []),
        }
    out["func_pending_count"] = func_pending
    out["inner_envelopes_decrypted"] = stats["decrypted"]
    out["inner_envelopes_failed"] = stats["failed"]
    return out


def summarize(readable):
    lines = []
    lines.append("WyrVPN 2.6.9 (build 473) - catalogo schema %s, ok=%s, status=%s"
                 % (readable.get("schema"), readable.get("ok"), readable.get("status")))
    for kind, res in readable["resources"].items():
        meta = res.get("meta") or {}
        lines.append("  %s: %d entradas (meta v%s, %s)"
                     % (kind, len(res["entries"]), meta.get("version_name"),
                        meta.get("date")))
    docs = readable.get("documents") or {}
    for name, doc in docs.items():
        if isinstance(doc, dict):
            data = doc.get("data")
            lines.append("  documento %s: %s"
                         % (name, len(data) if isinstance(data, list) else data))
    if readable.get("func_pending_count"):
        lines.append("  AVISO: %d credenciales _func(...) pendientes "
                     "(necesitan el paso Algo nativo, bloqueado)"
                     % readable["func_pending_count"])
    return "\n".join(lines)


# ------------------------------------------------------------ self-test
def _self_test():
    checks = []

    def check(name, fn):
        try:
            fn()
            checks.append((name, True, ""))
        except Exception as exc:  # noqa: BLE001
            checks.append((name, False, "%s: %s" % (type(exc).__name__, exc)))

    def t_gcm128_roundtrip():
        key = bytes(range(16))
        nonce = bytes(range(12))
        pt = b"hola wyrvpn" * 10
        ct, tag = _aes_gcm_encrypt(key, nonce, pt, b"aad")
        assert _aes_gcm_decrypt(key, nonce, ct, tag, b"aad") == pt

    def t_gcm256_roundtrip():
        key = bytes(range(32))
        nonce = os.urandom(12)
        pt = os.urandom(1000)
        ct, tag = _aes_gcm_encrypt(key, nonce, pt)
        assert _aes_gcm_decrypt(key, nonce, ct, tag) == pt

    def t_gcm_tag_tamper():
        key = bytes(range(16))
        nonce = bytes(range(12))
        ct, tag = _aes_gcm_encrypt(key, nonce, b"secreto")
        bad = bytearray(ct)
        bad[0] ^= 1
        try:
            _aes_gcm_decrypt(key, nonce, bytes(bad), tag)
        except ValueError:
            return
        raise AssertionError("el tag alterado no fue rechazado")

    def t_gcm_oracle():
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            return  # sin el oraculo instalado, el round-trip ya cubre el caso
        for klen in (16, 32):
            key = os.urandom(klen)
            nonce = os.urandom(12)
            pt = os.urandom(200)
            aad = os.urandom(7)
            ct1 = AESGCM(key).encrypt(nonce, pt, aad)
            ct2, tag2 = _aes_gcm_encrypt(key, nonce, pt, aad)
            assert ct1 == ct2 + tag2
            assert _aes_gcm_decrypt(key, nonce, ct1[:-16], ct1[-16:], aad) == pt

    def t_v01_roundtrip():
        enc = v01_encrypt(b'{"ok":true}', REQ_KEY)
        assert v01_decrypt(enc, REQ_KEY) == b'{"ok":true}'
        try:
            v01_decrypt(enc, RESP_KEY)
        except DecodeError:
            return
        raise AssertionError("la clave equivocada abrio el sobre")

    def t_live_sample():
        here = os.path.dirname(os.path.abspath(__file__))
        sample = os.path.join(here, "catalog_sample.json")
        if not os.path.exists(sample):
            return  # sin la muestra, el resto del self-test ya cubre el metodo
        with open(sample, encoding="utf-8") as fh:
            data = decode_response(fh.read())
        assert data.get("schema") == 21, data.get("schema")
        assert data.get("ok") is True
        servers = data["resources"]["SERVER"]["add"]
        payloads = data["resources"]["PAYLOAD"]["add"]
        assert len(servers) == 523, len(servers)
        assert len(payloads) == 1225, len(payloads)
        readable = readable_catalog(data)
        assert readable["func_pending_count"] == 0
        n_hex = sum(1 for s in servers if s.get("ovpn_password"))
        assert n_hex == 64, n_hex
        # salida totalmente descifrada (regla 2026-11-15): ningun sobre v01
        # interno puede quedar en la salida legible
        def _walk(o):
            if isinstance(o, dict):
                for v in o.values():
                    yield from _walk(v)
            elif isinstance(o, list):
                for v in o:
                    yield from _walk(v)
            elif isinstance(o, str):
                yield o
        left = [s for s in _walk(readable) if s.startswith("djAx")]
        assert not left, "quedaron %d sobres v01 sin descifrar" % len(left)
        assert readable["inner_envelopes_failed"] == 0
        assert len(readable["resources"]["SERVER"]["entries"]) == 523
        assert len(readable["resources"]["PAYLOAD"]["entries"]) == 1225

    def t_cred_status():
        assert _cred_status("") == "EMPTY"
        assert _cred_status(None) == "EMPTY"
        assert _cred_status("c07242958b9b") == "AS_STORED"
        assert _cred_status("_funcFoo('x')") == "FUNC_PENDING"
        assert _cred_status("abrand_uppercd") == "TEMPLATE_RANDOM"

    check("aes128-gcm round-trip", t_gcm128_roundtrip)
    check("aes256-gcm round-trip", t_gcm256_roundtrip)
    check("gcm tag alterado rechazado", t_gcm_tag_tamper)
    check("aes-gcm contra oraculo PyCryptodome/cryptography", t_gcm_oracle)
    check("sobre v01 round-trip + clave equivocada", t_v01_roundtrip)
    check("muestra viva: schema 21, 523 servidores, 1225 payloads", t_live_sample)
    check("estados de credenciales OVPN", t_cred_status)
    failed = [c for c in checks if not c[1]]
    for name, ok, err in checks:
        print(("OK  " if ok else "FAIL") + " " + name + ((" - " + err) if err else ""))
    print("SELF-TEST: %d/%d OK" % (len(checks) - len(failed), len(checks)))
    return 0 if not failed else 1


# ------------------------------------------------------------ CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="WyrVPN 2.6.9 - descarga y descifra el catalogo en vivo.")
    ap.add_argument("--url", action="store_true",
                    help="descargar el catalogo en vivo (POST a wyrhub.xyz)")
    ap.add_argument("--raw", metavar="ARCHIVO",
                    help="descifrar una respuesta guardada (JSON con sobre v01)")
    ap.add_argument("--hwid", metavar="HWID",
                    help="hardware id, 32 hex en mayusculas (por defecto: aleatorio)")
    ap.add_argument("--android-id", metavar="ID",
                    help="derivar el HWID como SHA-256(ID) en mayusculas, [:32]")
    ap.add_argument("--out", metavar="ARCHIVO",
                    help="guardar el catalogo legible (JSON) en ARCHIVO")
    ap.add_argument("--self-test", action="store_true",
                    help="pruebas internas (sin red salvo el oraculo opcional)")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.raw:
        with open(args.raw, encoding="utf-8") as fh:
            data = decode_response(fh.read())
    elif args.url:
        if args.hwid:
            hwid = args.hwid.strip().upper()
        elif args.android_id:
            hwid = derive_hwid(args.android_id)
        else:
            hwid = os.urandom(16).hex().upper()
        _raw, data = fetch_live(hwid)
    else:
        ap.error("usa --url para descargar en vivo o --raw ARCHIVO para una muestra")

    readable = readable_catalog(data)
    print(summarize(readable))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(readable, fh, ensure_ascii=False, indent=2)
        print("guardado en %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
