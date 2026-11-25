#!/usr/bin/env python3
"""
TOP PLUG SA VPN — decodificador de catálogo y archivos .tpc para SP-DECODE.

App: TOP PLUG SA VPN (TOP-PLUG-SA)
Paquete: mobi.ascensionrpg.khonavpn.activationtest
Versión analizada: 0.29.26 (code 89) — APK TOP-PLUG-SA-v02926.apk
  SHA-256: fe3e03b1725fd489688abac1ddfc7200da83f94530db515d26b9e1906779c0b4

Qué hace este script
--------------------
1. Catálogo vivo (público, sin login): descarga los 3 JSON públicos de
   https://ascensionrpg.mobi (contact/plans/notices) tal cual los pide la app
   (GET, Accept: application/json, sin redirects, timeout 3.5 s).
   El refresh del perfil gratuito "Free 50mb mtn" vive en
   topplug-contact.json -> bootstrap_50mb (sobre firmado TOPPLUG-50MB-V1).
   A 2026-11-24 el JSON en vivo NO trae bootstrap_50mb: el perfil vigente
   sigue siendo el revision 1 incluido en el APK (assets/fiftymb-default.json).
2. Sobre 50MB: verifica la firma ECDSA P-256 y descifra el perfil SSH
   (AES-CBC, clave derivada de d2.g()).
3. Archivos .tpc (la app importa/exporta .tpc en la carpeta "TOP PLUG SA"):
   - TOPPLUG4  (portable v4): AES-256-GCM, clave = d2.g() (32 B fijos del APK),
     AAD "TOPPLUG-PORTABLE-V4\n", nonce 12 B. VERIFIED_REAL con el archivo
     de ejemplo del APK (assets/activation-helper.tpc).
   - TOPPLUG5  (con contraseña v5): PBKDF2-HMAC-SHA256 (600000 iter, 256 bit)
     con salt 16 B, AES-256-GCM, AAD "TOPPLUG-PASSWORD-V5\n"; el contenido
     es un archivo TOPPLUG4. Requiere la contraseña del archivo.
   - TOPPLUG1  (firmado offline v2): "TOPPLUG1\\n<hex-firma>\\n<JSON>", firma
     ECDSA sobre "TOPPLUG-OFFLINE-V1\\n"+JSON con la clave del issuer.
   - TOPPLUG2  (sellado v3): "TOPPLUG2\\n<hex-firma>\\n<JSON>", firma ECDSA
     sobre "TOPPLUG-SEALED-V3\\n"+JSON. El perfil va cifrado con una clave
     que solo se abre con la clave RSA del KeyStore del teléfono dueño
     (device-bound): este script verifica la firma y muestra los metadatos,
     pero NO puede descifrar el perfil sin ese teléfono.
   - TOPPLUG-MANUAL-V2: "TOPPLUG-MANUAL-V2\\n<JSON>" en claro.
   Perfiles: trojan / vless / ssh (ssh_mode: direct_proxy, direct_tls,
   http_proxy, tls_proxy, tls_http_proxy; network tcp/ws).

Servidor de entrega (planes por dispositivo, solo referencia — requiere
registro del dispositivo con su clave RSA del KeyStore):
   https://esocs.info:8444/v1/device-plan/<register|challenge|...>

Uso:
  python3 topplugsa.py fetch [--out catalog.json]
  python3 topplugsa.py 50mb <fiftymb-default.json | sobre.json>
  python3 topplugsa.py tpc <archivo.tpc> [--password CLAVE]
  python3 topplugsa.py self-test
  python3 topplugsa.py <archivo.tpc>   (modo directo del worker: la
    contraseña llega por stdin como JSON {"password": ...}; sin
    contraseña, un TOPPLUG5 devuelve {"workerError": "PASSWORD_REQUIRED"}
    por stdout con código de salida 3)

Adaptación al repo (2026-11-24, integración FILE_ONLY, CATALOG 99):
  la lógica de descifrado es la del script de análisis, sin reescribir
  algoritmos. Solo se añade el adaptador del worker (`decode`/`run`,
  errores con código, modo directo por archivo) y el self-test salta
  (no falla) las comprobaciones que necesitan la muestra real del APK
  — no incluida en el repo porque lleva credenciales — o red.
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Util.asn1 import DerSequence

APP_PACKAGE = "mobi.ascensionrpg.khonavpn.activationtest"
APP_VERSION = "0.29.26"
BASE = "https://ascensionrpg.mobi"
PUBLIC_JSONS = {
    "contact": BASE + "/topplug-contact.json",
    "plans": BASE + "/topplug-plans.json",
    "notices": BASE + "/topplug-notices.json",
}
DELIVERY_BASE = "https://esocs.info:8444"  # /v1/device-plan/* (registro por dispositivo)

# Tamaño máximo de un .tpc (el mismo tope que aplica decrypt_tpc al texto).
MAX_BYTES = 65536

# --- Claves extraídas del APK (estáticas, no son secretos de usuario) -------
# d2.g(): material de 32 B = XOR de dos hex del APK.
_D2G_A = bytes.fromhex("8eb68e2c7c533488c550e0a87988cce8ddb88b34b3e5b57732422e1ca837b190")
_D2G_B = bytes.fromhex("415854f408eeb8a7dba6bd3c957f92cc2697f61e4354edfa913ee2a866925e9c")
# assets/fiftymb-public.der — P-256, clave del sobre 50MB (DER, base64).
_FIFTYMB_PUB_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElOLszID9VsXnimbeNOPtACOl35"
    "uYDDJ2rY0xSVZMmRrHLcVR+5na2Nzum+IxgdCuAEDf7CLFjGLEULJSCLZFyA=="
)
# assets/offline/issuer-public.der — P-256, clave del issuer .tpc (DER, base64).
_ISSUER_PUB_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcZa5LVH9W8Z/oxphEHMjPBHQNa"
    "ytYNtteC2T2ICnBUo4Epl73PmQ0gSDWb9TmD6kJNITq6MKusxbocG03i4hKg=="
)


def d2g():
    """Material de clave de 32 B (b/d2.java)."""
    return bytes(a ^ b for a, b in zip(_D2G_A, _D2G_B))


class TopPlugDecodeError(ValueError):
    """Fallo de descifrado con código del contrato del worker.

    Códigos: PASSWORD_REQUIRED (TOPPLUG5 sin contraseña),
    INVALID_CREDENTIALS (contraseña de menos de 12 caracteres),
    AUTH_FAILED (contraseña incorrecta o datos alterados: indistinguibles),
    DECODE_FAILED (cualquier otro archivo no abrible).
    """

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _b64d(s):
    if isinstance(s, str):
        s = s.encode("ascii")
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw) != s:
        raise ValueError("base64 no canónico")
    return raw


def _ecdsa_verify(pub_der, message, sig_der):
    """Verifica una firma ECDSA SHA-256 en formato DER (como Java)."""
    key = ECC.import_key(pub_der)
    h = SHA256.new(message)
    der = DerSequence()
    der.decode(sig_der)
    r, s = int(der[0]), int(der[1])
    DSS.new(key, "fips-186-3").verify(h, r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _unpad_pkcs7(data):
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("padding PKCS7 inválido")
    return data[:-pad]


# ---------------------------------------------------------------- catálogo vivo
def fetch_live(timeout=3.5):
    """Descarga los 3 JSON públicos tal cual los pide la app (GET, sin redirects)."""
    out = {}
    for name, url in PUBLIC_JSONS.items():
        # La app limita contact.json a 2048 B; plans/notices no tienen ese tope.
        limit = 2048 if name == "contact" else 65536
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10)",
        })
        opener = urllib.request.build_opener(NoRedirect())
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(limit + 1)
                if len(raw) > limit:
                    raise ValueError("respuesta mayor a %d bytes" % limit)
                out[name] = {"http": resp.status, "json": json.loads(raw.decode("utf-8"))}
        except urllib.error.HTTPError as e:
            out[name] = {"http": e.code, "error": str(e)}
        except Exception as e:  # noqa: BLE001 - reportar como fallo, no inventar
            out[name] = {"http": None, "error": str(e)}
    return out


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ------------------------------------------------------------- sobre 50MB (V1)
def decrypt_50mb(envelope):
    """Verifica la firma y descifra un sobre TOPPLUG-50MB-V1.

    envelope: dict {version:1, revision:int, body:str(b64), signature:str(b64)}.
    Devuelve el JSON interno {revision, enabled, profile:{...}}.
    """
    if envelope.get("version") != 1:
        raise ValueError("sobre 50MB: version != 1")
    revision = envelope["revision"]
    if not isinstance(revision, int) or revision < 1:
        raise ValueError("sobre 50MB: revision inválida")
    body_b64 = envelope["body"]
    sig = _b64d(envelope["signature"])
    if len(sig) > 128:
        raise ValueError("sobre 50MB: firma inválida")
    pub_der = base64.b64decode(_FIFTYMB_PUB_B64)
    _ecdsa_verify(pub_der,
                  ("TOPPLUG-50MB-V1\n%d\n%s\n" % (revision, body_b64)).encode("utf-8"),
                  sig)
    raw = _b64d(body_b64)
    if len(raw) < 32 or len(raw) % 16 != 0:
        raise ValueError("sobre 50MB: cuerpo inválido")
    iv, ct = raw[:16], raw[16:]
    key = hashlib.sha256(b"TOPPLUG-50MB-ENCRYPTION-V1\n" + d2g()).digest()
    pt = _unpad_pkcs7(AES.new(key, AES.MODE_CBC, iv).decrypt(ct))
    inner = json.loads(pt.decode("utf-8"))
    if inner.get("revision") != revision or not isinstance(inner.get("enabled"), bool):
        raise ValueError("sobre 50MB: estado interno inválido")
    return inner


# ------------------------------------------------------------------ archivos .tpc
def _gcm_decrypt(key, nonce, ct_with_tag, aad):
    if len(key) != 32 or len(nonce) != 12 or len(ct_with_tag) < 16:
        raise ValueError("parámetros GCM inválidos")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct_with_tag[:-16], ct_with_tag[-16:])


def _parse_tpc1(text, issuer_der):
    """TOPPLUG1: TOPPLUG1\\n<hex-firma>\\n<JSON> — firmado, perfil en claro."""
    nl1 = text.index("\n")
    nl2 = text.index("\n", nl1 + 1)
    sig = bytes.fromhex(text[nl1 + 1:nl2])
    if not 64 <= len(sig) <= 80:
        raise ValueError("TOPPLUG1: firma inválida")
    body = text[nl2 + 1:]
    _ecdsa_verify(issuer_der, ("TOPPLUG-OFFLINE-V1\n" + body).encode("utf-8"), sig)
    doc = json.loads(body)
    if doc.get("format") != "topplug" or doc.get("version") != 2:
        raise ValueError("TOPPLUG1: versión no soportada")
    return {"kind": "signed-offline-v2", "id": doc["id"], "name": doc.get("name"),
            "issued_at": doc.get("issued_at"), "expires_at": doc.get("expires_at"),
            "device_id": doc.get("device_id", ""), "device_locked": bool(doc.get("device_id")),
            "profile": doc["profile"]}


def _parse_tpc2(text, issuer_der):
    """TOPPLUG2: TOPPLUG2\\n<hex-firma>\\n<JSON> — sellado v3 (device-bound)."""
    nl1 = text.index("\n")
    nl2 = text.index("\n", nl1 + 1)
    sig_hex = text[nl1 + 1:nl2]
    if not (128 <= len(sig_hex) <= 160 and len(sig_hex) % 2 == 0):
        raise ValueError("TOPPLUG2: firma inválida")
    sig = bytes.fromhex(sig_hex)
    body = text[nl2 + 1:]
    _ecdsa_verify(issuer_der, ("TOPPLUG-SEALED-V3\n" + body).encode("utf-8"), sig)
    doc = json.loads(body)
    if doc.get("format") != "topplug" or doc.get("version") != 3:
        raise ValueError("TOPPLUG2: versión no soportada")
    return {"kind": "sealed-v3-device-bound", "id": doc["id"], "name": doc.get("name"),
            "issued_at": doc.get("issued_at"), "expires_at": doc.get("expires_at"),
            "device_id": doc.get("device_id", ""), "device_locked": bool(doc.get("device_id")),
            "profile": None,
            "note": "Perfil cifrado con clave ligada al teléfono dueño "
                    "(KeyStore RSA topplug_delivery_rsa_v1): no se puede "
                    "descifrar fuera de ese teléfono. Metadatos y firma verificados."}


def _parse_tpc4(text):
    """TOPPLUG4: TOPPLUG4\\n<base64> — portable v4, AES-256-GCM con d2.g()."""
    blob = _b64d(text[len("TOPPLUG4\n"):])
    if len(blob) < 29:
        raise ValueError("TOPPLUG4: archivo demasiado corto")
    nonce, ct = blob[:12], blob[12:]
    pt = _gcm_decrypt(d2g(), nonce, ct, b"TOPPLUG-PORTABLE-V4\n")
    doc = json.loads(pt.decode("utf-8"))
    if doc.get("format") != "topplug" or doc.get("version") != 4:
        raise ValueError("TOPPLUG4: versión no soportada")
    return {"kind": "portable-v4", "id": doc["id"], "name": doc.get("name"),
            "issued_at": doc.get("issued_at"), "expires_at": doc.get("expires_at"),
            "device_id": doc.get("device_id", ""), "device_locked": bool(doc.get("device_id")),
            "file_locked": doc.get("locked"), "profile": doc["profile"]}


def _parse_tpc5(text, password):
    """TOPPLUG5: TOPPLUG5\\n<base64> — con contraseña (PBKDF2 600k) -> TOPPLUG4."""
    if password is None:
        raise ValueError("TOPPLUG5: este archivo necesita contraseña (--password)")
    if len(password.encode("utf-8")) < 12:
        raise ValueError("TOPPLUG5: la contraseña tiene al menos 12 caracteres")
    blob = _b64d(text[len("TOPPLUG5\n"):])
    if len(blob) < 45:
        raise ValueError("TOPPLUG5: archivo demasiado corto")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=600000,
                 hmac_hash_module=SHA256)
    pt = _gcm_decrypt(key, nonce, ct, b"TOPPLUG-PASSWORD-V5\n")
    inner = pt.decode("utf-8")
    if not inner.startswith("TOPPLUG4\n"):
        raise ValueError("TOPPLUG5: contenido interno inválido")
    out = _parse_tpc4(inner)
    out["kind"] = "password-v5"
    out["password_file"] = True
    return out


def decrypt_tpc(text, password=None):
    """Descifra/verifica un archivo .tpc según su cabecera. Devuelve dict."""
    if len(text.encode("utf-8")) > 65536:
        raise ValueError("archivo .tpc demasiado grande")
    issuer_der = base64.b64decode(_ISSUER_PUB_B64)
    if text.startswith("TOPPLUG4\n"):
        return _parse_tpc4(text)
    if text.startswith("TOPPLUG5\n"):
        return _parse_tpc5(text, password)
    if text.startswith("TOPPLUG1\n"):
        return _parse_tpc1(text, issuer_der)
    if text.startswith("TOPPLUG2\n"):
        return _parse_tpc2(text, issuer_der)
    if text.startswith("TOPPLUG-MANUAL-V2\n"):
        doc = json.loads(text[len("TOPPLUG-MANUAL-V2\n"):])
        if doc.get("format") != "topplug" or doc.get("version") != 2:
            raise ValueError("MANUAL-V2: versión no soportada")
        return {"kind": "manual-v2", "id": None, "name": doc.get("name"),
                "issued_at": None, "expires_at": None, "device_id": "",
                "device_locked": False, "profile": doc["profile"]}
    raise ValueError("no es un archivo .tpc soportado "
                     "(TOPPLUG1/2/4/5 o TOPPLUG-MANUAL-V2)")


# ------------------------------------------------------- adaptador del worker
def decode(raw, password=None):
    """Entrada genérica del supplied_bridge: ``decode(raw, password=None)``.

    ``raw`` son los bytes del archivo .tpc. Devuelve el dict del perfil
    (para TOPPLUG2, metadatos con ``profile`` a None: el perfil es
    device-bound y nunca se devuelve). Los fallos son
    TopPlugDecodeError con código del contrato del worker.
    """
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise TopPlugDecodeError("DECODE_FAILED") from exc
    else:
        text = raw
    text = text.strip()
    if text.startswith("TOPPLUG5\n"):
        if password is None:
            raise TopPlugDecodeError("PASSWORD_REQUIRED")
        if len(password.encode("utf-8")) < 12:
            raise TopPlugDecodeError("INVALID_CREDENTIALS")
    try:
        return decrypt_tpc(text, password=password)
    except TopPlugDecodeError:
        raise
    except ValueError:
        if text.startswith("TOPPLUG5\n"):
            # Contraseña incorrecta y datos alterados son indistinguibles
            # (el tag GCM no verifica en ambos casos).
            raise TopPlugDecodeError("AUTH_FAILED")
        raise TopPlugDecodeError("DECODE_FAILED")


def run(data, password=None):
    """Devuelve el documento descifrado como JSON (str)."""
    return json.dumps(decode(data, password=password), ensure_ascii=False)


def _direct_file(path):
    """Modo directo del worker: ``python topplugsa.py <archivo.tpc>``.

    La contraseña, si la hay, llega por stdin como JSON
    (contrato del engine); nunca por argv, entorno o logs.
    """
    try:
        data = Path(path).read_bytes()
        if len(data) > MAX_BYTES + 1:
            raise TopPlugDecodeError("DECODE_FAILED")
        password = None
        if not sys.stdin.isatty():
            # Las credenciales, si las hay, llegan por stdin como JSON
            # (contrato del engine, que las escribe al arrancar el hijo).
            # No bloquear para siempre si stdin es una tubería abierta
            # sin datos: esperar como mucho 5 s y seguir sin contraseña.
            import select
            try:
                ready, _, _ = select.select([sys.stdin.buffer], [], [], 5.0)
            except (OSError, ValueError):
                ready = [sys.stdin.buffer]
            if ready:
                raw_credentials = sys.stdin.buffer.read(8193)
                if raw_credentials:
                    credentials = json.loads(raw_credentials)
                    if isinstance(credentials, dict):
                        password = credentials.get("password")
        sys.stdout.write(run(data, password=password))
        return 0
    except TopPlugDecodeError as exc:
        if exc.code in ("PASSWORD_REQUIRED", "AUTH_FAILED", "INVALID_CREDENTIALS"):
            sys.stdout.write(json.dumps({"workerError": exc.code}))
            return 3
        print("No se pudo leer el perfil TOP-PLUG-SA.", file=sys.stderr)
        return 1
    except (ValueError, OSError, UnicodeError):
        print("No se pudo leer el perfil TOP-PLUG-SA.", file=sys.stderr)
        return 1


# ------------------------------------------------------------------ self-test
class _SkipTest(Exception):
    """Muestra real o red no disponible: no es un fallo del decodificador."""


def _encrypt_tpc4(doc):
    import os
    nonce = os.urandom(12)
    cipher = AES.new(d2g(), AES.MODE_GCM, nonce=nonce)
    cipher.update(b"TOPPLUG-PORTABLE-V4\n")
    ct, tag = cipher.encrypt_and_digest(json.dumps(doc).encode("utf-8"))
    return "TOPPLUG4\n" + base64.b64encode(nonce + ct + tag).decode("ascii")


def self_test():
    ok = []

    def check(name, fn):
        try:
            fn()
            ok.append((name, True, ""))
            print(f"[OK] {name}")
        except _SkipTest as e:
            ok.append((name, None, str(e)))
            print(f"[SALTO] {name}: {e}")
        except Exception as e:  # noqa: BLE001
            ok.append((name, False, str(e)))
            print(f"[FALLO] {name}: {e}")

    def t_d2g():
        assert len(d2g()) == 32
        assert d2g().hex() == "cfeedad874bd8c2f1ef65d94ecf75e24fb2f7d2af0b1588da37cccb4cea5ef0c"

    def t_50mb_real():
        # Sobre real del APK (assets/fiftymb-default.json) si está presente
        # como fixture sanitizada del repo. La muestra real NO se incluye:
        # lleva credenciales. Las comprobaciones no reproducen ningún
        # servidor, usuario ni contraseña de la muestra.
        import os
        here = Path(__file__).resolve().parent
        for p in (here / "fixtures" / "fiftymb-default.json",
                  here / "fiftymb-default.json"):
            if os.path.exists(p):
                inner = decrypt_50mb(json.load(open(p)))
                assert inner["revision"] == 1 and inner["enabled"] is True
                assert inner["profile"]["protocol"] == "ssh"
                return
        raise _SkipTest("muestra fiftymb-default.json no incluida en el repo")

    def t_tpc4_real():
        # Muestra real del APK (assets/activation-helper.tpc) si está
        # presente como fixture. No se incluye en el repo: lleva
        # credenciales. Solo se comprueba la forma, nunca sus valores.
        import os
        here = Path(__file__).resolve().parent
        for p in (here / "fixtures" / "activation-helper.tpc",
                  here / "activation-helper.tpc"):
            if os.path.exists(p):
                out = decrypt_tpc(open(p).read().strip())
                assert out["kind"] == "portable-v4"
                assert isinstance(out.get("profile"), dict)
                assert out["profile"].get("protocol") in ("trojan", "vless", "ssh")
                return
        raise _SkipTest("muestra activation-helper.tpc no incluida en el repo")

    def t_tpc4_roundtrip():
        doc = {"format": "topplug", "version": 4,
               "id": "224b9616-8b46-4b21-9240-7b98ca1a1c77",
               "name": "prueba", "issued_at": 1794894665, "expires_at": 0,
               "device_id": "", "locked": True,
               "profile": {"protocol": "ssh", "server": "example.com", "port": 443,
                           "username": "u", "password": "p", "ssh_mode": "direct_tls"}}
        out = decrypt_tpc(_encrypt_tpc4(doc))
        assert out["profile"]["server"] == "example.com"

    def t_tpc5_roundtrip():
        import os
        doc = {"format": "topplug", "version": 4,
               "id": "224b9616-8b46-4b21-9240-7b98ca1a1c77",
               "name": "prueba5", "issued_at": 1794894665, "expires_at": 0,
               "device_id": "", "locked": True,
               "profile": {"protocol": "trojan", "server": "example.com", "port": 443,
                           "password": "x"}}
        inner = _encrypt_tpc4(doc)
        salt, nonce = os.urandom(16), os.urandom(12)
        key = PBKDF2(b"contrasena-de-prueba", salt, dkLen=32, count=600000,
                     hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(b"TOPPLUG-PASSWORD-V5\n")
        ct, tag = cipher.encrypt_and_digest(inner.encode("utf-8"))
        text = "TOPPLUG5\n" + base64.b64encode(salt + nonce + ct + tag).decode("ascii")
        out = decrypt_tpc(text, password="contrasena-de-prueba")
        assert out["kind"] == "password-v5" and out["profile"]["server"] == "example.com"
        try:
            decrypt_tpc(text, password="clave-incorrecta")
            raise AssertionError("contraseña incorrecta no rechazada")
        except ValueError:
            pass

    def t_tpc1_synthetic():
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        priv = ECC.generate(curve="P-256")
        doc = {"format": "topplug", "version": 2, "id": "prueba-1",
               "name": "prueba1", "issued_at": 1794894665, "expires_at": 0,
               "device_id": "",
               "profile": {"protocol": "vless", "server": "example.com", "port": 443}}
        body = json.dumps(doc)
        h = SHA256.new(("TOPPLUG-OFFLINE-V1\n" + body).encode("utf-8"))
        sig = DSS.new(priv, "fips-186-3").sign(h)
        # DER-encode r||s
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        der = DerSequence([r, s]).encode()
        text = "TOPPLUG1\n" + der.hex() + "\n" + body
        out = _parse_tpc1(text, priv.public_key().export_key(format="DER"))
        assert out["profile"]["protocol"] == "vless"

    def t_tpc2_synthetic():
        # TOPPLUG2: la firma verifica y los metadatos se devuelven, pero el
        # perfil es device-bound y NUNCA se descifra fuera del teléfono dueño.
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        priv = ECC.generate(curve="P-256")
        doc = {"format": "topplug", "version": 3,
               "id": "0123456789abcdef0123456789abcdef",
               "name": "prueba2", "issued_at": 1794894665, "expires_at": 0,
               "device_id": "0123456789abcdef",
               "nonce": base64.b64encode(b"\x00" * 12).decode("ascii"),
               "ciphertext": base64.b64encode(b"\x00" * 32).decode("ascii")}
        body = json.dumps(doc)
        h = SHA256.new(("TOPPLUG-SEALED-V3\n" + body).encode("utf-8"))
        sig = DSS.new(priv, "fips-186-3").sign(h)
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        der = DerSequence([r, s]).encode()
        text = "TOPPLUG2\n" + der.hex() + "\n" + body
        out = _parse_tpc2(text, priv.public_key().export_key(format="DER"))
        assert out["kind"] == "sealed-v3-device-bound"
        assert out["profile"] is None
        assert out["device_locked"] is True

    def t_manual_v2():
        doc = {"format": "topplug", "version": 2, "name": "prueba-manual",
               "profile": {"protocol": "ssh", "server": "example.com", "port": 443}}
        out = decrypt_tpc("TOPPLUG-MANUAL-V2\n" + json.dumps(doc))
        assert out["kind"] == "manual-v2"
        assert out["profile"]["server"] == "example.com"

    def t_live():
        live = fetch_live()
        if live["plans"].get("http") is None:
            raise _SkipTest("sin red (%s)" % live["plans"].get("error"))
        assert live["plans"]["http"] == 200, live["plans"]
        assert any(p["id"] == "mtn50" for p in live["plans"]["json"]["plans"])
        assert live["contact"]["http"] == 200
        assert live["notices"]["http"] == 200

    for name, fn in [("d2.g() key material", t_d2g),
                     ("sobre 50MB real (APK)", t_50mb_real),
                     ("TOPPLUG4 real (activation-helper.tpc)", t_tpc4_real),
                     ("TOPPLUG4 round-trip", t_tpc4_roundtrip),
                     ("TOPPLUG5 round-trip (con contraseña)", t_tpc5_roundtrip),
                     ("TOPPLUG1 sintético (firma ECDSA)", t_tpc1_synthetic),
                     ("TOPPLUG2 sintético (firma sí, perfil nunca)", t_tpc2_synthetic),
                     ("TOPPLUG-MANUAL-V2 sintético", t_manual_v2),
                     ("catálogo vivo (3 JSON públicos)", t_live)]:
        check(name, fn)
    failed = [n for n, good, _ in ok if good is False]
    skipped = [n for n, good, _ in ok if good is None]
    print("self-test: %d/%d OK (%d saltados)" % (len(ok) - len(failed) - len(skipped), len(ok), len(skipped)))
    return 0 if not failed else 1


# ------------------------------------------------------------------------ CLI
def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    # Modo directo del worker: un solo argumento que es un archivo existente.
    if len(args) == 1 and Path(args[0]).is_file():
        return _direct_file(args[0])
    ap = argparse.ArgumentParser(description="Decodificador TOP PLUG SA VPN (.tpc + catálogo)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("fetch", help="descargar los 3 JSON públicos")
    p.add_argument("--out", default=None)
    p = sub.add_parser("50mb", help="descifrar un sobre TOPPLUG-50MB-V1 (JSON)")
    p.add_argument("file")
    p = sub.add_parser("tpc", help="descifrar/verificar un archivo .tpc")
    p.add_argument("file")
    p.add_argument("--password", default=None)
    sub.add_parser("self-test", help="pruebas: vectores reales + round-trip + vivo")
    args = ap.parse_args(args)

    if args.cmd == "fetch":
        live = fetch_live()
        print(json.dumps(live, indent=2, ensure_ascii=False))
        if args.out:
            json.dump(live, open(args.out, "w"), indent=2, ensure_ascii=False)
            print("guardado en", args.out)
        return 0
    if args.cmd == "50mb":
        inner = decrypt_50mb(json.load(open(args.file)))
        print(json.dumps(inner, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "tpc":
        out = decrypt_tpc(open(args.file).read().strip(), password=args.password)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "self-test":
        return self_test()
    return 2


if __name__ == "__main__":
    sys.exit(main())
