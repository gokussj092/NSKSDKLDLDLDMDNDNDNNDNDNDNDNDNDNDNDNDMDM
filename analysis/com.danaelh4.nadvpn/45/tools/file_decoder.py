#!/usr/bin/env python3
"""NadiaVPN 1.4.6 `.nad` files and `nad://sec2:` / `nad://pw2:` text links.

Worker adapter over the verified sec2 envelope (PBKDF2-HMAC-SHA256 +
AES-256-CBC + HMAC-SHA256) recovered from NadiaVPN 1.4.6
(com.danaelh4.nadvpn, versionCode 45). A `.nad` file holds the same
envelope as a link: text with a ``NADIA_SEC_V2:`` / ``NADIA_SEC_PW2:``
prefix followed by Base64, or the raw binary envelope directly. In
clear, the file content is a ``java.util.Properties`` XML document
("NadiaVPN Hardened Profile V2"); a link carries the profile as JSON.

This module exposes the three contracts the repo uses:

* ``decode(raw, password=None, hwid=None) -> dict`` — the
  supplied-bridge generic route (``cloud/workers/python/
  supplied_bridge.py`` calls ``module.decode`` with the raw bytes and
  any ``password``/``hwid`` credential).
* ``run(data, password=None, hwid=None) -> str`` — JSON document, the
  file-decoder route (``cloud/workers/python/engine.py`` runs this
  file as a subprocess with the input file as argv and credentials on
  stdin; the Telegram bot registry does the same).
* ``decode_text(text, password=None) -> str | None`` — the text-bridge
  route (``cloud/workers/python/text_bridge.py``); None when the text
  is not a ``nad://`` link, never a fallback to another format.

There is NO server catalog in this integration (FILE_ONLY, by the
owner's decision): no catalog URL, no API host, no live server list.
``decode`` therefore returns only the decrypted profile, never any
download API.

Envelope layout (1120 bytes in the verified real sample):
``salt[0:16] || iv[16:32] || tag HMAC-SHA256[32:64] || ciphertext[64:]``.
KDF: PBKDF2-HMAC-SHA256, 20,000 iterations for sec2 / V2 files and
25,000 for pw2 / PW2 files, dkLen 64; ``key = dk[:32]`` (AES-256),
``mac_key = dk[32:]``; ``tag = HMAC-SHA256(mac_key, salt || iv ||
ciphertext)``. The ``info`` (PBKDF2 password) is the device-bound
master secret (K1, mangled per the exporting device's integrity
flags) + the APK signing-certificate SHA-256 (K2), plus the trimmed
user password for pw2. This adapter tries every plausible flag value
until the HMAC verifies, so links exported on other devices with the
same build open too. A link from a build signed with another
certificate does NOT open with these constants (K2/K1 change).

Credential codes (existing repo contract, never a new flow):
``PASSWORD_REQUIRED`` (PW2/pw2: without a password),
``HWID_REQUIRED`` (NADIA_SEC_HWID: without a HWID),
``HWID_PASSWORD_REQUIRED`` (NADIA_SEC_HWID_PW: without both),
``AUTH_FAILED`` (a supplied password fails the HMAC check),
``UNSUPPORTED_VERSION`` (legacy V1 prefixes),
``UNSUPPORTED_VARIANT`` (a HWID was supplied, but the HWID-slot
derivation is unverified — no real HWID sample exists yet, so the
variant stays pending; see ANALYSIS.md),
``DECODE_FAILED`` (anything else).
``text_bridge`` and ``supplied_bridge`` surface the credential codes
with exit code 3; this file's own CLI does the same.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Key material recovered from libandroidx.graphics.path.so (see
# analysis/com.danaelh4.nadvpn/45/ANALYSIS.md): K1 is the device-bound
# master secret before the per-device XOR-mangle; K2 is the SHA-256 of
# the APK signing certificate. Same role as the embedded constants in
# the other supplied decoders (e.g. MehafVPN PASSWORD).
_K1_BASE = bytes.fromhex(
    "dddd6bfcd0b12811acc49b23561c240bd04a74a050154036c1e3281c49fbf5df"
)
_K2 = bytes.fromhex(
    "f37a67c56fa18437f12bf961cf36aaf73ec1a38bfa9f59cda0697ce45f090b9b"
)
_W19_CANDIDATES = (
    2, 1, 3, 5, 7, 9, 11, 13, 15,
    0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F,
    0x61, 0x63, 0x65, 0x67, 0x69, 0x6B, 0x6D, 0x6F,
)

SCHEMES = ("nad://sec2:", "nad://pw2:", "nad://")
FILE_PREFIX_V2 = "NADIA_SEC_V2:"
FILE_PREFIX_PW2 = "NADIA_SEC_PW2:"
FILE_PREFIX_HWID = "NADIA_SEC_HWID:"
FILE_PREFIX_HWID_PW = "NADIA_SEC_HWID_PW:"
FILE_PREFIX_V1 = ("NADIA_SEC_V1:", "NADIA_SEC_PW:")
MAX_BYTES = 8 * 1024 * 1024

try:
    from Crypto.Cipher import AES as _AES

    def _aes_cbc_decrypt(key, iv, data):
        return _AES.new(key, _AES.MODE_CBC, iv).decrypt(data)

    def _aes_cbc_encrypt(key, iv, data):
        return _AES.new(key, _AES.MODE_CBC, iv).encrypt(data)

except ImportError:  # pragma: no cover - venv always has pycryptodome
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _aes_cbc_decrypt(key, iv, data):
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()

    def _aes_cbc_encrypt(key, iv, data):
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return e.update(data) + e.finalize()


class NadiaDecodeError(ValueError):
    """Decode failure with a worker ``code`` (``PASSWORD_REQUIRED``,
    ``HWID_REQUIRED``, ``HWID_PASSWORD_REQUIRED``, ``AUTH_FAILED``,
    ``UNSUPPORTED_VERSION``, ``UNSUPPORTED_VARIANT`` or
    ``DECODE_FAILED``)."""

    def __init__(self, message, code="DECODE_FAILED"):
        super().__init__(message)
        self.code = code


def _mangle(buf, w19):
    mask = 0xFFFFFFFF
    w9 = (w19 * 0x9E3779B9) & mask
    w9 ^= 0x85EBCA6B
    out = bytearray(buf)
    for i in range(32):
        w9 = (w9 * 0x19660D + 0x3C6EF35F) & mask
        out[i] ^= ((w19 ^ (w9 >> 16) ^ (w9 >> 24)) | 1) & 0xFF
    return bytes(out)


def _decrypt_v2(blob, password=None):
    """Decrypt one sec2 envelope -> plaintext bytes.

    Raises ValueError("Error de integridad: Firma de archivo no
    coincide") when no flag candidate verifies the HMAC (wrong
    password, tampered data, or a build signed with another
    certificate).
    """
    if len(blob) < 80:
        raise ValueError("envelope demasiado corto (minimo 80 bytes)")
    salt, iv, tag, ct = blob[:16], blob[16:32], blob[32:64], blob[64:]
    if password is None:
        iters = 20000
        suffix = b""
    else:
        iters = 25000
        suffix = password.strip().encode("utf-8")
    salt_mac = hmac.new(_K2, salt, hashlib.sha256).digest()
    for w19 in _W19_CANDIDATES:
        info = _mangle(_K1_BASE, w19) + _K2 + suffix
        dk = hashlib.pbkdf2_hmac("sha256", info, salt_mac, iters, dklen=64)
        key, mac_key = dk[:32], dk[32:]
        calc = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
        if hmac.compare_digest(calc, tag):
            pt = _aes_cbc_decrypt(key, iv, ct)
            pad = pt[-1]
            if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
                raise ValueError("relleno PKCS7 invalido")
            return pt[:-pad]
    raise ValueError("Error de integridad: Firma de archivo no coincide")


def _encrypt_v2(plaintext, password=None, w19=2, salt=None, iv=None):
    """Encrypt one sec2 envelope (test/fixture use only: reproduces the
    app's export path so round-trips can be verified)."""
    if salt is None:
        salt = os.urandom(16)
    if iv is None:
        iv = os.urandom(16)
    if password is None:
        iters = 20000
        suffix = b""
    else:
        iters = 25000
        suffix = password.strip().encode("utf-8")
    salt_mac = hmac.new(_K2, salt, hashlib.sha256).digest()
    info = _mangle(_K1_BASE, w19) + _K2 + suffix
    dk = hashlib.pbkdf2_hmac("sha256", info, salt_mac, iters, dklen=64)
    key, mac_key = dk[:32], dk[32:]
    pad = 16 - (len(plaintext) % 16)
    ct = _aes_cbc_encrypt(key, iv, plaintext + bytes([pad]) * pad)
    tag = hmac.new(mac_key, salt + iv + ct, hashlib.sha256).digest()
    return salt + iv + tag + ct


def _parse_properties_xml(data: bytes) -> dict:
    """java.util.Properties XML ("NadiaVPN Hardened Profile V2") -> dict."""
    text = data.decode("utf-8")
    root = ET.fromstring(text)
    out = {}
    for entry in root.iter("entry"):
        key = entry.get("key")
        if key is not None:
            out[key] = entry.text if entry.text is not None else ""
    if not out:
        raise NadiaDecodeError("perfil .nad vacio")
    return out


def _decrypt_or_auth(blob, password, identified=True):
    """Decrypt, mapping an HMAC failure to AUTH_FAILED when a password
    was supplied (wrong password) and to DECODE_FAILED otherwise
    (tampered data or another build)."""
    try:
        return _decrypt_v2(blob, password)
    except ValueError as exc:
        if str(exc).startswith("Error de integridad") and password:
            raise NadiaDecodeError(str(exc), code="AUTH_FAILED") from None
        raise NadiaDecodeError(str(exc)) from None


def decode(raw, password=None, hwid=None):
    """Decrypt a `.nad` file (bytes/str) or a `nad://` link.

    Returns the decrypted profile dict. Raises ``NadiaDecodeError``
    with ``code`` ``PASSWORD_REQUIRED`` (PW2/pw2: without a password),
    ``HWID_REQUIRED`` / ``HWID_PASSWORD_REQUIRED`` (HWID prefixes
    without the HWID), ``AUTH_FAILED`` (supplied password fails the
    HMAC), ``UNSUPPORTED_VERSION`` (legacy V1), ``UNSUPPORTED_VARIANT``
    (HWID supplied but the HWID-slot derivation is unverified) or
    ``DECODE_FAILED``.
    """
    if isinstance(raw, bytes) and (not raw or len(raw) > MAX_BYTES):
        raise NadiaDecodeError("archivo .nad vacio o demasiado grande")
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8-sig").strip()
        except UnicodeDecodeError:
            # Not UTF-8 text: only a raw binary envelope can still open.
            if len(raw) >= 80:
                try:
                    return _parse_properties_xml(_decrypt_v2(raw))
                except (ValueError, NadiaDecodeError):
                    pass
            raise NadiaDecodeError(
                "archivo no reconocido (se espera .nad con prefijo "
                "NADIA_SEC_V2: / NADIA_SEC_PW2: o sobre binario directo)"
            ) from None
    elif isinstance(raw, str):
        text = raw.strip()
    else:
        raise NadiaDecodeError("tipo de entrada no valido")
    if not text:
        raise NadiaDecodeError("archivo .nad vacio")
    lowered = text.lower()

    # --- Text links -----------------------------------------------------
    if lowered.startswith("nad://sec2:"):
        blob = base64.b64decode(text[len("nad://sec2:"):])
        plain = _decrypt_or_auth(blob, None)
        try:
            doc = json.loads(plain.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise NadiaDecodeError("perfil nad://sec2: no es JSON") from None
        if not isinstance(doc, dict) or not doc:
            raise NadiaDecodeError("perfil nad://sec2: vacio")
        return doc
    if lowered.startswith("nad://pw2:"):
        if password is None:
            raise NadiaDecodeError(
                "el enlace nad://pw2: requiere contrasena",
                code="PASSWORD_REQUIRED",
            )
        blob = base64.b64decode(text[len("nad://pw2:"):])
        plain = _decrypt_or_auth(blob, password)
        try:
            doc = json.loads(plain.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise NadiaDecodeError("perfil nad://pw2: no es JSON") from None
        if not isinstance(doc, dict) or not doc:
            raise NadiaDecodeError("perfil nad://pw2: vacio")
        return doc
    if lowered.startswith("nad://"):
        try:
            doc = json.loads(text[len("nad://"):])
        except ValueError:
            raise NadiaDecodeError("perfil nad:// en claro no es JSON") from None
        if not isinstance(doc, dict) or not doc:
            raise NadiaDecodeError("perfil nad:// en claro vacio")
        return doc

    # --- Files: prefixed text -------------------------------------------
    if text.startswith(FILE_PREFIX_V2):
        blob = base64.b64decode(text[len(FILE_PREFIX_V2):])
        return _parse_properties_xml(_decrypt_or_auth(blob, None))
    if text.startswith(FILE_PREFIX_PW2):
        if password is None:
            raise NadiaDecodeError(
                "el archivo requiere contrasena (NADIA_SEC_PW2:)",
                code="PASSWORD_REQUIRED",
            )
        blob = base64.b64decode(text[len(FILE_PREFIX_PW2):])
        return _parse_properties_xml(_decrypt_or_auth(blob, password))
    if text.startswith(FILE_PREFIX_HWID_PW):
        if hwid is None and password is None:
            raise NadiaDecodeError(
                "perfil bloqueado a HWID y contrasena",
                code="HWID_PASSWORD_REQUIRED",
            )
        if hwid is None:
            raise NadiaDecodeError(
                "perfil bloqueado a HWID",
                code="HWID_REQUIRED",
            )
        if password is None:
            raise NadiaDecodeError(
                "perfil bloqueado a HWID y contrasena",
                code="PASSWORD_REQUIRED",
            )
        raise NadiaDecodeError(
            "perfil bloqueado a HWID: derivacion de slots NHW1 sin "
            "verificar (falta muestra real)",
            code="UNSUPPORTED_VARIANT",
        )
    if text.startswith(FILE_PREFIX_HWID):
        if hwid is None:
            raise NadiaDecodeError(
                "perfil bloqueado a HWID: se necesita el HWID del "
                "dispositivo autorizado (SHA-256 del android_id)",
                code="HWID_REQUIRED",
            )
        raise NadiaDecodeError(
            "perfil bloqueado a HWID: derivacion de slots NHW1 sin "
            "verificar (falta muestra real)",
            code="UNSUPPORTED_VARIANT",
        )
    if text.startswith(FILE_PREFIX_V1):
        raise NadiaDecodeError(
            "formato legacy V1 (DES/ECB obsoleto o derivacion legacy): "
            "la app misma lo rechaza; vuelve a exportar el perfil",
            code="UNSUPPORTED_VERSION",
        )

    # --- Files: raw binary envelope --------------------------------------
    if isinstance(raw, bytes) and len(raw) >= 80:
        try:
            return _parse_properties_xml(_decrypt_v2(raw))
        except (ValueError, NadiaDecodeError):
            pass
    raise NadiaDecodeError(
        "archivo no reconocido (se espera .nad con prefijo "
        "NADIA_SEC_V2: / NADIA_SEC_PW2: o sobre binario directo)"
    )


def run(data: bytes, password=None, hwid=None) -> str:
    """Decrypt file/link bytes -> JSON document string."""
    return json.dumps(decode(data, password=password, hwid=hwid),
                      ensure_ascii=False, indent=2)


def decode_text(text: str, password=None) -> str | None:
    """Decrypt a `nad://sec2:` / `nad://pw2:` / `nad://` link.

    Returns the JSON document, or None when the text is not a `nad://`
    link. A password-locked link without a password raises
    ``NadiaDecodeError`` (``PASSWORD_REQUIRED``) instead of returning
    None, so the caller reports the missing password instead of an
    undecodable link.
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    lowered = value.lower()
    if not any(lowered.startswith(scheme) for scheme in SCHEMES):
        return None
    return json.dumps(decode(value, password=password),
                      ensure_ascii=False, indent=2)


def self_test():
    """Round-trip V2 / PW2 / binary envelope with fresh salt+IV, plus
    the negative cases (bad HMAC, legacy V1, HWID prefix)."""
    profile = {
        "Name": "Synthetic Test",
        "ServerIP": "example.invalid",
        "ServerPort": "443",
        "Protocol": "SSL",
        "SSHUser": "synthetic",
        "SSHPass": "synthetic",
    }
    payload = json.dumps(profile, ensure_ascii=False).encode("utf-8")
    plain = _decrypt_v2(_encrypt_v2(payload))
    assert json.loads(plain.decode("utf-8")) == profile, "V2 round-trip"
    plain = _decrypt_v2(_encrypt_v2(payload, password="test123"),
                        password="test123")
    assert json.loads(plain.decode("utf-8")) == profile, "PW2 round-trip"

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE properties SYSTEM '
        '"http://java.sun.com/dtd/properties.dtd">\n'
        "<properties>\n"
        '<entry key="Name">Synthetic Test</entry>\n'
        '<entry key="ServerIP">example.invalid</entry>\n'
        '<entry key="ServerPort">443</entry>\n'
        "</properties>\n"
    ).encode("utf-8")
    # V2 file (prefixed text).
    blob = _encrypt_v2(xml)
    out = decode(("NADIA_SEC_V2:" + base64.b64encode(blob).decode()).encode())
    assert out == {"Name": "Synthetic Test", "ServerIP": "example.invalid",
                   "ServerPort": "443"}, out
    # PW2 file (prefixed text, password).
    blob = _encrypt_v2(xml, password="test123")
    try:
        decode(("NADIA_SEC_PW2:" + base64.b64encode(blob).decode()).encode())
    except NadiaDecodeError as exc:
        assert exc.code == "PASSWORD_REQUIRED", exc.code
    else:
        raise AssertionError("PW2 without password must fail")
    out = decode(("NADIA_SEC_PW2:" + base64.b64encode(blob).decode()).encode(),
                 password="test123")
    assert out["Name"] == "Synthetic Test", out
    try:
        decode(("NADIA_SEC_PW2:" + base64.b64encode(blob).decode()).encode(),
               password="wrong")
    except NadiaDecodeError as exc:
        assert exc.code == "AUTH_FAILED", exc.code
    else:
        raise AssertionError("PW2 with wrong password must fail")
    # Binary envelope, no prefix.
    out = decode(_encrypt_v2(xml))
    assert out["ServerIP"] == "example.invalid", out
    # Negative cases.
    bad = bytearray(_encrypt_v2(xml))
    bad[-1] ^= 0x01
    try:
        decode(bytes(bad))
    except NadiaDecodeError as exc:
        assert exc.code == "DECODE_FAILED", exc.code
    else:
        raise AssertionError("tampered envelope must fail")
    try:
        decode(b"NADIA_SEC_V1:AAAA")
    except NadiaDecodeError as exc:
        assert exc.code == "UNSUPPORTED_VERSION", exc.code
    else:
        raise AssertionError("V1 must fail")
    try:
        decode(b"NADIA_SEC_HWID:AAAA")
    except NadiaDecodeError as exc:
        assert exc.code == "HWID_REQUIRED", exc.code
    else:
        raise AssertionError("HWID without HWID must fail")
    try:
        decode(b"NADIA_SEC_HWID:AAAA", hwid="00" * 32)
    except NadiaDecodeError as exc:
        assert exc.code == "UNSUPPORTED_VARIANT", exc.code
    else:
        raise AssertionError("HWID with HWID must fail as unverified")
    # Text links.
    link = "nad://sec2:" + base64.b64encode(_encrypt_v2(payload)).decode()
    assert json.loads(decode_text(link)) == profile
    assert decode_text("vmess://AAAA") is None
    print("self-test OK: V2/PW2/binary round-trips, tampered/V1/HWID "
          "negatives, sec2 link")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", nargs="?", type=Path,
                   help="archivo .nad (o enlace nad:// en un archivo)")
    p.add_argument("--password", default=None,
                   help="contrasena para NADIA_SEC_PW2: / nad://pw2:")
    p.add_argument("--hwid", default=None,
                   help="HWID para NADIA_SEC_HWID: (sin verificar)")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if a.self_test:
        return self_test()
    try:
        password = a.password
        hwid = a.hwid
        if a.file:
            with a.file.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            # Credentials arrive on stdin as JSON (engine contract) when
            # a file path is given; never read a tty.
            if password is None and hwid is None and not sys.stdin.isatty():
                raw_credentials = sys.stdin.buffer.read(8193)
                if raw_credentials:
                    credentials = json.loads(raw_credentials)
                    if isinstance(credentials, dict):
                        password = credentials.get("password")
                        hwid = credentials.get("hwid")
            sys.stdout.write(run(data, password=password, hwid=hwid))
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
            sys.stdout.write(run(data, password=password, hwid=hwid))
        return 0
    except NadiaDecodeError as exc:
        if exc.code in ("PASSWORD_REQUIRED", "HWID_REQUIRED",
                        "HWID_PASSWORD_REQUIRED", "AUTH_FAILED",
                        "UNSUPPORTED_VERSION", "UNSUPPORTED_VARIANT"):
            sys.stdout.write(json.dumps({"workerError": exc.code}))
            return 3
        print("No se pudo leer el perfil NadiaVPN.", file=sys.stderr)
        return 1
    except (ValueError, OSError):
        print("No se pudo leer el perfil NadiaVPN.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
