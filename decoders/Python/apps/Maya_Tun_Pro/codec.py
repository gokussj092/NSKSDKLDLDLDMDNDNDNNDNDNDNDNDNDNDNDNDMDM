"""MAYA TUN PRO 43.0 (43) live catalog and ``maya://`` links.

No new crypto is invented here. The catalog envelope and every nested
field use the NoobCrypt primitives exactly as reverse-engineered from
the 43.0 APK and verified against the live catalog on 2026-11-22
(see ``~/workspace/catalogs/mayatun/NOTES.md`` and the dossier
``analysis/maya.tun.udp/43/``):

- Outer layer (NoobCrypt mode 5): Base64 -> AES-256-XTS, tweak = first
  16 bytes, ciphertext = the rest. The 64-byte XTS key is derived in
  native code from four masked 16-byte blocks in ``libovpn3.so``
  ``.rodata`` (``ROL6(block XOR mask)``); the derived key is embedded
  below as ``XTS_KEY_HEX`` so this module works without the APK. The
  derivation is reproduced in ``mayatun.py`` (``derive_xts_key``) and
  was verified live.
- Inner string fields (NoobCrypt modes 0 / 1 / 4) use the ``"maya"``
  key. That key is NOT duplicated here: it is imported from the
  existing ``decoders/Python/_noobcrypt.py`` (``KEYS["maya"]``), which
  the 43.0 native code reproduces byte-for-byte (32 bytes at 0x221e20
  XOR 16 bytes at 0x1c2b80 || 16 bytes at 0x1c2860). Mode 0 is
  AES-256-GCM, Base64(nonce[12] + ciphertext + tag[16]); modes 1/4 are
  AES-256-CBC, Base64(IV[16] + ciphertext), PKCS#7 (or trailing-newline)
  padding stripped. GCM is tried first (authentication fails loudly on
  a wrong mode), then CBC with a printability check. Values that do not
  open are served as-is, never invented.
- Text links (NoobCrypt mode 3): ``maya://`` + Base64 of the
  ChaCha20-Poly1305 encryption of the ``.maya`` file bytes, same key,
  envelope Base64(nonce[12] + ciphertext + tag[16]) — the native-core
  layout documented for modes 0/3 (nonce 12 B + tag 16 B). The
  decrypted bytes are opened with the existing repo file route
  (``_noobcrypt.decrypt_profile`` via ``decoders/Python/maya.py``'s
  scheme), never with a second copy of that logic. No real ``maya://``
  link has been supplied, so the text route is VERIFIED_SYNTHETIC.

The live catalog (``https://jezvpn.xyz/api/app?json=38FD5AC7020E09D8203F``,
plain GET, no headers, no auth) was verified 2026-11-22: HTTP 200,
454,716 bytes, SHA-256
``131869d6027906f3cfcadfbc96bf81db9479435ad54a6b069ef80f84668b4806``,
Version 1.3.41, 27 servers, 376 tweaks, 2,449 Base64-looking inner
strings, 0 left undecrypted. Fetch + full decode takes ~1.2 s in this
VM, far below the 120 s catalog worker cap.

HMAC connection authentication: NOT_OBSERVED (see dossier
MANIFEST.json ``connection_authentication``). The XTS envelope is
unauthenticated; the inner GCM fields carry an AEAD tag (not HMAC).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

if __package__ and __package__.startswith("decoders."):
    from ... import _noobcrypt as _noobcrypt_module
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import _noobcrypt as _noobcrypt_module

KEYS = _noobcrypt_module.KEYS
_decrypt_maya_profile = _noobcrypt_module.decrypt_profile

MAX_BYTES = 8 * 1024 * 1024
CATALOG_URL = "https://jezvpn.xyz/api/app?json=38FD5AC7020E09D8203F"
SCHEME = "maya://"

# AES-256-XTS key (64 bytes) for NoobCrypt mode 5, derived from the 43.0
# libovpn3.so .rodata (see module docstring). Verified live 2026-11-22.
XTS_KEY_HEX = (
    "f76cece731b39b5c0c4f33824a77307dd3ff8c826e11a78f051d3699bdf78288"
    "0f33dd731fa8ed043e97f8c20aa45186ce9efd3108dceabf8b5ef74a76a96048"
)

# NoobCrypt mode-0/1/3/4 key ("maya"). Imported, never re-typed, from
# decoders/Python/_noobcrypt.py; identical to the 43.0 native derivation.
MAYA_KEY = KEYS["maya"]


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


def _aes_xts_decrypt(key: bytes, tweak: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_outer_blob(blob: bytes, xts_key: bytes = bytes.fromhex(XTS_KEY_HEX)) -> dict:
    """Base64 blob -> AES-256-XTS (tweak = first 16 bytes) -> catalog JSON."""
    if not isinstance(blob, bytes) or len(blob) < 32:
        raise DecodeError("Sobre exterior inválido para MAYA TUN PRO 43.0.")
    tweak, ciphertext = blob[:16], blob[16:]
    try:
        plaintext = _aes_xts_decrypt(xts_key, tweak, ciphertext)
        doc = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_unique,
                         parse_constant=_invalid_constant)
    except DecodeError:
        raise
    except (ValueError, UnicodeError):
        raise DecodeError("Sobre exterior inválido para MAYA TUN PRO 43.0.") from None
    if not isinstance(doc, dict):
        raise DecodeError("Sobre exterior sin JSON válido.")
    return doc


def _gcm_decrypt(raw: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key).decrypt(raw[:12], raw[12:], None)


def _cbc_decrypt(raw: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.CBC(raw[:16])).decryptor()
    plaintext = decryptor.update(raw[16:]) + decryptor.finalize()
    if plaintext:
        pad = plaintext[-1]
        if 1 <= pad <= 16 and plaintext[-pad:] == bytes([pad]) * pad:
            return plaintext[:-pad]
        return plaintext.rstrip(b"\n\x00")
    return plaintext


def _is_printable_text(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ch.isprintable() or ch in "\n\r\t" for ch in text)


def try_decrypt_inner_string(value: str, key: bytes = MAYA_KEY) -> str:
    """Decrypt one NoobCrypt mode-0 (GCM) or mode-1/4 (CBC) string value.

    Returns the original string when it is not a valid encrypted value.
    """
    encoded = "".join(value.split())
    if len(encoded) < 28:
        return value
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception:
        return value
    if len(raw) < 28:
        return value
    try:
        return _gcm_decrypt(raw, key).decode("utf-8")
    except Exception:
        pass
    try:
        plaintext = _cbc_decrypt(raw, key)
    except Exception:
        return value
    if _is_printable_text(plaintext):
        return plaintext.decode("utf-8")
    return value


def decode_inner_values(value, key: bytes = MAYA_KEY):
    """Recursively decrypt every inner string field of a catalog object."""
    if isinstance(value, dict):
        return {name: decode_inner_values(item, key) for name, item in value.items()}
    if isinstance(value, list):
        return [decode_inner_values(item, key) for item in value]
    if isinstance(value, str) and value:
        return try_decrypt_inner_string(value, key)
    return value


def open_outer(data: bytes) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError("Entrada vacía o superior a 8 MiB.")
    try:
        blob = base64.b64decode(b"".join(data.split()))
    except Exception:
        raise DecodeError("Sobre exterior inválido para MAYA TUN PRO 43.0.") from None
    doc = decrypt_outer_blob(blob)
    if (not isinstance(doc.get("Version"), str) or not doc["Version"]
            or not isinstance(doc.get("Servers"), list) or not doc["Servers"]
            or not isinstance(doc.get("Tweaks"), list) or not doc["Tweaks"]):
        raise DecodeError("Faltan secciones completas del catálogo.")
    return doc


def decode_catalog(data: bytes) -> dict:
    try:
        doc = open_outer(data)
        decoded = decode_inner_values(doc)
        if (not isinstance(decoded.get("Servers"), list) or not decoded["Servers"]
                or not isinstance(decoded.get("Tweaks"), list) or not decoded["Tweaks"]):
            raise DecodeError("Faltan secciones completas del catálogo.")
        return decoded
    except DecodeError:
        raise
    except (ValueError, UnicodeError, KeyError, TypeError,
            RecursionError, OverflowError):
        raise DecodeError("Catálogo inválido o incompatible con MAYA TUN PRO 43.0.") from None


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def _chacha_decrypt(raw: bytes, key: bytes = MAYA_KEY) -> bytes:
    """NoobCrypt mode 3: Base64(nonce[12] + ciphertext + tag[16])."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    if len(raw) < 28:
        raise DecodeError("Enlace maya:// inválido.")
    return ChaCha20Poly1305(key).decrypt(raw[:12], raw[12:], None)


def decode_text(text: str) -> str | None:
    """Decrypt a ``maya://`` link (case-insensitive scheme).

    The payload is the ChaCha20-Poly1305 (mode 3) encryption of the
    ``.maya`` file bytes; the decrypted bytes are opened with the
    existing repo file route (``_noobcrypt.decrypt_profile``), the same
    scheme ``decoders/Python/maya.py`` uses for ``.maya`` files. No
    file logic is duplicated here.

    Returns the JSON document, or None when the text is not a
    ``maya://`` link, the payload is empty, or decryption fails — so
    the text bridge treats None as final for this unambiguous scheme.
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    if not value.lower().startswith(SCHEME):
        return None
    payload = value[len(SCHEME):].strip()
    if not payload:
        return None
    try:
        encoded = "".join(payload.split())
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        raw = base64.b64decode(encoded, validate=True)
        file_bytes = _chacha_decrypt(raw)
        profile = _decrypt_maya_profile(file_bytes, "maya")
    except Exception:
        return None
    return json.dumps({"application": "Maya Tunnel", "extension": ".maya",
                       "protocol": SCHEME, "config": profile},
                      ensure_ascii=False, indent=2)
