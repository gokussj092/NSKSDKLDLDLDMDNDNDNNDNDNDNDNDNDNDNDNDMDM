#!/usr/bin/env python3
"""RMP TUNNEL LITE RMP-4 `.rmplite` files and `rmplite://` links.

Adapted from the batch-16 deliverable ``rmptunnel_files.py`` (dossier
``analysis/com.rmptunnel.lite/4/``); no new crypto, standard library
only.

A `.rmplite` file is ONE line of hexadecimal text. The app reads the
first line (``OpenVPNClient.onActivityResult`` / ``onCreate``,
ACTION_VIEW), decrypts it with PUtils.pDecrypt (native
``libputils.so``) and parses the result as a JSON tweak object:
  hex -> XOR with the 12-byte format key (index mod 12) -> JNI modified
  UTF-8 text -> JSON object with at least ``tweak_password`` (the app
  shows a password-lock dialog when it is non-empty, then merges the
  tweak as a new payload into its local catalog copy, checking
  ``tweak_expiry`` ``yyyy-MM-dd-HH-mm``, ``hwid_lock`` and
  ``block_rooted``).

The native primitive was verified against the real ``libputils.so``
from the arm64 split (SHA-256 e1eb45e2..., xorWithKey at 0x1486d4, key
built on the stack from .rodata 0xc4e37 plus the immediate 0x5d506b66)
with a Unicorn oracle: the oracle decrypts Python-encrypted synthetic
tweaks exactly. Same key and recipe as the verified HX Tunnel .hxt
family.

Text links use the scheme the app defines:
  rmplite://<hex>            (optionally with a leading RMPLITE marker)
The link carries the same hex payload as the file's first line.

OpenVPN profiles (``.ovpn`` / ``.conf``) are imported by the app as-is
through the OpenVPN core; there is no RMP encryption on them, so this
decoder reports them as passthrough elsewhere and does not transform
them here.

No real exported `.rmplite` file or link was available, so the format
is VERIFIED_SYNTHETIC (native-oracle round-trip + code flow); a real
file or link is the one pending item for end-to-end confirmation.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
if __package__:
    from .codec import DecodeError, MAX_BYTES
else:
    from codec import DecodeError, MAX_BYTES

SCHEME = "rmplite://"
# Shared client format constant from libputils.so, not a user password.
PROFILE_KEY = b"4%PdXch>fkP]"
# JSON keys the app reads from a decrypted tweak (OpenVPNClient.B/Z).
TWEAK_KEYS = ("tweak_password", "tweak_expiry", "hwid_lock",
              "block_rooted", "friendly_name")


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("Se esperaba texto o bytes UTF-8.")
    if len(data) > MAX_BYTES:
        raise DecodeError("La entrada supera el límite de tamaño.")
    try:
        value = data.decode("utf-8-sig") if isinstance(data, bytes) else data.removeprefix("\ufeff")
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise DecodeError("La entrada supera el límite de tamaño.")
    except UnicodeError as exc:
        raise DecodeError("La entrada no es UTF-8 válido.") from exc
    return value.strip()


def _first_line(data: bytes | str) -> str:
    """The app reads exactly the first line of the file/link stream."""
    text = _text(data)
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    raise DecodeError("El archivo .rmplite está vacío.")


def _modified_utf8(data: bytes) -> str:
    # JNI GetStringUTFChars encodes UTF-16 surrogate pairs separately
    # (CESU-8). DataOutputStream.writeUTF uses the same representation.
    try:
        if any(byte >= 0xF0 for byte in data):
            raise UnicodeError("four-byte UTF-8 is not JNI modified UTF-8")
        text = data.replace(b"\xc0\x80", b"\0").decode("utf-8", errors="surrogatepass")
        return text.encode("utf-16-le", errors="surrogatepass").decode("utf-16-le")
    except UnicodeError as exc:
        raise DecodeError("El perfil no contiene texto JNI válido.") from exc


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


MAX_DEPTH = 64
MAX_NODES = 1_000_000


def _validate(doc):
    pending, count = [(doc, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise DecodeError("El JSON supera el límite de complejidad.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise DecodeError("Número JSON no finito.")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise DecodeError("Unicode JSON inválido.") from exc
    return doc


def decrypt_profile_text(data: bytes | str) -> str:
    """Hex -> XOR key -> JNI modified UTF-8 text (native pDecrypt)."""
    compact = re.sub(r"[ \t\r\n]", "", _first_line(data))
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        raise DecodeError("Se esperaba hexadecimal de longitud par de un archivo .rmplite.")
    encrypted = bytes.fromhex(compact)
    plain = bytes(value ^ PROFILE_KEY[i % len(PROFILE_KEY)]
                  for i, value in enumerate(encrypted))
    return _modified_utf8(plain)


def decode(data: bytes | str) -> dict:
    """Return the tweak JSON object exactly as stored (keys unchanged)."""
    try:
        doc = json.loads(decrypt_profile_text(data),
                         object_pairs_hook=_unique, parse_constant=_nonfinite)
    except DecodeError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecodeError("JSON inválido o con claves duplicadas.") from exc
    if not isinstance(doc, dict):
        raise DecodeError("El perfil debe contener un objeto JSON.")
    return _validate(doc)


def _decode_payload(payload: str):
    """Decrypt one bare hex payload; None when it does not open."""
    if not payload or not payload.strip():
        return None
    try:
        return decode(payload)
    except (ValueError, UnicodeError, RecursionError):
        return None


def run(data: bytes) -> str:
    """Decrypt a bare `.rmplite` payload, or one carrying the scheme prefix.

    Accepts bytes that are a bare hex payload (first line only, as the
    app reads it) or that start with ``rmplite://`` (case-insensitive).
    Anything else -- empty or oversize input, non-UTF-8 bytes, another
    scheme, garbage -- is rejected with DecodeError.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError('Perfil vacío o superior a 8 MiB.')
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise DecodeError('Perfil RMP TUNNEL LITE inválido.') from None
    if not text:
        raise DecodeError('Perfil RMP TUNNEL LITE inválido.')
    if "://" in text:
        prefix, _, payload = text.partition("://")
        if prefix.lower() + "://" != SCHEME:
            raise DecodeError('Perfil RMP TUNNEL LITE inválido.')
        try:
            from urllib.parse import unquote
            payload = unquote(payload)
        except Exception:  # noqa: BLE001 - keep the raw payload on odd input
            pass
        if payload.upper().startswith("RMPLITE"):
            payload = payload[len("RMPLITE"):]
        config = _decode_payload(payload)
    else:
        config = _decode_payload(text)
    if config is None:
        raise DecodeError('Perfil RMP TUNNEL LITE inválido.')
    return json.dumps(config, ensure_ascii=False, indent=2, allow_nan=False)


def decode_text(text: str) -> str | None:
    """Decrypt a `rmplite://` link (case-insensitive scheme).

    Returns the JSON document, or None when the text is not a
    `rmplite://` link, the payload is empty, or decryption fails --
    so the text bridge keeps looking (or, for this unambiguous scheme,
    treats None as final).
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    if not value.lower().startswith(SCHEME):
        return None
    payload = value[len(SCHEME):]
    try:
        from urllib.parse import unquote
        payload = unquote(payload)
    except Exception:  # noqa: BLE001 - keep the raw payload on odd input
        pass
    if payload.upper().startswith("RMPLITE"):
        payload = payload[len("RMPLITE"):]
    config = _decode_payload(payload)
    if config is None:
        return None
    return json.dumps(config, ensure_ascii=False, indent=2, allow_nan=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('file', nargs='?', type=Path)
    a = p.parse_args()
    try:
        if a.file:
            with a.file.open('rb') as stream:
                data = stream.read(MAX_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        sys.stdout.write(run(data))
        return 0
    except (ValueError, OSError):
        print('No se pudo leer el perfil RMP TUNNEL LITE.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
