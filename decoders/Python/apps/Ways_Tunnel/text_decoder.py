#!/usr/bin/env python3
"""Ways Tunnel 18.1 ``wyst://`` tweak text links.

Worker adapter over the original decoder in ``waystunnel.py`` (kept
verbatim): a tweak pasted in the app is decrypted with the same
AES-256-CBC / zero-IV construction as the catalog, keyed by
``tweakdam0n`` (``waystunnel.decrypt_tweak``), and parsed as a JSON
object.

This module exposes the contract the repo uses:

* ``decode_text(text, password=<redacted>) -> str | None`` — the
  text-bridge route (``cloud/workers/python/text_bridge.py``); None
  when the text is not a ``wyst://`` link or cannot be decrypted,
  never a fallback to another format. Tweaks carry no password, so
  a password credential is refused with ``CREDENTIALS_NOT_ALLOWED``.

There is NO file route in this app: Ways Tunnel registers no file
suffix and imports no configuration files, so this module ships no
``decode``/``run`` file entry point. The live server catalog lives
in ``server_catalog_decoder.py``.

State: VERIFIED_SYNTHETIC — the AES/CBC/IV-zero construction with
``tweakdam0n`` is reconstructed from the DEX and the round-trip
below is synthetic; no real ``wyst://`` sample has been supplied
yet, so no real tweak is claimed to open without one. The result
document carries NO download API.
"""
from __future__ import annotations

import json
import sys

if __package__:
    from .waystunnel import TWEAK_SCHEME, decrypt_tweak, encrypt_tweak
else:
    from waystunnel import TWEAK_SCHEME, decrypt_tweak, encrypt_tweak

SCHEMES = (TWEAK_SCHEME,)


class WaysDecodeError(ValueError):
    """Decode failure with a worker ``code``."""

    def __init__(self, message, code="DECODE_FAILED"):
        super().__init__(message)
        self.code = code


def decode_text(text, password=None) -> str | None:
    """``wyst://`` link -> worker document, or None if not a Ways link."""
    if not isinstance(text, str):
        return None
    value = text.strip()
    if not value.lower().startswith(TWEAK_SCHEME):
        return None
    if password is not None:
        raise WaysDecodeError(
            "Los tweaks wyst:// no admiten contraseña.",
            code="CREDENTIALS_NOT_ALLOWED")
    try:
        plain = decrypt_tweak(value)
        config = json.loads(plain)
    except (ValueError, UnicodeError):
        return None
    if not isinstance(config, dict):
        return None
    doc = {"application": "Ways Tunnel 18.1",
           "protocol": TWEAK_SCHEME, "config": config}
    return json.dumps(doc, ensure_ascii=False, indent=2)


def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: text_decoder.py 'wyst://...'", file=sys.stderr)
        return 2
    try:
        out = decode_text(sys.argv[1])
    except WaysDecodeError as error:
        print(str(error), file=sys.stderr)
        return 3
    if out is None:
        print("Enlace wyst:// inválido o no descifrable.", file=sys.stderr)
        return 1
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
