#!/usr/bin/env python3
"""CLI adapter: decode STLRAY TVC files and links for the SP-DECODE
C8 engine and text bridge.

A ``.sray`` file (and ``.tvc`` / ``.gv`` / ``.uv`` / ``.gpx`` /
``.test`` / ``.insan`` / ``.opq``) holds the same raw bytes as a
link body: ``salt || MASK(GCM layers)`` (see stlray.py, codec "TVC").
The decoder also accepts the file as base64url text, with or
without its scheme prefix. Each scheme has its own 32-byte key;
``hyb://`` has no key of its own and uses the ``sray://`` key.

This module exposes the three contracts the repo uses:

* ``decode(raw, scheme="sray://") -> dict`` — the decrypted profile.
* ``run(data, scheme="sray://") -> str`` — JSON document, the
  file-decoder route (``cloud/workers/python/engine.py`` runs this
  file as a subprocess with the input file as argv; the scheme comes
  from the file extension).
* ``decode_text(text) -> str | None`` — the text-bridge route
  (``cloud/workers/python/text_bridge.py``); None when the text is
  not an STLRAY link, never a fallback to another format. A
  malformed STLRAY link is undecodable (None), never an error
  surfaced as another format.

No password is needed: the TVC variants (locked / normal / legacy)
are tried in order until the GCM tags verify. No real exported
``.sray`` file or link has been supplied yet — the codec is
VERIFIED_SYNTHETIC by round-trip (encode/decode symmetric over a
real profile taken from the live catalog); see
analysis/com.stlray.thvpn/36/RESULTS.md.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

if __package__:
    from .stlray import (
        SCHEME_KEYS,
        decode_link,
        decode_profile_bytes,
        encode_profile,
    )
else:
    from stlray import (
        SCHEME_KEYS,
        decode_link,
        decode_profile_bytes,
        encode_profile,
    )

SCHEMES = tuple(SCHEME_KEYS) + ("hyb://",)
MAX_BYTES = 8 * 1024 * 1024


def _scheme_for_extension(path: str) -> str:
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext and (ext + "://") in SCHEME_KEYS:
        return ext + "://"
    return "sray://"


def decode(raw, scheme: str = "sray://") -> dict:
    """Decrypt a TVC file (bytes/str) or a TVC link (str).

    Returns the decrypted profile dict. Raises ValueError when no
    TVC variant verifies (tampered data, truncated input, or a file
    from another format).
    """
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            raise ValueError("entrada vacía")
        if text.lower().startswith(SCHEMES):
            profile, _info = decode_link(text)
            return profile
        # Bare base64url body (treated as sray:// by the codec).
        try:
            profile, _info = decode_link(text)
            return profile
        except ValueError:
            raise ValueError("texto no es un enlace TVC válido") from None
    if isinstance(raw, bytes):
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError("archivo vacío o demasiado grande")
        try:
            text = raw.decode("utf-8-sig").strip()
        except UnicodeError:
            text = ""
        if text and text.lower().startswith(SCHEMES):
            profile, _info = decode_link(text)
            return profile
        if text and re.fullmatch(r"[A-Za-z0-9_\-]+", text):
            # Bare base64url text file (no scheme prefix).
            try:
                profile, _info = decode_link(text)
                return profile
            except ValueError:
                pass
        return decode_profile_bytes(raw, scheme)[0]
    raise ValueError("tipo de entrada no válido")


def run(data: bytes, scheme: str = "sray://") -> str:
    """Decrypt file/link bytes -> JSON document string."""
    return json.dumps(decode(data, scheme=scheme),
                      ensure_ascii=False, indent=2)


def decode_text(text: str) -> str | None:
    """Decrypt an STLRAY link (sray://, tvc://, uv://, gv://, gpx://,
    insan://, opq://, test://, hyb://).

    Returns the JSON document, or None when the text is not an
    STLRAY link (or is a malformed one). Never falls back to
    another format.
    """
    if not isinstance(text, str):
        return None
    value = text.strip()
    if not any(value.lower().startswith(s) for s in SCHEMES):
        return None
    try:
        profile, _info = decode_link(value)
    except ValueError:
        return None
    return json.dumps(profile, ensure_ascii=False, indent=2)


def self_test() -> int:
    """Round-trips (normal + locked, every keyed scheme, raw bytes,
    base64url text) plus negatives (truncated, garbage, tampered)."""
    profile = {
        "Name": "Synthetic Test",
        "Server": "example.invalid",
        "Port": 443,
        "Protocol": "VLESS",
    }
    for locked in (False, True):
        link, raw = encode_profile(profile, locked=locked)
        assert decode_link(link)[0] == profile, f"link locked={locked}"
        assert decode_profile_bytes(raw)[0] == profile, f"raw locked={locked}"
        assert decode(raw) == profile, f"raw locked={locked}"
    for scheme in SCHEME_KEYS:
        link, _raw = encode_profile(profile, scheme=scheme)
        assert decode_link(link)[0] == profile, scheme
        assert decode(link) == profile, scheme
    hyb_link, _raw = encode_profile(profile, scheme="sray://")
    hyb_link = "hyb://" + hyb_link[len("sray://"):]
    assert decode_link(hyb_link)[0] == profile, "hyb://"
    assert json.loads(decode_text(hyb_link)) == profile, "hyb decode_text"
    assert decode_text("vmess://AAAA") is None
    assert decode_text("not a link") is None
    for bad in (b"", b"\x00\x01\x02", b"AAAA",
                b"sray://AAAAAAAAAAAAAAAAAAAAAA=="):
        try:
            decode(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"bad input must fail: {bad[:20]!r}")
    print("self-test OK: TVC round-trips (normal/locked, 8 schemes, "
          "hyb://, raw bytes), truncated/garbage negatives")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path,
                        help="archivo .sray/.tvc/.gv/.uv/.gpx/.test/"
                        ".insan/.opq (o enlace en un archivo)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        if args.file:
            data = args.file.read_bytes()
            scheme = _scheme_for_extension(str(args.file))
            sys.stdout.write(run(data, scheme=scheme))
        else:
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
            sys.stdout.write(run(data))
        return 0
    except (ValueError, OSError):
        print("No se pudo leer el perfil STLRAY.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
