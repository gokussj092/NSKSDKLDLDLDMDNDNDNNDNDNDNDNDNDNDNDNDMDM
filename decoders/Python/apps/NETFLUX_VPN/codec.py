"""NetFlux VPN 1.1 (11) catalog via the shared RENZ route.

No new crypto and NO new profile in ``decoders/Python/renz.py``:
the catalog envelope and every nested field dispatch EXPLICITLY to
the existing profile ``gcpvpn``. The key material is byte-identical
to ``gcpvpn`` (same developer, same signer, same catalog blob: the
live ``netflux`` blob is byte-identical to ``gcpvpn2026``, SHA-256
fff27a6d...044e, Version "3304", 90 servers, 334 networks), so the
``gcpvpn`` profile opens it exactly as the live catalog was verified
on 2026-11-20 (outer AES-128-CBC + custom XXTEA + byte -2; nested
hosts via Threefish/HKDF, credentials via PBKDF2-XXTEA-AES, the rest
via the generic recursive pass). This is deliberate: a server-side
catalog/file/text update must NOT touch the APK, so no ``netflux``
profile, suffix or scheme is registered in ``renz.py`` (and nothing
under ``android/`` changes). If the NetFlux and GCP blobs ever
diverge, that is a separate decision to take then -- not something
to pre-register now. NetFlux stays online-only, with no offline
port, exactly like GCP VPN.

A 7NET-style explicit per-field codec was NOT written: there is no
APK evidence for a NetFlux-specific field-mode table, and the generic
pass already decrypts 2,736 fields of the live catalog. Fields it
cannot open (51 short presentation names/infos) are served as-is,
never invented.

SlowDNS.PubKey note (same as GCP VPN): the 10 PubKeys DO open with
the generic ``main`` mode to a 64-char hex key -- the same dispatch the
7NET codec documents explicitly for SlowDNS.PubKey (mode 0). The
``speciale`` mode returns non-printable garbage for them, so no
fallback change was made in ``renz.py``.
"""
from __future__ import annotations
import json
from pathlib import Path
import sys

if __package__ and __package__.startswith('decoders.'):
    from ... import renz as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import renz as shared

MAX_BYTES = 8 * 1024 * 1024
CATALOG_URL = 'https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/netflux'


class DecodeError(ValueError):
    pass


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DecodeError('JSON ambiguo.')
        out[key] = value
    return out


def _invalid_constant(value):
    raise DecodeError('Constante JSON inválida.')


def open_outer(data: bytes) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise DecodeError('Entrada vacía o superior a 8 MiB.')
    try:
        text = shared.renz_decrypt_main(data.strip(), 'gcpvpn')
    except Exception:
        raise DecodeError('Sobre exterior inválido para NetFlux VPN 1.1.') from None
    if not text:
        raise DecodeError('Sobre exterior inválido para NetFlux VPN 1.1.')
    try:
        doc = json.loads(text, object_pairs_hook=_unique,
                         parse_constant=_invalid_constant)
    except ValueError:
        raise DecodeError('Sobre exterior sin JSON válido.') from None
    if (not isinstance(doc, dict) or 'Version' not in doc or
            not isinstance(doc.get('Servers'), list) or not doc['Servers'] or
            not isinstance(doc.get('Networks'), list) or not doc['Networks']):
        raise DecodeError('Faltan secciones completas del catálogo.')
    return doc


def decode_catalog(data: bytes) -> dict:
    try:
        doc = open_outer(data)
        shared.renz_recursive_decrypt_main(doc, 'gcpvpn')
        if (not isinstance(doc.get('Servers'), list) or not doc['Servers'] or
                not isinstance(doc.get('Networks'), list) or not doc['Networks']):
            raise DecodeError('Faltan secciones completas del catálogo.')
        return doc
    except DecodeError:
        raise
    except (ValueError, UnicodeError, KeyError, TypeError,
            RecursionError, OverflowError):
        raise DecodeError('Catálogo inválido o incompatible con NetFlux VPN 1.1.') from None


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
