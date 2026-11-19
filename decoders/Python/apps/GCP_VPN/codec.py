"""GCP VPN 1.1 (11) catalog via the shared RENZ route.

No new crypto: the catalog envelope and every nested field use the
canonical ``decoders/Python/renz.py`` profile ``gcpvpn`` exactly as the
live catalog was verified on 2026-11-19 (outer AES-128-CBC + custom
XXTEA + byte -2; nested hosts via Threefish/HKDF, credentials via
PBKDF2-XXTEA-AES, the rest via the generic recursive pass). A 7NET-style
explicit per-field codec was NOT written: there is no APK evidence for a
GCP-specific field-mode table, and the generic pass already decrypts
2,736 fields of the live catalog (Version "3304", 90 servers,
334 networks). Fields it cannot open (51 short presentation
names/infos) are served as-is, never invented.

SlowDNS.PubKey note (corrected 2026-11-19): the 10 PubKeys DO open with
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
CATALOG_URL = 'https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/gcpvpn2026'


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
        raise DecodeError('Sobre exterior inválido para GCP VPN 1.1.') from None
    if not text:
        raise DecodeError('Sobre exterior inválido para GCP VPN 1.1.')
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
        raise DecodeError('Catálogo inválido o incompatible con GCP VPN 1.1.') from None


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
