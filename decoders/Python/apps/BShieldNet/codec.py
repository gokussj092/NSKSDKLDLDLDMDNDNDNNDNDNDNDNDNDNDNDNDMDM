"""B SHIELD NET 2.9 (29) catalog via the shared RENZ route.

No new crypto and NO new profile in ``decoders/Python/renz.py``:
the catalog envelope and every nested field dispatch EXPLICITLY to
the existing profile ``bshield``. The key material is the one
already registered for ``bshield`` (same seed/IV/salt, same live
catalog URL, same ``.bshield`` suffix and ``bshieldnet://`` /
``bshield://`` schemes). This is deliberate: a server-side
catalog/file/text update must NOT touch the APK, so no ``bshield``
profile is added here -- it already exists -- and nothing under
``android/`` changes. B SHIELD NET stays online-only for its live
catalog, exactly like GCP VPN / NetFlux VPN; its ``.bshield`` files
and ``bshieldnet://`` / ``bshield://`` links are already served by
the frozen C0 route (``decoders/Python/renz.py`` via
``docs/cloud/C0_FORMAT_MATRIX.csv``) and the generic RENZ text
handler, so this module only adds the catalog codec.

The outer envelope is Base64 -> AES-128-CBC (key =
SHA-256(KEY_SEED)[:16], fixed IV, PKCS7) -> custom XXTEA (delta
0x7A56D3E1, 6 + 52/n rounds) -> subtract 2 per byte -> JSON; the
nested fields open with the generic recursive pass
(HKDF/PBKDF2 + Threefish/AES/XXTEA, modes 0/1/2/3). The inverse
generator is verified: re-encrypting the live plaintext reproduces
the live blob byte for byte (see ``bshieldnet.py`` and the dossier
``analysis/xyz.bshieldnet.org/29/``).
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
CATALOG_URL = ('https://raw.githubusercontent.com/snapb/B-SHIELD-NET-2026/'
               'refs/heads/main/b_shield_net_2026')
PROFILE = 'bshield'


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
        text = shared.renz_decrypt_main(data.strip(), PROFILE)
    except Exception:
        raise DecodeError('Sobre exterior inválido para B SHIELD NET 2.9.') from None
    if not text:
        raise DecodeError('Sobre exterior inválido para B SHIELD NET 2.9.')
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
        shared.renz_recursive_decrypt_main(doc, PROFILE)
        if (not isinstance(doc.get('Servers'), list) or not doc['Servers'] or
                not isinstance(doc.get('Networks'), list) or not doc['Networks']):
            raise DecodeError('Faltan secciones completas del catálogo.')
        return doc
    except DecodeError:
        raise
    except (ValueError, UnicodeError, KeyError, TypeError,
            RecursionError, OverflowError):
        raise DecodeError('Catálogo inválido o incompatible con B SHIELD NET 2.9.') from None


def render(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
