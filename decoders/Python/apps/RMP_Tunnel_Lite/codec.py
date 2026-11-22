"""RMP TUNNEL LITE RMP-4: shared, independently verified XXTEA catalog.

No new crypto. The catalog engine is the already-integrated
``python-shared-mx-xxtea`` motor, reused through the RMP TUNNEL PRO
module (``decoders/Python/apps/RMP_TUNNEL_PRO/codec.py``), which itself
delegates to ``decoders/Python/apps/Mx_Tunnel_PRO/codec.py`` and the
``HX_Tunnel_VPN`` shared primitives. The Lite APK ships the
byte-identical embedded asset ``gremlin.json`` as PRO (SHA-256
03c9cc0f2baa6e46026f8759715867071b2796e9af30b03e1c2186c202223501,
version 3.8, 40 free servers, 1211 payloads), and its live catalog
bytes are identical to the live RMPPRO bytes, so the same key, delta
(0x9e5729b1) and schema open it. The only Lite divergence is the fixed
catalog URL (``.../RMPLITE`` instead of ``.../RMPPRO``), which lives in
``server_catalog_decoder.py``, not here.
"""
from __future__ import annotations
from pathlib import Path
import sys
if __package__ and '.' in __package__:
    from ..RMP_TUNNEL_PRO import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from RMP_TUNNEL_PRO import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
LIST_FIELDS = shared.LIST_FIELDS
# Hm.a/b/f/g and C0195zJ.e match the shared key, delta and schema.


def decode_catalog(data: bytes) -> dict:
    try:
        return shared.decode_catalog(data)
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise DecodeError('Catálogo inválido o incompatible con RMP TUNNEL LITE RMP-4.') from None
