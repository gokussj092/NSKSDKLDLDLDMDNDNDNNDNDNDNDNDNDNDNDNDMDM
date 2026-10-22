"""TurboMX VPN 143.1.26 SV5C v2/release 143 with its own fixed native material."""
from __future__ import annotations
from pathlib import Path
import sys

if __package__ and '.' in __package__:
    from ..SuperFlash_VPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from SuperFlash_VPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
SIGNATURE_PUBLIC_KEY = bytes.fromhex('1f213845526722ec9f86e5b3009da7b81e09e51674e823e114df2d7ba494adc9')
ROOT_KEY = bytes.fromhex('e973cfb02d8a0fc2102cd8a0351c199c1cba7c04a507d082fa68231bea2f4fb3')
CONTEXT = bytes.fromhex('8a6d9413d68bb509c4976a19877b4cfadb74c2f7b6dcd1f8ce9d10836fd9ae2f')
SERVER_FIELDS = shared.SERVER_FIELDS
USER_FIELDS = shared.USER_FIELDS


def decode_catalog(data: bytes) -> dict:
    try:
        return shared.decode_sv5c(data, release_code=143, signature_key=SIGNATURE_PUBLIC_KEY,
                                  root_key=ROOT_KEY, context=CONTEXT)
    except DecodeError:
        raise DecodeError('Catálogo inválido o incompatible con TurboMX VPN 143.1.26.') from None
