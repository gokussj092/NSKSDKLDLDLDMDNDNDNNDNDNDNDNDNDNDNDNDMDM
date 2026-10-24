"""RJC TUNNEL PRO RJC-6: shared, independently verified XXTEA catalog."""
from __future__ import annotations
from pathlib import Path
import sys
if __package__ and '.' in __package__:
    from ..Mx_Tunnel_PRO import codec as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from Mx_Tunnel_PRO import codec as shared

DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
render=shared.render
LIST_FIELDS=shared.LIST_FIELDS
# AbstractC0015Mm.a/b/f/g and HJ.e match the shared key, delta and schema.


def decode_catalog(data: bytes) -> dict:
    try:
        return shared.decode_catalog(data)
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con RJC TUNNEL PRO RJC-6.') from None
