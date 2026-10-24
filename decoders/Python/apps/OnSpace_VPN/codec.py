"""OnSpace VPN 4.2: nibble/AES-CBC catalog and AES-CBC/ROT24 fields."""
from __future__ import annotations
import hashlib
from pathlib import Path
import sys
if __package__ and '.' in __package__:
    from ..HTTP_Jireh import codec as shared
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from HTTP_Jireh import codec as shared

DecodeError=shared.DecodeError
MAX_BYTES=shared.MAX_BYTES
render=shared.render
# ConfigUtil$1, AESCrypt.Jakey/generateKey; fixed format constants.
CATALOG_PASSWORD=b'netconexionestunnel'
CATALOG_KEY=hashlib.sha256(CATALOG_PASSWORD.hex().upper().encode('ascii')).digest()
FIELD_KEY=b'speedtunnel@2406'  # res/raw/dnsd_conf: SSH_SSL
SERVER_FIELDS=shared.SERVER_FIELDS
USER_FIELDS=shared.USER_FIELDS


def decode_catalog(data: bytes) -> dict:
    try:
        return shared.decode_catalog(data,catalog_key=CATALOG_KEY,field_key=FIELD_KEY,rotation=24)
    except (ValueError,UnicodeError,RecursionError,TypeError):
        raise DecodeError('Catálogo inválido o incompatible con OnSpace VPN 4.2.') from None
