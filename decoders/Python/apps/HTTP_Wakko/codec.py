"""HTTP Wakko 4.9: independently verified recipe, including its two BHTTP fields."""
from __future__ import annotations
import json
from pathlib import Path
import sys

if __package__ and "." in __package__:
    from ..HTTP_SocketClay import codec as crypto
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_SocketClay import codec as crypto

# Build 40 native KDF/ChaCha/AESED parameters match these shared primitives.
# Wakko's field schema is separate: SocketClay lacks BhttpUpSlot/BhttpDownSlot.
shared = crypto.shared
DecodeError = crypto.DecodeError
MAX_BYTES = crypto.MAX_BYTES
render = crypto.render
field_key = crypto.field_key
decode_field = crypto.decode_field
decrypt_catalog = crypto.decrypt_catalog
_names = json.loads(Path(__file__).with_name("field_names.json").read_text("utf-8"))
SERVER_FIELDS = frozenset(_names["servers"].values())
USER_FIELDS = frozenset(_names["users"].values())


def decode_catalog(data: bytes) -> dict:
    try:
        return crypto.decode_catalog_fields(data, server_fields=SERVER_FIELDS,
            user_fields=USER_FIELDS, display_key=_names["servers"]["sName"])
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise DecodeError("Catálogo inválido o no compatible con HTTP Wakko 4.9.") from exc
