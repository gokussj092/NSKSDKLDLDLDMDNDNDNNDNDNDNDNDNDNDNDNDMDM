"""MD PROXY VPN build29 uses the independently checked Ultra/Sandok envelope.

Its native CU uses the same public document and format constants as Ultra59.
Keep the common bounded implementation unchanged; MD identity/UA are separate.
"""
from ..Ultra_Tunnel.codec import DecodeError, MAX_BYTES, decode_catalog as _decode, render


def decode_catalog(data):
    try:
        return _decode(data)
    except (ValueError, TypeError, RecursionError):
        raise DecodeError("Catálogo MD PROXY VPN inválido o incompatible.") from None


def run(data):
    return render(decode_catalog(data))
