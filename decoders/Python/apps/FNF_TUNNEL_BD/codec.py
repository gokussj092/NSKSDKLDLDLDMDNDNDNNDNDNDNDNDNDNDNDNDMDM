"""FNF TUNNEL BD PrinceBuild35 catalog: Base64 / modified XXTEA / plain JSON.

Reuse only the independently matched outer primitive. Catalog fields are already
plaintext in this app; applying BD NET's nested hex/XOR heuristic corrupts them.
"""
from decoders.Python.apps.BD_NET_VPN.codec import (
    CatalogError, MAX_INPUT, decode_outer_bytes, parse_document, render,
)

def decode_catalog(data: bytes) -> dict:
    doc=parse_document(decode_outer_bytes(data).decode('utf-8'))
    if not doc['Free_servers'] or not doc['Payloads']:
        raise CatalogError('FNF catalog has no servers or payloads')
    return doc

def run(data: bytes) -> str:
    return render(decode_catalog(data)).decode('utf-8')
