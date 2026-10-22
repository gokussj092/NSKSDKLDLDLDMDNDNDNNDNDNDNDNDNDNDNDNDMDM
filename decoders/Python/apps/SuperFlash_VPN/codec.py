"""SuperFlash 184.0.1 SV5C v2, release 157; offline, authenticated full records."""
from __future__ import annotations
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Signature import eddsa
from Crypto.Util.Padding import unpad

if __package__ and '.' in __package__:
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
render = shared.render
# Native libspeigoshield.so: SV5C verifier and SVR5B2 key/AAD derivation.
SIGNATURE_PUBLIC_KEY = bytes.fromhex('e6520ef2b0b219bad6aaf6438dd71441af50f8291942af6a0b26a6cf42cf176b')
ROOT_KEY = bytes.fromhex('0f95b23b72e53068a580189404d3527f426463d57aefbb93a01c3b7a13b9570e')
CONTEXT = bytes.fromhex('00e5a040735a5873f6a298a5408cb87776cee8682df31792e1a2c503bb561b8e')
BASE_SALT = bytes.fromhex('e16bc172948f3d5add29a76b8f30461e')
RECORD_SALT = bytes.fromhex('0f34b5982d7ae6c1')
AAD_SALT = bytes.fromhex('38d6e952af04b17b')
RELEASE = struct.pack('<I', 157)
SIGNATURE_SUFFIX = bytes.fromhex('d2f5270a3b6c91e4')
FIELD_KEY = b'Diablo2105AZW8Es'.ljust(32, b'\0')  # assets/LICENSE SSH_UDP
# Same opaque resource names; crypto and envelope are specific to SuperFlash.
SERVER_FIELDS = shared.SERVER_FIELDS
USER_FIELDS = shared.USER_FIELDS


def _json(data: bytes):
    value = json.loads(data.decode('utf-8'), object_pairs_hook=shared._unique,
                       parse_constant=shared._constant)
    shared._validate(value)
    return value


def decode_field(value: str) -> str:
    if not isinstance(value, str):
        raise DecodeError('Campo cifrado incompatible.')
    if not value:
        return value
    raw = shared._base64(value, urlsafe=True)
    if len(raw) < 32 or len(raw) % 16:
        raise DecodeError('Campo cifrado incompatible.')
    text = unpad(AES.new(FIELD_KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]), 16).decode('utf-8')
    return shared.rotate_java(text, 21)  # Servers.decoder(value, 5)


def decode_catalog(data: bytes) -> dict:
    try:
        shared._bounded(data)
        if len(data) < 84:
            raise DecodeError('Sobre SV5C incompleto.')
        magic, version, purpose, reserved, release, count, meta_size = struct.unpack_from('<4sBBHIII', data)
        if (magic != b'SV5C' or version != 2 or purpose not in (1, 2)
                or reserved or release != 157 or not 1 <= count <= 4096
                or not 1 <= meta_size <= 512 * 1024 or 20 + meta_size > len(data) - 64):
            raise DecodeError('Sobre SV5C incompatible.')
        unsigned = data[:-64]
        message = hashlib.sha256(b'SV5C-SIG-V2\0' + unsigned + SIGNATURE_SUFFIX).digest()
        eddsa.new(eddsa.import_public_key(SIGNATURE_PUBLIC_KEY), 'rfc8032').verify(message, data[-64:])
        metadata_bytes = data[20:20 + meta_size]
        metadata = _json(metadata_bytes)
        section, other = ('Servers', 'Usuarios') if purpose == 1 else ('Usuarios', 'Servers')
        if (not isinstance(metadata, dict) or not isinstance(metadata.get('Version'), str)
                or not metadata['Version'] or other in metadata
                or not isinstance(metadata.get(section), list) or len(metadata[section]) != count
                or any(not isinstance(item, dict) or not item for item in metadata[section])):
            raise DecodeError('Metadatos SV5C incompatibles.')
        meta_hash = hashlib.sha256(metadata_bytes).digest()
        purpose_byte = bytes([purpose])
        base_key = hmac.digest(ROOT_KEY, b'SVR5B2-BASE-KDF-V1\0' + BASE_SALT + RELEASE + purpose_byte + CONTEXT, 'sha256')
        fields = SERVER_FIELDS if purpose == 1 else USER_FIELDS
        result = metadata.copy()
        records = []
        offset = 20 + meta_size
        for index, presentation in enumerate(metadata[section]):
            if offset + 48 > len(unsigned):
                raise DecodeError('Registro SV5C incompleto.')
            record_index, size = struct.unpack_from('<II', data, offset)
            if record_index != index or not 1 <= size <= 512 * 1024 or offset + 48 + size > len(unsigned):
                raise DecodeError('Registro SV5C incompatible.')
            index_bytes = struct.pack('<I', index)
            key = hmac.digest(base_key, b'SVR5B2-REC-KDF-V1\0' + RECORD_SALT + RELEASE + index_bytes + purpose_byte + meta_hash + CONTEXT, 'sha256')
            aad = data[:20] + meta_hash + AAD_SALT + RELEASE + struct.pack('<II', index, size) + purpose_byte + CONTEXT
            cipher = ChaCha20_Poly1305.new(key=key, nonce=data[offset + 8:offset + 32])
            cipher.update(aad)
            record = _json(cipher.decrypt_and_verify(data[offset + 32:offset + 32 + size], data[offset + 32 + size:offset + 48 + size]))
            if not isinstance(record, dict) or not record:
                raise DecodeError('Registro JSON incompatible.')
            # Preserve presentation-only metadata and reject conflicting copies.
            if any(record[k] != v for k, v in presentation.items() if k in record):
                raise DecodeError('Metadatos de registro inconsistentes.')
            entry = {**presentation, **record}
            for name in fields & entry.keys():
                entry[name] = decode_field(entry[name])
            records.append(entry)
            offset += 48 + size
        if offset != len(unsigned):
            raise DecodeError('Datos SV5C sobrantes.')
        result[section] = records
        shared._validate(result)
        return result
    except (ValueError, UnicodeError, RecursionError, TypeError, struct.error, OverflowError):
        raise DecodeError('Catálogo inválido o incompatible con SuperFlash VPN 184.0.1.') from None
