#!/usr/bin/env python3
"""Lossless experimental EHI standard-IV v1 export. No production integration.

Preserve both JSON layers and the original binary framing. Access changes are
diagnostics, not a claim about the original importer's lock-hash validation.
"""
from __future__ import annotations
import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import zlib

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad
from argon2.low_level import hash_secret_raw, Type

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from decoders.Python.HTTPINJECTOR import EHIConstants as C, EHIDecryptor as D, _aes_cbc_decrypt
from tests.golden.a23_batch7 import _xxtea_encrypt
from lossless_json import parse, replace_values, equal

MAX_BYTES = 16 * 1024 * 1024


class EhiLabError(ValueError):
    pass


def b64(raw):
    try:
        return base64.b64decode(raw, validate=True)
    except (ValueError, TypeError):
        raise EhiLabError('INVALID_BASE64') from None


def decode_field(token, salt):
    if not isinstance(token, str) or '?' in token or not salt or not salt.isascii():
        raise EhiLabError('UNSUPPORTED_FIELD_CARRIER')
    standard = token[::-1].translate(str.maketrans(C.CUSTOM_ALPHABET, C.STD_ALPHABET))
    raw_hex = b64(standard + '=' * (-len(standard) % 4))
    if not re.fullmatch(rb'(?:[0-9a-fA-F]{2})+', raw_hex):
        raise EhiLabError('INVALID_FIELD_HEX')
    upper = any(65 <= x <= 70 for x in raw_hex)
    data = bytes.fromhex(raw_hex.decode('ascii'))
    clear = bytes(v ^ ord(salt[n % len(salt)]) for n, v in enumerate(data))
    return clear, upper


def encode_field(clear, salt, upper=True):
    data = bytes(v ^ ord(salt[n % len(salt)]) for n, v in enumerate(clear))
    encoded = data.hex().upper() if upper else data.hex()
    return base64.b64encode(encoded.encode('ascii')).decode('ascii').translate(
        str.maketrans(C.STD_ALPHABET, C.CUSTOM_ALPHABET))[::-1]


def encode_message(message):
    if not isinstance(message, str) or len(message.encode('utf-8')) > 256000:
        raise EhiLabError('INVALID_MESSAGE')
    raw = message.encode('utf-16-be')
    units = struct.unpack('>' + 'H' * (len(raw) // 2), raw)
    encrypted = struct.pack('>' + 'H' * len(units),
                            *(v ^ ord('EHIMSG'[n % 6]) for n, v in enumerate(units)))
    return base64.b64encode(encrypted.decode('utf-16-be').encode('utf-8')).decode('ascii')


def kdf_key(outer, body):
    if len(body) < 66 or body[0] != 1:
        raise EhiLabError('UNSUPPORTED_AEAD_VERSION')
    time_cost, memory = struct.unpack_from('<II', body, 1)
    lanes = body[9]
    if not (1 <= time_cost <= 10 and 1 <= lanes <= 8 and 8 * lanes <= memory <= 262144):
        raise EhiLabError('KDF_LIMIT_EXCEEDED')
    return hash_secret_raw(D._generate_master_key(outer), body[10:26],
        time_cost=time_cost, memory_cost=memory, parallelism=lanes,
        hash_len=32, type=Type.ID)


@dataclass
class EhiDocument:
    source: bytes
    length_offset: int
    payload_offset: int
    payload_size: int
    iv_index: int
    iv2: bytes
    middle: bytes
    xx_prefix: bytes
    raw_outer: bytes
    outer: dict
    aead: bytes
    upper_hex: bool
    raw_inner: bytes
    inner: dict


def open_profile(source):
    if not isinstance(source, bytes) or not 40 <= len(source) <= MAX_BYTES:
        raise EhiLabError('INVALID_SIZE')
    pos = 0
    for slot in range(2):
        if pos + 2 > len(source):
            raise EhiLabError('TRUNCATED_HEADER')
        size = int.from_bytes(source[pos:pos+2], 'big')
        pos += 2
        if pos + size + 8 > len(source):
            raise EhiLabError('TRUNCATED_HEADER')
        if slot == 0 and source[pos:pos+size] != b'ehi':
            raise EhiLabError('UNSUPPORTED_FILE_MAGIC')
        # Preserve Java modified-UTF and opaque long slots without normalization.
        pos += size + 8
    length_offset = pos
    if pos + 12 > len(source):
        raise EhiLabError('TRUNCATED_LENGTH')
    size = int.from_bytes(source[pos:pos+4], 'big')
    payload_offset = pos + 12
    payload = source[payload_offset:payload_offset+size]
    if len(payload) != size or not size or size % 16:
        raise EhiLabError('INVALID_PAYLOAD_LENGTH')
    stored_checksum = int.from_bytes(source[pos+4:pos+12], 'big')
    if stored_checksum != zlib.adler32(payload) & 0xffffffff:
        raise EhiLabError('FRAME_ADLER32_MISMATCH')
    matches = []
    for index, iv in enumerate(C.BYPASS_IVS + C.STANDARD_IVS):
        try:
            l1 = _aes_cbc_decrypt(payload, C.L1_KEY, iv)
            parts = l1.split(b':')
            if len(parts) != 3:
                continue
            iv2 = b64(parts[0])
            if len(iv2) != 16:
                continue
            xx_cipher = _aes_cbc_decrypt(b64(parts[2]), C.L2_KEY_STATIC, iv2)
            xx_plain = D._xxtea_decrypt(xx_cipher, C.EOO_MASTER_KEY)
            start = xx_plain.find(b'{')
            if start < 0:
                continue
            outer = parse(xx_plain[start:])
            if not isinstance(outer, dict):
                continue
            # This confirms the original length word, zero padding and XXTEA
            # variant; do not silently normalize an unrecognized packing style.
            if _xxtea_encrypt(xx_plain, C.EOO_MASTER_KEY) != xx_cipher:
                continue
            matches.append((index, iv2, parts[1], xx_plain[:start], xx_plain[start:], outer))
        except (ValueError, TypeError, UnicodeError, KeyError, struct.error):
            continue
    if len(matches) != 1:
        raise EhiLabError('OUTER_DECRYPT_FAILED_OR_AMBIGUOUS')
    index, iv2, middle, prefix, raw_outer, outer = matches[0]
    if index < 3:
        raise EhiLabError('NON_AEAD_VARIANT_NOT_IN_THIS_LAB')
    salt = outer.get('configSalt')
    if type(salt) is not str or not salt or not salt.isascii():
        raise EhiLabError('UNSUPPORTED_FIELD_SALT')
    field, upper = decode_field(outer.get('configData'), salt)
    if encode_field(field, salt, upper) != outer['configData']:
        raise EhiLabError('NONCANONICAL_CONFIG_DATA_CARRIER')
    body = b64(field)
    key = kdf_key(outer, body)
    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=body[26:50])
        cipher.update(body[:26])
        raw_inner = cipher.decrypt_and_verify(body[50:-16], body[-16:])
        inner = parse(raw_inner)
    except (ValueError, UnicodeError):
        raise EhiLabError('AUTH_OR_INNER_JSON_FAILED') from None
    if not isinstance(inner, dict):
        raise EhiLabError('INNER_OBJECT_REQUIRED')
    return EhiDocument(source, length_offset, payload_offset, size, index, iv2,
                       middle, prefix, raw_outer, outer, body, upper, raw_inner, inner)


def reseal(document, *, outer_edits=None, inner_edits=None,
           allow_unverified_middle=False):
    outer_edits, inner_edits = outer_edits or {}, inner_edits or {}
    if set(outer_edits) - {'lockModes', 'lockModesHash'} or set(inner_edits) - {'isConfigLock', 'configMessage'}:
        raise EhiLabError('EDIT_OUTSIDE_LAB_SCOPE')
    for mapping, original in ((outer_edits, document.outer), (inner_edits, document.inner)):
        if any(k not in original or type(v) is not type(original[k]) for k, v in mapping.items()):
            raise EhiLabError('FIELD_MISSING_OR_TYPE_CHANGED')
    raw_inner = replace_values(document.raw_inner, {(k,): v for k, v in inner_edits.items()})
    raw_outer = replace_values(document.raw_outer, {(k,): v for k, v in outer_edits.items()})
    outer = parse(raw_outer)
    changed = raw_inner != document.raw_inner or raw_outer != document.raw_outer
    # The owner accepted only the byte-identical A control. Every changed case
    # retained the original carrier middle segment while replacing ciphertext.
    # Its 32 decoded bytes resemble a MAC, but neither its key nor verification
    # rule has been recovered. An AEAD round trip does not verify this segment.
    # Keep historical reproduction possible without presenting it as an export.
    if changed and not allow_unverified_middle:
        raise EhiLabError('MODIFIED_EXPORT_BLOCKED_UNVERIFIED_CARRIER_SEGMENT')
    header = document.aead[:50]
    if changed:
        header = document.aead[:10] + os.urandom(16) + os.urandom(24)
    key = kdf_key(outer, header + bytes(16))
    cipher = ChaCha20_Poly1305.new(key=key, nonce=header[26:50])
    cipher.update(header[:26])
    ciphertext, tag = cipher.encrypt_and_digest(raw_inner)
    body = header + ciphertext + tag
    token = encode_field(base64.b64encode(body), outer['configSalt'], document.upper_hex)
    if token != outer['configData']:
        raw_outer = replace_values(raw_outer, {('configData',): token})
    xx_cipher = _xxtea_encrypt(document.xx_prefix + raw_outer, C.EOO_MASTER_KEY)
    second = AES.new(C.L2_KEY_STATIC, AES.MODE_CBC, document.iv2).encrypt(pad(xx_cipher, 16))
    carrier = base64.b64encode(document.iv2) + b':' + document.middle + b':' + base64.b64encode(second)
    iv = (C.BYPASS_IVS + C.STANDARD_IVS)[document.iv_index]
    first = AES.new(C.L1_KEY, AES.MODE_CBC, iv).encrypt(pad(carrier, 16))
    raw = (document.source[:document.length_offset] + struct.pack('>I', len(first)) +
           struct.pack('>Q', zlib.adler32(first) & 0xffffffff) + first +
           document.source[document.payload_offset+document.payload_size:])
    after = open_profile(raw)
    if after.raw_inner != raw_inner or after.raw_outer != raw_outer:
        raise EhiLabError('ROUNDTRIP_PLAINTEXT_MISMATCH')
    expected_outer = dict(document.outer, **outer_edits)
    expected_outer['configData'] = after.outer['configData']
    if not equal(after.outer, expected_outer) or not equal(after.inner, dict(document.inner, **inner_edits)):
        raise EhiLabError('UNRELATED_CONFIGURATION_CHANGED')
    return raw


def access_candidate_edits(document):
    # These two strings already exist together in the authenticated inner JSON.
    # Reuse them rather than guessing how the original lock hash is computed.
    # Their validity in the outer importer remains a manual-test hypothesis.
    if (document.inner.get('lockModes') != '["none"]' or
            not re.fullmatch(r'[a-fA-F0-9]{64}', document.inner.get('lockModesHash', '')) or
            type(document.inner.get('isConfigLock')) is not bool):
        raise EhiLabError('OBSERVED_NONE_METADATA_REQUIRED')
    return ({k: document.inner[k] for k in ('lockModes', 'lockModesHash')}, {'isConfigLock': False})


def private_write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)


def summary(document):
    return {'source_sha256': hashlib.sha256(document.source).hexdigest(),
            'bytes': len(document.source), 'outer_json_bytes': len(document.raw_outer),
            'inner_json_bytes': len(document.raw_inner), 'iv_index': document.iv_index,
            'source_config_version_code': (document.outer.get('configVersionCode')
                if type(document.outer.get('configVersionCode')) is int else None),
            'aead_version': document.aead[0], 'authenticated': True,
            'authentication_scope': 'inner_aead_only',
            'carrier_integrity_verified': False,
            'modified_export_status': 'blocked_pending_carrier_integrity',
            'frame_checksum': 'adler32_verified',
            'original_app_import': 'pending'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        document = open_profile(args.source.read_bytes())
        result = summary(document)
        if args.output is not None:
            output = reseal(document)
            private_write(args.output, output)
            result['rewrap_byte_identical'] = output == document.source
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, TypeError, KeyError, struct.error, RecursionError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, EhiLabError) else 'INPUT_OR_OUTPUT_ERROR'}), file=sys.stderr)
        sys.exit(1)
