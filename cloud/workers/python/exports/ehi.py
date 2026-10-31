#!/usr/bin/env python3
"""Lossless EHI standard-IV v1 export adapter.

Preserve both JSON layers and the original binary framing. Access changes are
diagnostics, not a claim about the original importer's lock-hash validation.
"""
from __future__ import annotations
import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
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

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from decoders.Python.HTTPINJECTOR import EHIConstants as C, EHIDecryptor as D, _aes_cbc_decrypt
from .xxtea import encrypt as _xxtea_encrypt
from .lossless import parse, replace_values, equal, put_member

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
    carrier_mac_key: bytes | None = field(default=None, repr=False)

    @property
    def field_salt(self):
        # Open.ehi (244) omits configSalt. This is the existing reader's
        # default for field codecs, not a value to insert into the outer JSON
        # or into the master-key concatenation.
        return self.outer.get('configSalt', 'EVZJNI')


def open_profile(source, *, carrier_mac_key=None, require_carrier_mac=False):
    if carrier_mac_key is not None and (type(carrier_mac_key) is not bytes or len(carrier_mac_key) != 32):
        raise EhiLabError('INVALID_CARRIER_MAC_KEY')
    if require_carrier_mac and carrier_mac_key is None:
        raise EhiLabError('CARRIER_MAC_KEY_REQUIRED')
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
    mac_failures = 0
    for index, iv in enumerate(C.BYPASS_IVS + C.STANDARD_IVS):
        try:
            l1 = _aes_cbc_decrypt(payload, C.L1_KEY, iv)
            parts = l1.split(b':')
            if len(parts) != 3:
                continue
            iv2 = b64(parts[0])
            if len(iv2) != 16:
                continue
            second = b64(parts[2])
            if carrier_mac_key is not None:
                if not hmac.compare_digest(b64(parts[1]), hmac.digest(carrier_mac_key, iv2 + second, 'sha256')):
                    mac_failures += 1
                    continue
            xx_cipher = _aes_cbc_decrypt(second, C.L2_KEY_STATIC, iv2)
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
        if not matches and mac_failures:
            raise EhiLabError('CARRIER_HMAC_MISMATCH')
        raise EhiLabError('OUTER_DECRYPT_FAILED_OR_AMBIGUOUS')
    index, iv2, middle, prefix, raw_outer, outer = matches[0]
    if index < 3:
        raise EhiLabError('NON_AEAD_VARIANT_NOT_IN_THIS_LAB')
    salt = outer.get('configSalt', 'EVZJNI')
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
                       middle, prefix, raw_outer, outer, body, upper, raw_inner, inner,
                       carrier_mac_key)


def reseal(document, *, outer_edits=None, inner_edits=None,
           allow_unverified_middle=False):
    outer_edits, inner_edits = outer_edits or {}, inner_edits or {}
    if set(outer_edits) - {'lockModes', 'lockModesHash', 'configExpiryTimestamp'} or set(inner_edits) - {'isConfigLock', 'configMessage'}:
        raise EhiLabError('EDIT_OUTSIDE_LAB_SCOPE')
    if 'configExpiryTimestamp' in outer_edits and (
            type(document.outer.get('configExpiryTimestamp')) is not int or
            type(outer_edits['configExpiryTimestamp']) is not int or
            outer_edits['configExpiryTimestamp'] != 0):
        raise EhiLabError('UNSUPPORTED_EXPIRY_METADATA')
    for mapping, original in ((outer_edits, document.outer), (inner_edits, document.inner)):
        if any((k not in original and not (mapping is inner_edits and k == 'configMessage' and type(v) is str))
               or (k in original and type(v) is not type(original[k])) for k, v in mapping.items()):
            raise EhiLabError('FIELD_MISSING_OR_TYPE_CHANGED')
    raw_inner = replace_values(document.raw_inner, {(k,): v for k, v in inner_edits.items() if k in document.inner})
    if 'configMessage' in inner_edits and 'configMessage' not in document.inner:
        raw_inner = put_member(raw_inner, (), 'configMessage', inner_edits['configMessage'])
    raw_outer = replace_values(document.raw_outer, {(k,): v for k, v in outer_edits.items()})
    outer = parse(raw_outer)
    changed = raw_inner != document.raw_inner or raw_outer != document.raw_outer
    # The owner accepted only the byte-identical A control. Every changed case
    # retained the original carrier middle segment while replacing ciphertext.
    # The recovered importer confirms HMAC-SHA256(IV2 || ciphertext2). Keep
    # read-only inspection available, but require its key for modified exports.
    # The opt-in remains solely for reproducing historical rejected artifacts.
    if changed and document.carrier_mac_key is None and not allow_unverified_middle:
        raise EhiLabError('MODIFIED_EXPORT_BLOCKED_UNVERIFIED_CARRIER_SEGMENT')
    header = document.aead[:50]
    if changed:
        header = document.aead[:10] + os.urandom(16) + os.urandom(24)
    key = kdf_key(outer, header + bytes(16))
    cipher = ChaCha20_Poly1305.new(key=key, nonce=header[26:50])
    cipher.update(header[:26])
    ciphertext, tag = cipher.encrypt_and_digest(raw_inner)
    body = header + ciphertext + tag
    token = encode_field(base64.b64encode(body), document.field_salt, document.upper_hex)
    if token != outer['configData']:
        raw_outer = replace_values(raw_outer, {('configData',): token})
    xx_cipher = _xxtea_encrypt(document.xx_prefix + raw_outer, C.EOO_MASTER_KEY)
    iv2 = os.urandom(16) if changed and document.carrier_mac_key is not None else document.iv2
    second = AES.new(C.L2_KEY_STATIC, AES.MODE_CBC, iv2).encrypt(pad(xx_cipher, 16))
    middle = (base64.b64encode(hmac.digest(document.carrier_mac_key, iv2 + second, 'sha256'))
              if document.carrier_mac_key is not None else document.middle)
    carrier = base64.b64encode(iv2) + b':' + middle + b':' + base64.b64encode(second)
    iv = (C.BYPASS_IVS + C.STANDARD_IVS)[document.iv_index]
    first = AES.new(C.L1_KEY, AES.MODE_CBC, iv).encrypt(pad(carrier, 16))
    raw = (document.source[:document.length_offset] + struct.pack('>I', len(first)) +
           struct.pack('>Q', zlib.adler32(first) & 0xffffffff) + first +
           document.source[document.payload_offset+document.payload_size:])
    if len(raw) >= 500000:
        raise EhiLabError('ORIGINAL_IMPORTER_SIZE_LIMIT_EXCEEDED')
    after = open_profile(raw, carrier_mac_key=document.carrier_mac_key)
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


def lock_hash_rule(document):
    """Select only a formula that reproduces this source's existing hash.

    Observed separately in real 229 and 244 exports. Version numbers alone
    never select a rule, and inner hashes are never transplanted into outer.
    """
    outer = document.outer
    modes, stored = outer.get('lockModes'), outer.get('lockModesHash')
    if type(modes) is not str or type(stored) is not str:
        raise EhiLabError('LOCK_HASH_CONTEXT_UNSUPPORTED')
    candidates = []
    salt, identifier = outer.get('configSalt'), outer.get('configIdentifier')
    if type(salt) is str and salt:
        candidates.append(('modes_then_explicit_salt', modes + salt))
    if type(identifier) is str and identifier:
        candidates.append(('identifier_then_modes', identifier + modes))
    matched = [name for name, text in candidates
               if hashlib.sha256(text.encode('utf-8')).hexdigest() == stored]
    if len(matched) != 1:
        raise EhiLabError('LOCK_HASH_CONTEXT_UNVERIFIED_OR_AMBIGUOUS')
    return matched[0]


def observed_open_access_edits(document):
    """Recompute a source-verified outer hash; importer acceptance is pending."""
    lock_hash_rule(document)
    if (document.inner.get('lockModes') != '["none"]' or
            type(document.inner.get('isConfigLock')) is not bool):
        raise EhiLabError('OBSERVED_INNER_ACCESS_LAYOUT_REQUIRED')
    modes = '["none"]'
    identifier = document.outer.get('configIdentifier')
    if type(identifier) is not str or not identifier:
        raise EhiLabError('OBSERVED_OPEN_IDENTIFIER_REQUIRED')
    # The recovered exporter uses identifier || modes when isConfigLock is
    # false. Preserve an explicit source salt for its existing connection
    # tokens, but do not use the locked-export hash rule for the open target.
    text = identifier + modes
    outer_edits = {'lockModes': modes,
                   'lockModesHash': hashlib.sha256(text.encode('utf-8')).hexdigest()}
    # The timestamp participates in the Argon2 master-key transcript. Reset
    # to the observed no-expiry integer and authenticate both carrier layers.
    if 'configExpiryTimestamp' in document.outer:
        expiry = document.outer['configExpiryTimestamp']
        if type(expiry) is not int or expiry < 0:
            raise EhiLabError('UNSUPPORTED_EXPIRY_METADATA')
        if expiry != 0:
            outer_edits['configExpiryTimestamp'] = 0
    return (outer_edits, {'isConfigLock': False})


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
            'field_salt_mode': 'explicit' if 'configSalt' in document.outer else 'observed_default_absent',
            'aead_version': document.aead[0], 'authenticated': True,
            'authentication_scope': 'inner_aead_and_outer_hmac' if document.carrier_mac_key is not None else 'inner_aead_only',
            'carrier_integrity_verified': document.carrier_mac_key is not None,
            'modified_export_status': 'local_verified_android_pending' if document.carrier_mac_key is not None else 'blocked_pending_carrier_integrity',
            'frame_checksum': 'adler32_verified',
            'original_app_import': 'pending'}
