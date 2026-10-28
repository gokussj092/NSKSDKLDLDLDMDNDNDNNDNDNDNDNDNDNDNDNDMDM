#!/usr/bin/env python3
"""Experimental NPVO1 and NPVS v5 app-key export; never a production router."""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import sys

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from decoders.Python import npvs as D
from lossless_json import parse, equal, _value_spans

MAX_BYTES = 4 * 1024 * 1024
OPEN_MAGIC = b'NPVO1\n'


class NpvLabError(ValueError):
    pass


def validate_document(value):
    if (type(value) is not dict or type(value.get('configs')) is not list or
            not value['configs'] or any(type(x) is not dict for x in value['configs'])):
        raise NpvLabError('CONFIGS_DOCUMENT_REQUIRED')
    # A bound also protects the token-preserving traversal below.
    def visit(node, depth=0):
        if depth > 64:
            raise NpvLabError('JSON_DEPTH_LIMIT')
        if isinstance(node, dict):
            for child in node.values():
                visit(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                visit(child, depth + 1)
    visit(value)


def leaves(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, path + (index,))
    else:
        yield path, value


def raw_replace(raw, edits):
    """Replace leaf tokens with validated raw JSON, preserving other bytes."""
    text, spans = _value_spans(raw)
    changes = []
    for path, token in edits.items():
        parse(token)
        start, end = spans[path]
        changes.append((start, end, token.decode('utf-8')))
    ordered = sorted(changes)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise NpvLabError('OVERLAPPING_RECORD_LAYOUT')
    for start, end, token in reversed(ordered):
        text = text[:start] + token + text[end:]
    result = text.encode('utf-8')
    parse(result)
    return result


@dataclass(repr=False)
class NpvDocument:
    source: bytes
    kind: str
    document: dict
    raw_document: bytes
    metadata: dict | None = None
    raw_metadata: bytes | None = None
    records: dict[int, bytes] = field(default_factory=dict)
    envelope: dict | None = None


def read_profile(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise NpvLabError('INPUT_SIZE_LIMIT')
    if raw.startswith(OPEN_MAGIC):
        plain = raw[len(OPEN_MAGIC):]
        value = parse(plain)
        validate_document(value)
        return NpvDocument(raw, 'NPVO1', value, plain)
    if not raw.startswith(b'NPVS'):
        raise NpvLabError('UNSUPPORTED_NPV_FORMAT')
    env = D.inspect_npvs(raw)  # Verify framing and signature before using keys.
    if env['version'] != 5 or env['mode'] != 2 or env['recipients']:
        raise NpvLabError('ONLY_V5_APPKEY_WITHOUT_RECIPIENTS')
    result = D.decode_npvs(raw)
    validate_document(result['document'])
    desc, header, nonce = env['descriptor'], env['header'], env['nonce']
    salt, wrapped = desc[2:18], desc[18:78]
    kdk = hashlib.sha256(b'npvtunnel/appkey/v2 ' + D._whitebox_block(salt) + header[1:17]).digest()
    dek = D._open(kdk, wrapped[:12], wrapped[12:], salt, 'document key')
    mkey = HKDF(dek, 32, nonce, SHA256, context=b'NPVS-v5/metadata')
    metadata_raw = D._open(mkey, nonce, header[env['prefixEnd'] + 4:],
                           header[:env['prefixEnd']], 'metadata')
    body, records, pos = env['body'], {}, 38
    for _ in range(int.from_bytes(body[36:38], 'big')):
        identifier, length = struct.unpack_from('>HI', body, pos)
        pos += 6
        aad = b'NPV-fields-v1/record/' + body[4:36] + struct.pack('>HI', identifier, length - 16)
        records[identifier] = D._open(D._field_key(dek, body[4:36], b'field', identifier),
                                     bytes(12), body[pos:pos + length], aad, 'field')
        pos += length
    layout = parse(records[65535])
    edits = {path: records[identifier] for path, identifier in leaves(layout)}
    plain = raw_replace(records[65535], edits)
    if not equal(parse(plain), result['document']) or not equal(parse(metadata_raw), result['metadata']):
        raise NpvLabError('RAW_RECONSTRUCTION_MISMATCH')
    return NpvDocument(raw, 'NPVS_V5_APPKEY', result['document'], plain,
                       result['metadata'], metadata_raw, records, env)


def open_policy_supported(profile):
    """NPVO1 has no outer policy: only the observed empty policy is converted."""
    if profile.kind == 'NPVO1':
        return
    policy = profile.metadata['policy']
    allowed = {'configVersion', 'onlyMobileNetwork', 'attestationLevel', 'expiresAt',
               'displayMessage', 'customServerMessage'}
    if (set(policy) - allowed or type(policy.get('configVersion', 2)) is not int or
            policy.get('configVersion', 2) not in (1, 2) or
            not equal(policy.get('onlyMobileNetwork', False), False) or
            policy.get('attestationLevel', '') not in ('', 'NONE') or
            policy.get('expiresAt') is not None or
            policy.get('displayMessage', '') != '' or policy.get('customServerMessage', '') != ''):
        raise NpvLabError('OPEN_POLICY_NOT_REPRESENTABLE_IN_OBSERVED_FORMAT')


def export_open(profile):
    open_policy_supported(profile)
    # SecretString's npvs1: tokens belong in this JSON, as in the owner's file.
    raw = OPEN_MAGIC + profile.raw_document
    if len(raw) > MAX_BYTES or not equal(read_profile(raw).document, profile.document):
        raise NpvLabError('OPEN_EXPORT_MISMATCH')
    return raw


def split_records(raw_document):
    value = parse(raw_document)
    validate_document(value)
    text, spans = _value_spans(raw_document)
    records, replacements = {}, {}
    for identifier, (path, _) in enumerate(leaves(value), 1):
        if identifier >= 65535:
            raise NpvLabError('TOO_MANY_FIELDS')
        start, end = spans[path]
        records[identifier] = text[start:end].encode('utf-8')
        replacements[path] = str(identifier).encode('ascii')
    records[65535] = raw_replace(raw_document, replacements)
    return records


def source_context(metadata, config_id, public_key, nonce):
    policy = metadata['policy']
    projected = {k: policy.get(k, default) for k, default in (
        ('onlyMobileNetwork', False), ('attestationLevel', ''), ('expiresAt', None),
        ('displayMessage', ''), ('customServerMessage', ''))}
    if policy.get('configVersion', 0):
        projected['configVersion'] = policy['configVersion']
    url = lambda b: base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')
    source = {'v': 5, 'configId': url(config_id), 'issuedAt': metadata.get('issuedAt', ''),
              'creator': {'fp': url(hashlib.sha256(public_key).digest()), 'pk': url(public_key)},
              'policy': projected, 'recipients': None}
    return hashlib.sha256(b'NPVS-v5/source-fields-v1/' + D._canonical(source) + nonce).digest()


def seal(key, nonce, clear, aad):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(clear)
    return ciphertext + tag


def export_sealed(profile, *, metadata_template=None):
    """Fresh export identity and crypto; never pretend to sign as the author."""
    template = profile if profile.raw_metadata is not None else metadata_template
    if template is None or template.kind != 'NPVS_V5_APPKEY':
        raise NpvLabError('AUTHENTICATED_METADATA_TEMPLATE_REQUIRED')
    if profile.kind == 'NPVO1':
        open_policy_supported(template)
    records = profile.records or split_records(profile.raw_document)
    creator = ECC.generate(curve='P-256')
    public = creator.public_key().export_key(format='SEC1', compress=True)
    config_id, salt, nonce = os.urandom(16), os.urandom(16), os.urandom(12)
    dek, wrap_nonce = os.urandom(32), os.urandom(12)
    kdk = hashlib.sha256(b'npvtunnel/appkey/v2 ' + D._whitebox_block(salt) + config_id).digest()
    descriptor = b'\x00\x02' + salt + wrap_nonce + seal(kdk, wrap_nonce, dek, salt)
    prefix = b'\x01' + config_id + public + b'\x02\x00\x00' + descriptor
    mkey = HKDF(dek, 32, nonce, SHA256, context=b'NPVS-v5/metadata')
    encrypted_metadata = seal(mkey, nonce, template.raw_metadata, prefix)
    header = prefix + struct.pack('>I', len(encrypted_metadata)) + encrypted_metadata
    context = source_context(template.metadata, config_id, public, nonce)
    body = b'NPF\x01' + context + struct.pack('>H', len(records))
    for identifier, plain in sorted(records.items()):
        aad = b'NPV-fields-v1/record/' + context + struct.pack('>HI', identifier, len(plain))
        encrypted = seal(D._field_key(dek, context, b'field', identifier), bytes(12), plain, aad)
        body += struct.pack('>HI', identifier, len(encrypted)) + encrypted
    body += hmac.digest(D._field_key(dek, context, b'inventory', 0), body, 'sha256')
    unsigned = b'NPVS\x05' + struct.pack('>I', len(header)) + header + nonce + struct.pack('>I', len(body)) + body
    if len(unsigned) + 64 > MAX_BYTES:
        raise NpvLabError('EXPORT_SIZE_LIMIT')
    raw = unsigned + DSS.new(creator, 'deterministic-rfc6979', encoding='binary').sign(SHA256.new(unsigned))
    after = read_profile(raw)
    if (not equal(after.document, profile.document) or after.raw_metadata != template.raw_metadata or
            after.records != records or after.raw_document != profile.raw_document):
        raise NpvLabError('RESEALED_CONTENT_MISMATCH')
    return raw


def summary(profile):
    return {'kind': profile.kind, 'bytes': len(profile.source),
            'sha256': hashlib.sha256(profile.source).hexdigest(),
            'configs': len(profile.document['configs']), 'records': len(profile.records),
            'signature_and_aead': 'verified' if profile.envelope else 'not_present_in_NPVO1',
            'banner_added': False, 'android_import': 'pending', 'editor_access': 'pending'}


def private_write(path, data):
    path = Path(path)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--mode', required=True, choices=('rewrap', 'open', 'sealed'))
    parser.add_argument('--metadata-template', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise NpvLabError('NEW_OUTPUT_FILE_REQUIRED')
        profile = read_profile(args.source.read_bytes())
        template = read_profile(args.metadata_template.read_bytes()) if args.metadata_template else None
        raw = (profile.source if args.mode == 'rewrap' else export_open(profile) if args.mode == 'open'
               else export_sealed(profile, metadata_template=template))
        private_write(args.output, raw)
        print(json.dumps(summary(read_profile(raw))))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({'error': 'NPV_LAB_EXPORT_FAILED'}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
