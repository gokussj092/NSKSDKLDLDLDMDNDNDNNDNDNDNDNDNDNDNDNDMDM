#!/usr/bin/env python3
"""Independent OpenSSL/cryptography checks for the limited NPVS v5 writer."""
import base64
import hashlib
import hmac
import json
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from npvs_export_experiment import D, MAX_BYTES, NpvLabError
from lossless_json import equal


def hkdf(key, salt, label):
    # SHA-256 HKDF with exactly one output block, independently of Crypto.HKDF.
    prk = hmac.digest(salt, key, 'sha256')
    return hmac.digest(prk, label + b'\x01', 'sha256')


def audit(raw, expected):
    if not 89 <= len(raw) <= MAX_BYTES or raw[:5] != b'NPVS\x05':
        raise NpvLabError('AUDIT_UNSUPPORTED_FRAME')
    hlen = struct.unpack_from('>I', raw, 5)[0]
    header = raw[9:9 + hlen]
    if len(header) != hlen or header[:1] != b'\x01' or header[50:55] != b'\x02\x00\x00\x00\x02':
        raise NpvLabError('AUDIT_UNSUPPORTED_DESCRIPTOR')
    end = 9 + hlen
    nonce = raw[end:end + 12]
    blen = struct.unpack_from('>I', raw, end + 12)[0]
    if end + 16 + blen + 64 != len(raw):
        raise NpvLabError('AUDIT_FRAME_BOUNDS')
    pub = header[17:50]
    sig = raw[-64:]
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
    signature = encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big'))
    key.verify(signature, raw[:-64], ec.ECDSA(hashes.SHA256()))
    salt, wrapped = header[55:71], header[71:131]
    kdk = hashlib.sha256(b'npvtunnel/appkey/v2 ' + D._whitebox_block(salt) + header[1:17]).digest()
    dek = ChaCha20Poly1305(kdk).decrypt(wrapped[:12], wrapped[12:], salt)
    mlen = struct.unpack_from('>I', header, 131)[0]
    if 135 + mlen != len(header):
        raise NpvLabError('AUDIT_METADATA_BOUNDS')
    plain_metadata = ChaCha20Poly1305(hkdf(dek, nonce, b'NPVS-v5/metadata')).decrypt(
        nonce, header[135:], header[:131])
    metadata = json.loads(plain_metadata)
    pol = metadata['policy']
    policy = {k: pol.get(k, default) for k, default in (
        ('onlyMobileNetwork', False), ('attestationLevel', ''), ('expiresAt', None),
        ('displayMessage', ''), ('customServerMessage', ''))}
    if pol.get('configVersion', 0):
        policy['configVersion'] = pol['configVersion']
    url = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
    source = {'v': 5, 'configId': url(header[1:17]), 'issuedAt': metadata.get('issuedAt', ''),
              'creator': {'pk': url(pub), 'fp': url(hashlib.sha256(pub).digest())},
              'policy': policy, 'recipients': None}
    canonical = json.dumps(source, ensure_ascii=False, sort_keys=True,
                           separators=(',', ':'), allow_nan=False).encode()
    context = hashlib.sha256(b'NPVS-v5/source-fields-v1/' + canonical + nonce).digest()
    body = raw[end + 16:-64]
    if body[:4] != b'NPF\x01' or body[4:36] != context:
        raise NpvLabError('AUDIT_CONTEXT_MISMATCH')
    inv_key = hkdf(dek, context, b'NPV-fields-v1/inventory/\0\0')
    if not hmac.compare_digest(hmac.digest(inv_key, body[:-32], 'sha256'), body[-32:]):
        raise NpvLabError('AUDIT_INVENTORY_MISMATCH')
    count = int.from_bytes(body[36:38], 'big')
    records, pos, previous = {}, 38, 0
    for _ in range(count):
        identifier, length = struct.unpack_from('>HI', body, pos)
        pos += 6
        if not previous < identifier or length < 16 or pos + length > len(body) - 32:
            raise NpvLabError('AUDIT_RECORD_BOUNDS')
        info = b'NPV-fields-v1/field/' + struct.pack('>H', identifier)
        aad = b'NPV-fields-v1/record/' + context + struct.pack('>HI', identifier, length - 16)
        plain = ChaCha20Poly1305(hkdf(dek, context, info)).decrypt(bytes(12), body[pos:pos + length], aad)
        records[identifier] = plain
        pos += length
        previous = identifier
    if pos != len(body) - 32 or 65535 not in records:
        raise NpvLabError('AUDIT_LAYOUT_MISSING')
    used = set()
    def resolve(node):
        if isinstance(node, dict):
            return {k: resolve(v) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        if type(node) is not int or not 0 < node < 65535 or node not in records:
            raise NpvLabError('AUDIT_LAYOUT_REFERENCE')
        used.add(node)
        value = json.loads(records[node])
        if isinstance(value, (dict, list)):
            raise NpvLabError('AUDIT_SCALAR_TYPE')
        return value
    document = resolve(json.loads(records[65535]))
    if (used != set(records) - {65535} or not equal(document, expected.document) or
            records != expected.records or plain_metadata != expected.raw_metadata):
        raise NpvLabError('AUDIT_DOCUMENT_MISMATCH')
    return {'independent_backend': 'cryptography_OpenSSL', 'ecdsa_signatures': 1,
            'chacha20_poly1305_tags': count + 2, 'inventory_hmac': 'verified',
            'source_context': 'verified', 'raw_metadata_and_records': 'identical',
            'whitebox_backend': 'existing_native_verified_table_evaluator_shared',
            'whitebox_independent_for_this_run': False}
