"""Authenticated NPVS -> observed NPVO1, with user-supplied credentials only."""
import base64
import hashlib
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from decoders.Python import npvs as D
from .lossless import parse, equal, _value_spans

MAGIC = b'NPVO1\n'


def reconstruct(records):
    layout = parse(records[65535])
    text, spans = _value_spans(records[65535])
    edits = []
    def walk(node, path=()):
        if isinstance(node, dict):
            for k, v in node.items(): walk(v, path+(k,))
        elif isinstance(node, list):
            for i, v in enumerate(node): walk(v, path+(i,))
        else:
            a, b = spans[path]
            edits.append((a, b, records[node].decode('utf-8')))
    walk(layout)
    for a, b, token in sorted(edits, reverse=True): text = text[:a]+token+text[b:]
    return text.encode('utf-8')


def export(raw, credentials, language='es'):
    if raw.startswith(MAGIC):
        if credentials: raise ValueError('CREDENTIALS_NOT_ALLOWED')
        doc = parse(raw[len(MAGIC):])
        if not isinstance(doc, dict) or not isinstance(doc.get('configs'), list) or not doc['configs']:
            raise ValueError('CONFIGS_REQUIRED')
        return raw
    result = D.decode_npvs(raw, password=credentials.get('password'),
        public_key=credentials.get('publicKey'), recipient_key=credentials.get('recipientKey'))
    env = D.inspect_npvs(raw)
    header, nonce = env['header'], env['nonce']
    cid, descriptor = header[1:17], env['descriptor']
    if env['mode'] == 0:
        from decoders.Python.npvs_identity import agreement
        record, shared = agreement(credentials['recipientKey'], raw, env['recipients'])
        key = HKDF(shared, 32, record[:32], SHA256, context=b'NPVS-v1-wrap'+cid)
        c = AES.new(key, AES.MODE_GCM, nonce=record[65:77]); c.update(record[:32])
        dek = c.decrypt_and_verify(record[77:109], record[109:125])
        if env['version'] == 6:
            p = 53+125*len(env['recipients']); salt = header[p:p+16]
            kdk = hashlib.sha256(b'npvtunnel/appkey/v2 '+D._whitebox_block(salt)+cid).digest()
            mask = HKDF(kdk, 32, salt, SHA256, context=b'NPVS-v6/recipient-binding'+cid)
            dek = bytes(a ^ b for a, b in zip(dek, mask))
    elif env['version'] == 5 and env['mode'] in (1, 2):
        if env['mode'] == 1:
            iterations = int.from_bytes(descriptor[:4], 'big')
            salt, wrapped = descriptor[4:20], descriptor[20:80]
            kdk = hashlib.pbkdf2_hmac('sha256', credentials['password'].encode('utf-8'), salt, iterations, 32)
        else:
            salt, wrapped = descriptor[2:18], descriptor[18:78]
            kdk = hashlib.sha256(b'npvtunnel/appkey/v2 '+D._whitebox_block(salt)+cid).digest()
        dek = D._open(kdk, wrapped[:12], wrapped[12:], salt, 'document key')
    else: raise ValueError('UNSUPPORTED_NPVS_VARIANT')
    body, records, pos = env['body'], {}, 38
    for _ in range(int.from_bytes(body[36:38], 'big')):
        i, length = struct.unpack_from('>HI', body, pos); pos += 6
        aad = b'NPV-fields-v1/record/'+body[4:36]+struct.pack('>HI', i, length-16)
        records[i] = D._open(D._field_key(dek, body[4:36], b'field', i), bytes(12), body[pos:pos+length], aad, 'field')
        pos += length
    document = reconstruct(records)
    if not equal(parse(document), result['document']): raise ValueError('RAW_DOCUMENT_MISMATCH')
    policy = result['metadata']['policy']
    allowed = {'configVersion','onlyMobileNetwork','attestationLevel','expiresAt','displayMessage','customServerMessage'}
    # No expiry/mobile/attestation restriction is silently lost by opening it.
    if (set(policy)-allowed or not equal(policy.get('onlyMobileNetwork', False), False) or
            policy.get('attestationLevel', '') not in ('', 'NONE') or policy.get('expiresAt') is not None or
            type(policy.get('configVersion', 2)) is not int or policy.get('configVersion', 2) not in (1, 2) or
            policy.get('displayMessage', '') != '' or policy.get('customServerMessage', '') != ''):
        raise ValueError('NPVS_POLICY_NOT_REPRESENTABLE')
    out = MAGIC+document
    # Output contains only the authenticated document, no key or recipients.
    if not equal(parse(out[len(MAGIC):]), result['document']): raise ValueError('OUTPUT_MISMATCH')
    return out
