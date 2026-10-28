#!/usr/bin/env python3
"""Audited, lossless Dark Tunnel export adapter. Never formats a production decode.

Only the observed modern two-layer container is decrypted. Unknown MessagePack
values stay in their original bytes. Unlock is limited to the audited SSH map
and exact generated VLESS/Xray template; other layouts fail explicitly.
The open JSON format works for every type without rewriting its contents.
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
import sys

import msgpack
from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from decoders.Python.DARKTUNNEL import DTConstants
from .lossless import parse, put_member, replace_values, equal
from .dark_vless import recover as recover_vless

MAX_BYTES = 16 * 1024 * 1024
SCHEME = 'darktunnel://'
TUNNEL_TYPES = frozenset(('UNSUPPORTED', 'SSH', 'SSH_DNSTT', 'OPENVPN', 'VMESS',
                          'VLESS', 'TROJAN', 'SHADOWSOCKS', 'V2RAY_CUSTOM_CONFIG'))
INJECT_NAMES = {
    'Mode': 'mode', 'ProxyHost': 'proxyHost', 'ProxyPort': 'proxyPort',
    'ServerNameIndication': 'serverNameIndication', 'Payload': 'payload',
    'DnsttDnsHost': 'dnsttUdpDnsHost', 'DnsttDnsPort': 'dnsttUdpDnsPort',
    'DnsttServerName': 'dnsttServerName', 'DnsttPubkey': 'dnsttPublicKey',
}
SSH_NAMES = {'Host': 'host', 'Port': 'port', 'Username': 'username', 'Password': 'password'}
GROUP_FIELDS = {
    'SshConfig': tuple(SSH_NAMES), 'InjectConfig': tuple(INJECT_NAMES),
    'V2RayConfig': ('Config',),
}
APP_FIELDS = frozenset(('VersionCode', 'VersionName', 'Message', 'ConnectedMessage',
                        'Password', 'ExpiredAtTimestamp', 'HardwareIdList', 'TunnelType',
                        'IsSshLocked'))


class LabError(ValueError):
    """A fixed public error code, never an exception containing private data."""


def bounded(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise LabError('INVALID_SIZE')
    return raw


def b64decode(text):
    if not isinstance(text, str) or not re.fullmatch(r'[A-Za-z0-9_+/\-]*={0,2}', text):
        raise LabError('INVALID_BASE64')
    if len(text) > MAX_BYTES * 2 or len(text.rstrip('=')) % 4 == 1:
        raise LabError('INVALID_BASE64')
    try:
        return base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)
    except (ValueError, TypeError):
        raise LabError('INVALID_BASE64') from None


def encode_json(raw):
    bounded(raw)
    if not isinstance(parse(raw), dict):
        raise LabError('JSON_OBJECT_REQUIRED')
    # Android Base64 flags 10 = URL_SAFE | NO_WRAP, padding retained.
    return (SCHEME + base64.urlsafe_b64encode(raw).decode('ascii')).encode('ascii')


def crypt(raw, key, *, decrypt=False):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise LabError('INVALID_CIPHER_INPUT')
    cipher = AES.new(key, AES.MODE_CFB, iv=DTConstants.IV, segment_size=128)
    return cipher.decrypt(raw) if decrypt else cipher.encrypt(raw)


def _unique(pairs):
    result = {}
    for k, v in pairs:
        if not isinstance(k, (str, bytes, int)) or k in result:
            raise LabError('DUPLICATE_OR_UNSUPPORTED_MSGPACK_KEY')
        result[k] = v
    return result


def unpack(raw):
    bounded(raw)
    try:
        value = msgpack.unpackb(raw, raw=False, strict_map_key=False, object_pairs_hook=_unique,
                                max_str_len=MAX_BYTES, max_bin_len=MAX_BYTES,
                                max_array_len=100000, max_map_len=100000, max_ext_len=MAX_BYTES)
    except LabError:
        raise
    except Exception:
        raise LabError('INVALID_MSGPACK') from None
    if not isinstance(value, dict):
        raise LabError('MSGPACK_MAP_REQUIRED')
    return value


def replace_packed(raw, path, value):
    """Replace one map value; unknown raw encodings and sibling bytes survive."""
    unpack(raw)
    reader = msgpack.Unpacker(raw=False, strict_map_key=False, max_buffer_size=MAX_BYTES)
    reader.feed(raw)
    try:
        count = reader.read_map_header()
        for _ in range(count):
            key = reader.unpack()
            start = reader.tell()
            reader.unpack()
            end = reader.tell()
            if key == path[0]:
                new = (replace_packed(raw[start:end], path[1:], value) if len(path) > 1
                       else msgpack.packb(value, use_bin_type=True))
                output = raw[:start] + new + raw[end:]
                unpack(output)
                return output
    except LabError:
        raise
    except Exception:
        raise LabError('INVALID_MSGPACK_EDIT') from None
    raise LabError('MSGPACK_FIELD_MISSING')


@dataclass
class Document:
    source: bytes
    raw_json: bytes
    outer: dict
    raw_export: bytes | None = None
    export: dict | None = None
    raw_locked: bytes | None = None
    locked: dict | None = None

    @property
    def protected(self):
        return self.raw_export is not None


def decode(source):
    bounded(source)
    try:
        token = source.decode('utf-8').strip()
    except UnicodeError:
        raise LabError('INVALID_UTF8') from None
    if token.startswith(SCHEME):
        token = token[len(SCHEME):]
    elif '://' in token:
        raise LabError('UNSUPPORTED_SCHEME')
    raw = b64decode(token)
    try:
        outer = parse(raw)
    except (ValueError, UnicodeError):
        raise LabError('INVALID_JSON') from None
    if (not isinstance(outer, dict) or type(outer.get('type')) is not str or
            outer['type'] not in TUNNEL_TYPES or type(outer.get('name')) is not str):
        raise LabError('INVALID_TUNNEL_SCHEMA')
    enc = outer.get('encryptedLockedConfig', '')
    if type(enc) is not str:
        raise LabError('INVALID_LOCKED_FIELD_TYPE')
    document = Document(source, raw, outer)
    if enc:
        document.raw_export = crypt(b64decode(enc), DTConstants.KEY_256, decrypt=True)
        document.export = unpack(document.raw_export)
        inner = document.export.get('EncryptedLockedConfig')
        if not isinstance(document.export.get('LockedAppConfig'), dict) or type(inner) is not bytes:
            raise LabError('UNSUPPORTED_LOCKED_LAYOUT')
        document.raw_locked = crypt(inner, DTConstants.KEY_192, decrypt=True)
        document.locked = unpack(document.raw_locked)
    return document


def rewrap(document, *, note=None):
    """Reseal exact raw layers. AES-CFB is deterministic and has no auth tag."""
    raw = document.raw_json
    if document.protected:
        packed = document.raw_export
        # Decrypt and encrypt the inner container without serializing its map.
        inner = crypt(document.raw_locked, DTConstants.KEY_192)
        if inner != document.export['EncryptedLockedConfig']:
            packed = replace_packed(packed, ('EncryptedLockedConfig',), inner)
        if note is not None:
            if not isinstance(note, bytes) or len(note) > 256000:
                raise LabError('INVALID_NOTE')
            try:
                note.decode('utf-8')
            except UnicodeError:
                raise LabError('INVALID_NOTE_UTF8') from None
            packed = replace_packed(packed, ('LockedAppConfig', 'Message'), note)
        ciphertext = crypt(packed, DTConstants.KEY_256)
        if ciphertext != b64decode(document.outer['encryptedLockedConfig']):
            encoded = base64.b64encode(ciphertext).decode('ascii')
            raw = replace_values(raw, {('encryptedLockedConfig',): encoded})
    elif note is not None:
        # The open Kotlin model has no note property. Do not invent one.
        raise LabError('OPEN_FORMAT_HAS_NO_NOTE_FIELD')
    result = encode_json(raw)
    check = decode(result)
    if document.protected and check.raw_locked != document.raw_locked:
        raise LabError('LOCKED_PLAINTEXT_CHANGED')
    if not document.protected and check.raw_json != raw:
        raise LabError('JSON_BYTES_CHANGED')
    return result


def decrypted_group(group, fields, extra):
    if not isinstance(group, dict) or set(group) != {'IsEncrypted', *extra, *('Encrypted' + k for k in fields)}:
        raise LabError('UNSUPPORTED_GROUP_SCHEMA')
    if group['IsEncrypted'] is not True or any(type(group[k]) is not bool for k in extra):
        raise LabError('UNSUPPORTED_GROUP_FLAGS')
    result = {}
    for name in fields:
        encrypted = group['Encrypted' + name]
        if type(encrypted) is not bytes:
            raise LabError('INVALID_ENCRYPTED_VALUE_TYPE')
        try:
            value = crypt(encrypted, DTConstants.KEY_192, decrypt=True).decode('utf-8')
        except UnicodeError:
            raise LabError('INVALID_FIELD_UTF8') from None
        if name.endswith('Port'):
            if not re.fullmatch(r'[0-9]{1,5}', value) or not 1 <= int(value) <= 65535:
                raise LabError('INVALID_PORT')
            value = int(value)
        result[name] = value
    return result


def _put_fields(raw, parent, values):
    obj = parse(raw)
    for index, key in enumerate(parent):
        if key not in obj:
            raw = put_member(raw, parent[:index], key, {})
            obj = {}
        else:
            obj = obj[key]
        if not isinstance(obj, dict):
            raise LabError('INVALID_TARGET_OBJECT')
    for name, value in values.items():
        raw = put_member(raw, parent, name, value)
    return raw


def unlock_configuration(document):
    """Materialize observed connection fields, then clear the native Ca wrapper.

    Arbitrary/legacy/Xray locked configurations are not silently converted.
    Restrictions are removed only along with an entirely recognized wrapper.
    The caller must retain the private original for all source metadata.
    """
    if not document.protected:
        return encode_json(document.raw_json)
    app = document.export['LockedAppConfig']
    if (set(document.export) != {'LockedAppConfig', 'EncryptedLockedConfig'} or
            set(app) != APP_FIELDS or app['VersionCode'] != 32 or
            type(app['VersionCode']) is not int or app['VersionName'] != b'1.0.26'):
        raise LabError('UNSUPPORTED_APP_SCHEMA')
    if (any(type(app[k]) is not bytes for k in ('VersionName', 'Message', 'ConnectedMessage', 'Password'))
            or type(app['ExpiredAtTimestamp']) is not int or type(app['HardwareIdList']) is not list
            or any(type(v) is not str for v in app['HardwareIdList'])
            or type(app['TunnelType']) is not str or type(app['IsSshLocked']) is not bool):
        raise LabError('UNSUPPORTED_APP_FIELD_TYPES')
    tunnel_type = document.outer['type']
    if tunnel_type not in ('SSH', 'VLESS') or app['TunnelType'] != tunnel_type:
        raise LabError('LOCKED_TUNNEL_TYPE_NOT_YET_AUDITED')
    if set(document.locked) != {'SshConfig', 'InjectConfig', 'V2RayConfig'}:
        raise LabError('UNSUPPORTED_CONNECTION_SECTIONS')
    ssh = decrypted_group(document.locked['SshConfig'], GROUP_FIELDS['SshConfig'], ('IsLocked',))
    inject = decrypted_group(document.locked['InjectConfig'], GROUP_FIELDS['InjectConfig'], ())
    if inject['Mode'] not in ('DIRECT', 'DIRECT_SNI', 'PROXY', 'PROXY_SNI', 'DNSTT'):
        raise LabError('UNSUPPORTED_INJECT_MODE')
    if type(app['IsSshLocked']) is not bool or app['IsSshLocked'] != document.locked['SshConfig']['IsLocked']:
        raise LabError('CONFLICTING_LOCK_FLAGS')
    v2ray = document.locked['V2RayConfig']
    clear_v2ray = (decrypted_group(v2ray, GROUP_FIELDS['V2RayConfig'], ('IsInjectModeEnabled',))
                   if v2ray is not None else None)
    raw = document.raw_json
    if tunnel_type == 'SSH':
        if clear_v2ray is not None and (clear_v2ray['Config'] or v2ray['IsInjectModeEnabled']):
            raise LabError('UNUSED_V2RAY_SECTION_HAS_DATA')
        # This is the flag emitted by C4967.m11201 for SSH.
        source_branch = document.outer.get('sshTunnelConfig')
        if (not isinstance(source_branch, dict) or
                not isinstance(source_branch.get('injectConfig'), dict) or
                source_branch['injectConfig'].get('enabled') is not True):
            raise LabError('UNSUPPORTED_SSH_INJECT_FLAGS')
        branch = 'sshTunnelConfig'
        raw = _put_fields(raw, (branch, 'sshConfig'), {SSH_NAMES[k]: v for k, v in ssh.items()})
    else:
        if ssh != {'Host': '', 'Port': 80, 'Username': '', 'Password': ''} or clear_v2ray is None:
            raise LabError('UNUSED_SSH_SECTION_HAS_DATA')
        try:
            vless = recover_vless(clear_v2ray['Config'])
        except (ValueError, TypeError, RecursionError):
            raise LabError('VLESS_TEMPLATE_NOT_REPRESENTABLE') from None
        branch = 'vlessTunnelConfig'
        raw = _put_fields(raw, (branch, 'v2rayConfig'), vless)
        raw = _put_fields(raw, (branch, 'injectConfig'), {'enabled': v2ray['IsInjectModeEnabled']})
    raw = _put_fields(raw, (branch, 'injectConfig'),
                      {INJECT_NAMES[k]: v for k, v in inject.items()})
    raw = put_member(raw, (), 'encryptedLockedConfig', '')
    result = encode_json(raw)
    check = decode(result)
    if check.protected:
        raise LabError('LOCK_WRAPPER_REMAINS')
    comparisons = [('injectConfig', {INJECT_NAMES[k]: v for k, v in inject.items()})]
    comparisons.append(('sshConfig', {SSH_NAMES[k]: v for k, v in ssh.items()}) if tunnel_type == 'SSH'
                       else ('v2rayConfig', vless))
    for section, expected in comparisons:
        actual = check.outer[branch][section]
        if not all(equal(actual[k], v) for k, v in expected.items()):
            raise LabError('CONNECTION_MISMATCH')
    return result


def private_write(path, raw):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)


def summary(document):
    return {'source_sha256': hashlib.sha256(document.source).hexdigest(),
            'source_bytes': len(document.source), 'json_bytes': len(document.raw_json),
            'layout': 'modern_aes_cfb_msgpack' if document.protected else 'open_base64_json',
            'encrypted_layers': 2 if document.protected else 0,
            'authentication_tag': False, 'android_import': 'pending'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='Private .dark file or text-token file')
    parser.add_argument('--mode', choices=('inspect', 'rewrap', 'unlock'), default='inspect')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--note-file', type=Path, help='Replace Message in a protected container only')
    args = parser.parse_args()
    try:
        document = decode(args.source.read_bytes())
        result = summary(document)
        if args.mode != 'inspect':
            if args.output is None:
                raise LabError('OUTPUT_REQUIRED')
            if args.mode == 'unlock' and args.note_file is not None:
                raise LabError('OPEN_FORMAT_HAS_NO_NOTE_FIELD')
            note = args.note_file.read_bytes() if args.note_file is not None else None
            output = rewrap(document, note=note) if args.mode == 'rewrap' else unlock_configuration(document)
            # A text export and a .dark export contain the same native token.
            private_write(args.output, output + b'\n')
            result.update(output_sha256=hashlib.sha256(output + b'\n').hexdigest(),
                          output_bytes=len(output) + 1, mode=args.mode)
        print(json.dumps(result, indent=2))
        return 0
    except (LabError, OSError, ValueError, TypeError, KeyError, RecursionError):
        # Native/library exceptions can embed plaintext. Print only our fixed codes.
        error = sys.exc_info()[1]
        code = str(error) if isinstance(error, LabError) else 'INPUT_OR_OUTPUT_ERROR'
        print(json.dumps({'error': code}), file=sys.stderr)
        return 1
