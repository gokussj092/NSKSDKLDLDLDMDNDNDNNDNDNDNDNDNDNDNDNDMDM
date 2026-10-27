"""Synthetic controls only. These are not exports captured from Dark Tunnel.

wrap_open_vless uses the supplied owner's open profile privately, so its output
must never be committed. Its purpose is to test restoration of real values,
not to substitute for a real vendor-generated locked sample.
"""
import base64
import json

import msgpack

from dark_tunnel_experiment import (DTConstants, INJECT_NAMES, GROUP_FIELDS, crypt,
                                    encode_json, decode, LabError)
from dark_vless_reference import render, DEFAULTS
from lossless_json import put_member

INJECT_DEFAULTS = {
    'Mode': 'DIRECT', 'ProxyHost': 'localhost', 'ProxyPort': 8080,
    'ServerNameIndication': '',
    'Payload': '[method] [host_port] [protocol][crlf]Host: [host][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]',
    'DnsttDnsHost': '1.1.1.1', 'DnsttDnsPort': 53,
    'DnsttServerName': '', 'DnsttPubkey': '',
}


def build_wrapper(raw_json, tunnel_type, ssh, inject, xray='', *, ssh_locked=True, inject_enabled=False):
    """Forward recipe inferred from build-32 E and original serializers."""
    groups = {}
    for name, values in [('InjectConfig', inject), ('SshConfig', ssh), ('V2RayConfig', {'Config': xray})]:
        if set(values) != set(GROUP_FIELDS[name]):
            raise LabError('SYNTHETIC_FIELDS_MISMATCH')
        group = {'IsEncrypted': True}
        if name == 'SshConfig':
            group['IsLocked'] = ssh_locked
        if name == 'V2RayConfig':
            group['IsInjectModeEnabled'] = inject_enabled
        group.update({'Encrypted' + k: crypt(str(v).encode('utf-8'), DTConstants.KEY_192)
                      for k, v in values.items()})
        groups[name] = group
    raw_inner = msgpack.packb(groups, use_bin_type=True)
    app = {'VersionCode': 32, 'VersionName': b'1.0.26',
           'Message': b'Synthetic SP-DECODE laboratory control', 'ConnectedMessage': b'',
           'Password': b'', 'ExpiredAtTimestamp': 0, 'HardwareIdList': [],
           'TunnelType': tunnel_type, 'IsSshLocked': ssh_locked}
    exported = {'LockedAppConfig': app, 'EncryptedLockedConfig': crypt(raw_inner, DTConstants.KEY_192)}
    raw_export = msgpack.packb(exported, use_bin_type=True)
    raw_json = put_member(raw_json, (), 'encryptedLockedConfig',
        base64.b64encode(crypt(raw_export, DTConstants.KEY_256)).decode('ascii'))
    return encode_json(raw_json)


def wrap_open_vless(document):
    if document.protected or document.outer['type'] != 'VLESS':
        raise LabError('OPEN_VLESS_REFERENCE_REQUIRED')
    branch = document.outer.get('vlessTunnelConfig', {})
    config = dict(DEFAULTS, **branch.get('v2rayConfig', {}))
    clear_inject = branch.get('injectConfig', {})
    inject = {k: clear_inject.get(v, INJECT_DEFAULTS[k]) for k, v in INJECT_NAMES.items()}
    raw = document.raw_json
    # Same masked properties as C4967.m11201; retain all other source members.
    for k in ('host', 'port', 'uuid', 'serverNameIndication', 'wsPath', 'wsHeaderHost', 'grpcServiceName'):
        raw = put_member(raw, ('vlessTunnelConfig', 'v2rayConfig'), k, DEFAULTS[k])
    raw = put_member(raw, ('vlessTunnelConfig',), 'injectConfig',
                     {'enabled': clear_inject.get('enabled', False), 'mode': inject['Mode']})
    return build_wrapper(raw, 'VLESS', {'Host': '', 'Port': 80, 'Username': '', 'Password': ''},
                         inject, render(config), ssh_locked=False,
                         inject_enabled=clear_inject.get('enabled', False))


def reserved_ssh():
    raw = json.dumps({'type': 'SSH', 'name': 'SP-DECODE synthetic SSH (no live service)',
                      'sshTunnelConfig': {'injectConfig': {'enabled': True, 'mode': 'DIRECT_SNI'}}},
                     separators=(',', ':')).encode('utf-8')
    inject = dict(INJECT_DEFAULTS, Mode='DIRECT_SNI', ServerNameIndication='sni.example.invalid',
                  Payload='GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
    return build_wrapper(raw, 'SSH', {'Host': 'ssh.example.invalid', 'Port': 443,
                                    'Username': 'synthetic-user', 'Password': 'synthetic-password'}, inject)
