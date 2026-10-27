#!/usr/bin/env python3
"""Synthetic regression and independent-backend tests; no customer secrets."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers.modes import CFB
import msgpack

from dark_tunnel_experiment import (DTConstants, LabError, decode, rewrap, unlock_configuration,
    crypt, encode_json, replace_packed, unpack, private_write, GROUP_FIELDS,
    SSH_NAMES, INJECT_NAMES)
from decoders.Python.DARKTUNNEL import DTDecryptor, run as production_run
from lossless_json import parse, equal
from dark_vless_reference import render, recover, parse_template, DEFAULTS

unlock_ssh = unlock_configuration  # Historical test shorthand, no production alias.


def packed(value):
    return msgpack.packb(value, use_bin_type=True)


def sample_values():
    return {
        'SshConfig': {'Host': 'ssh.example.invalid', 'Port': 443,
                      'Username': 'synthetic-user', 'Password': 'SYNTHETIC_SECRET_ñ'},
        'InjectConfig': {'Mode': 'PROXY_SNI', 'ProxyHost': 'proxy.example.invalid',
                         'ProxyPort': 8080, 'ServerNameIndication': 'sni.example.invalid',
                         'Payload': 'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
                         'DnsttDnsHost': 'dns.example.invalid', 'DnsttDnsPort': 53,
                         'DnsttServerName': 'dnstt.example.invalid', 'DnsttPubkey': 'SYNTHETIC_KEY'},
        'V2RayConfig': {'Config': ''},
    }


def protected_fixture(*, values=None, unknown=False):
    """Field names and binary types cross-checked with original Go serializers."""
    values = sample_values() if values is None else values
    inner = {}
    for name, fields in values.items():
        group = {'IsEncrypted': True}
        if name == 'SshConfig':
            group['IsLocked'] = True
        if name == 'V2RayConfig':
            group['IsInjectModeEnabled'] = False
        group.update({'Encrypted' + k: crypt(str(v).encode(), DTConstants.KEY_192)
                      for k, v in fields.items()})
        inner[name] = group
    raw_inner = packed(inner)
    app = {'VersionCode': 32, 'VersionName': b'1.0.26', 'Message': b'old note',
           'ConnectedMessage': b'connected', 'Password': bytes(range(32)),
           'ExpiredAtTimestamp': 4102444800, 'HardwareIdList': ['SYNTHETIC_HWID'],
           'TunnelType': 'SSH', 'IsSshLocked': True}
    export = {'LockedAppConfig': app, 'EncryptedLockedConfig': crypt(raw_inner, DTConstants.KEY_192)}
    if unknown:
        export['unknown'] = msgpack.ExtType(7, b'\x00\xff')
    raw_export = packed(export)
    outer = {'type': 'SSH', 'name': 'Synthetic authorized laboratory',
             'sshTunnelConfig': {'injectConfig': {'enabled': True, 'mode': 'PROXY_SNI',
                                                 'payloadEnhanced': True, 'unknown': [False, 0]}},
             'encryptedLockedConfig': base64.b64encode(crypt(raw_export, DTConstants.KEY_256)).decode()}
    raw_json = json.dumps(outer, ensure_ascii=True, indent=2).replace('/', '\\/').encode()
    return encode_json(raw_json)


class DarkExportTests(unittest.TestCase):
    def test_open_file_and_text_keep_exact_json_and_secrets(self):
        raw = b' {"type":"VLESS", "name":"Synthetic", "Password":"synthetic", "u":"https:\\/\\/example.invalid", "n":1e+03, "vlessTunnelConfig":{"v2rayConfig":{"uuid":"synthetic"}}} '
        d = decode(encode_json(raw) + b'\n')
        self.assertFalse(d.protected)
        self.assertEqual(decode(rewrap(d)).raw_json, raw)
        self.assertEqual(unlock_ssh(d), rewrap(d))

    def test_all_raw_crypto_layers_and_noncanonical_msgpack_survive(self):
        d = decode(protected_fixture(unknown=True))
        # A valid but non-minimal encoding of an unknown extension must survive.
        raw = d.raw_export.replace(b'\xd5\x07\x00\xff', b'\xc7\x02\x07\x00\xff')
        d.raw_export = raw
        from lossless_json import put_member
        d.raw_json = put_member(d.raw_json, (), 'encryptedLockedConfig',
            base64.b64encode(crypt(raw, DTConstants.KEY_256)).decode())
        d.outer = parse(d.raw_json)
        after = decode(rewrap(d))
        self.assertEqual(after.raw_json, d.raw_json)
        self.assertEqual(after.raw_export, raw)
        self.assertEqual(after.raw_locked, d.raw_locked)
        self.assertEqual(after.export['LockedAppConfig']['Password'], bytes(range(32)))

    def test_replace_msgpack_retains_sibling_bytes(self):
        raw = b'\x82\xa1a\xcc\x01\xa1b\xc6\x00\x00\x00\x01x'
        out = replace_packed(raw, ('a',), 2)
        self.assertEqual(out, b'\x82\xa1a\x02\xa1b\xc6\x00\x00\x00\x01x')

    def test_note_replaces_only_app_message_and_keeps_connection(self):
        d = decode(protected_fixture(unknown=True))
        a = decode(rewrap(d, note=b'NEW SP-DECODE NOTE'))
        self.assertEqual(a.raw_locked, d.raw_locked)
        expected = deepcopy(d.export)
        expected['LockedAppConfig']['Message'] = b'NEW SP-DECODE NOTE'
        self.assertEqual(a.export, expected)

    def test_note_missing_or_empty_does_not_invent_open_note_property(self):
        for note in (b'', b'<b>SP-DECODE</b>'):
            d = decode(encode_json(b'{"type":"VLESS","name":"Synthetic"}'))
            with self.assertRaisesRegex(LabError, 'OPEN_FORMAT_HAS_NO_NOTE_FIELD'):
                rewrap(d, note=note)

    def test_ssh_materialization_preserves_every_decrypted_value(self):
        d = decode(protected_fixture())
        a = decode(unlock_ssh(d))
        self.assertFalse(a.protected)
        for group, mapping in [('SshConfig', SSH_NAMES), ('InjectConfig', INJECT_NAMES)]:
            dest = 'sshConfig' if group == 'SshConfig' else 'injectConfig'
            for k, v in sample_values()[group].items():
                actual = a.outer['sshTunnelConfig'][dest][mapping[k]]
                self.assertTrue(equal(actual, v))
        self.assertEqual(a.outer['sshTunnelConfig']['injectConfig']['unknown'], [False, 0])
        self.assertTrue(a.outer['sshTunnelConfig']['injectConfig']['payloadEnhanced'])
        self.assertEqual(a.outer['name'], d.outer['name'])

    def test_unknown_wrapper_requires_preservation_instead_of_partial_unlock(self):
        with self.assertRaisesRegex(LabError, 'UNSUPPORTED_APP_SCHEMA'):
            unlock_ssh(decode(protected_fixture(unknown=True)))

    def test_locked_other_tunnel_types_are_explicitly_pending(self):
        d = decode(protected_fixture())
        d.outer['type'] = 'VMESS'
        with self.assertRaisesRegex(LabError, 'LOCKED_TUNNEL_TYPE_NOT_YET_AUDITED'):
            unlock_ssh(d)

    def test_group_unknowns_binary_strings_and_bad_ports_fail_closed(self):
        from dark_tunnel_experiment import decrypted_group
        d = decode(protected_fixture())
        for name, value in [('extra', 1), ('EncryptedHost', 'wrong type'),
                            ('EncryptedPort', crypt(b'65536', DTConstants.KEY_192)),
                            ('EncryptedPassword', crypt(b'\xff', DTConstants.KEY_192))]:
            g = deepcopy(d.locked['SshConfig']); g[name] = value
            with self.assertRaises(LabError):
                decrypted_group(g, GROUP_FIELDS['SshConfig'], ('IsLocked',))

    def test_no_unaudited_app_build_or_conflicting_flags(self):
        for key, value in [('VersionCode', True), ('VersionCode', 33),
                            ('VersionName', b'1.0.27'), ('IsSshLocked', False)]:
            d = decode(protected_fixture()); d.export['LockedAppConfig'][key] = value
            with self.assertRaises(LabError):
                unlock_ssh(d)

    def test_all_cfb_lengths_and_keys_match_independent_backend(self):
        for key in (DTConstants.KEY_192, DTConstants.KEY_256):
            for n in (0, 1, 15, 16, 17, 31, 32, 257, 4097):
                raw = bytes(i % 256 for i in range(n))
                cipher = Cipher(algorithms.AES(key), CFB(DTConstants.IV)).encryptor()
                reference = cipher.update(raw) + cipher.finalize()
                self.assertEqual(crypt(raw, key), reference)
                self.assertEqual(crypt(reference, key, decrypt=True), raw)

    def test_nist_sp800_38a_cfb128_vector(self):
        from Crypto.Cipher import AES
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv = bytes(range(16))
        plaintext = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        ciphertext = bytes.fromhex('3b3fd92eb72dad20333449f8e83cfb4a')
        self.assertEqual(AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(plaintext), ciphertext)

    def test_vless_exact_template_all_transports_and_tls(self):
        for network in ('Tcp', 'Websocket', 'Grpc'):
            for tls in (False, True):
                config = dict(DEFAULTS, host='vless.example.invalid', port=443, uuid='synthetic-uuid',
                              serverNameIndication='sni.example.invalid', transportNetwork=network,
                              tls=tls, wsPath='/synthetic', wsHeaderHost='ws.example.invalid',
                              grpcServiceName='synthetic-service', mux=True)
                recovered = recover(render(config))
                self.assertTrue(equal(parse_template(render(config)), parse_template(render(recovered))))
                self.assertEqual(recovered['host'], config['host'])

    def test_vless_unknown_xray_behavior_is_not_silently_dropped(self):
        base = render(DEFAULTS)
        for text in (base.replace('"loglevel":"none"', '"loglevel":"debug"'),
                     base.replace('"stats":{}', '"stats":{},"routing":{"domainStrategy":"AsIs"}'),
                     base.replace('$MUX_ENABLED', '$UNOBSERVED'),
                     base.replace('"port":80', '"port":true')):
            with self.assertRaises(ValueError):
                recover(text)

    def test_vless_materialization_and_outer_unknowns(self):
        from lossless_json import put_member
        d = decode(protected_fixture())
        d.outer['type'] = 'VLESS'
        d.export['LockedAppConfig']['TunnelType'] = 'VLESS'
        group = d.locked['SshConfig']
        for k, v in {'Host': '', 'Port': 80, 'Username': '', 'Password': ''}.items():
            group['Encrypted'+k] = crypt(str(v).encode(), DTConstants.KEY_192)
        config = dict(DEFAULTS, host='vless.example.invalid', uuid='synthetic-uuid', port=443)
        d.locked['V2RayConfig']['EncryptedConfig'] = crypt(render(config).encode(), DTConstants.KEY_192)
        d.raw_json = put_member(d.raw_json, (), 'type', 'VLESS')
        d.raw_json = put_member(d.raw_json, (), 'vlessTunnelConfig', {'v2rayConfig': {'mux': True, 'unknown': 7}})
        a = decode(unlock_configuration(d))
        self.assertFalse(a.protected)
        self.assertEqual(a.outer['type'], 'VLESS')
        self.assertEqual(a.outer['vlessTunnelConfig']['v2rayConfig']['unknown'], 7)
        self.assertTrue(a.outer['vlessTunnelConfig']['v2rayConfig']['mux'])
        self.assertEqual(a.outer['vlessTunnelConfig']['v2rayConfig']['uuid'], config['uuid'])
        self.assertTrue(equal(a.outer['sshTunnelConfig'], d.outer['sshTunnelConfig']))

    def test_cfb_has_no_authentication_and_cannot_be_reported_as_aead(self):
        raw = b'AAAA' * 20
        c = bytearray(crypt(raw, DTConstants.KEY_192)); c[-1] ^= 1
        # This succeeds by protocol design: no tag is present.
        self.assertNotEqual(crypt(bytes(c), DTConstants.KEY_192, decrypt=True), raw)

    def test_bad_json_base64_scheme_and_types_fail(self):
        for raw in (b'dark://AAAA', b'darktunnel://!abc', b'darktunnel://A', b'\xff',
                    b'darktunnel://' + base64.b64encode(b'{"type":"SSH","name":"x","name":"y"}'),
                    b'darktunnel://' + base64.b64encode(b'{"type":[],"name":"x"}'),
                    b'darktunnel://' + base64.b64encode(b'{"type":"SSH","name":"x","encryptedLockedConfig":null}')):
            with self.assertRaises(LabError):
                decode(raw)

    def test_duplicate_msgpack_or_trailing_object_rejected(self):
        for raw in (b'\x82\xa1a\x01\xa1a\x02', b'\x80\x80'):
            with self.assertRaises(LabError):
                unpack(raw)

    def test_existing_display_is_not_a_lossless_export_source(self):
        d = decode(protected_fixture())
        self.assertIsNotNone(production_run(d.source))
        self.assertEqual(DTDecryptor._normalize_for_json({'Password': 'sentinel'}), {})
        self.assertEqual(d.export['LockedAppConfig']['Password'], bytes(range(32)))
        self.assertIsNone(production_run(encode_json(b'{"type":"VLESS","name":"Synthetic"}')))

    def test_output_is_exclusive_private_and_never_overwrites_source(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'a.dark'
            private_write(p, b'original')
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                private_write(p, b'changed')
            q = Path(directory) / 'link.dark'; q.symlink_to(p)
            with self.assertRaises(FileExistsError):
                private_write(q, b'changed')
            self.assertEqual(p.read_bytes(), b'original')

    def test_cli_file_text_and_sanitized_failures(self):
        script = Path(__file__).with_name('dark_tunnel_experiment.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 's.dark'; source.write_bytes(protected_fixture())
            for extension in ('dark', 'txt'):
                p = subprocess.run([sys.executable, str(script), str(source), '--mode', 'rewrap',
                                    '--output', str(root / ('out.' + extension))],
                                   cwd=directory, capture_output=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertNotIn(b'SYNTHETIC_SECRET', p.stdout + p.stderr)
            self.assertEqual((root/'out.dark').read_bytes(), (root/'out.txt').read_bytes())
            bad = root/'bad.dark'; bad.write_bytes(b'PRIVATE_SENTINEL_NOT_VALID')
            p = subprocess.run([sys.executable, str(script), str(bad)], capture_output=True)
            self.assertEqual(p.returncode, 1)
            self.assertNotIn(b'PRIVATE_SENTINEL', p.stdout+p.stderr)

    def test_matrix_protected_source_and_note_isolated(self):
        from create_dark_export_matrix import generate
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'matrix'
            r = generate(protected_fixture(), target)
            self.assertEqual(len(r['cases']), 6)
            self.assertTrue(r['source_has_locked_container'])
            self.assertFalse(r['vendor_locked_export_confirmed'])
            before = decode((target/'A_rewrapped.dark').read_bytes())
            after = decode((target/'E_note_rewrapped.dark').read_bytes())
            self.assertEqual(before.raw_locked, after.raw_locked)
            self.assertFalse(decode((target/'C_open.dark').read_bytes()).protected)
            self.assertEqual((target/'C_open.dark').read_bytes(), (target/'D_open_text.txt').read_bytes())
            self.assertEqual(r['cases'][0]['independent_cfb_checks'], 16)

    def test_open_vless_matrix_recovers_all_effective_fields(self):
        from create_dark_export_matrix import generate, effective_vless
        for encrypted in ({}, {'encryptedLockedConfig': ''}):
            outer = {'type': 'VLESS', 'name': 'Synthetic', 'vlessTunnelConfig': {
                'v2rayConfig': dict(DEFAULTS, host='vless.example.invalid', uuid='synthetic',
                                     wsPath='/synthetic', mux=True)}, **encrypted}
            source = encode_json(json.dumps(outer).encode())
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/'matrix'; r = generate(source, target)
                self.assertTrue(r['effective_vless_reference_preserved'])
                self.assertEqual(r['cases'][4]['origin'], 'synthetic_wrapper_on_source')
                recovered = decode((target/'E_reference_restored.dark').read_bytes())
                self.assertTrue(equal(effective_vless(decode(source)), effective_vless(recovered)))
                self.assertEqual((target/'A_rewrapped.dark').read_bytes(), (target/'B_rewrapped_text.txt').read_bytes())

    def test_matrix_failure_writes_nothing_and_existing_dir_is_never_reused(self):
        from create_dark_export_matrix import generate
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'matrix'
            with self.assertRaises(LabError):
                generate(protected_fixture(unknown=True), path)
            self.assertFalse(path.exists())
            path.mkdir()
            with self.assertRaisesRegex(LabError, 'NEW_OUTPUT_DIRECTORY_REQUIRED'):
                generate(protected_fixture(), path)

    def test_reserved_ssh_vector_is_reproducible_and_ready_for_manual_import(self):
        from dark_synthetic_vectors import reserved_ssh
        source = reserved_ssh()
        self.assertEqual(source, reserved_ssh())
        clear = decode(unlock_configuration(decode(source)))
        self.assertEqual(clear.outer['sshTunnelConfig']['sshConfig']['host'], 'ssh.example.invalid')


if __name__ == '__main__':
    unittest.main()
