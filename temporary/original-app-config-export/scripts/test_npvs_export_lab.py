"""Synthetic NPV export tests: strict preservation, authentication and errors."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from npvs_export_experiment import (D, OPEN_MAGIC, NpvLabError, NpvDocument,
    read_profile, export_open, export_sealed)
from audit_npvs_export import audit
from create_npvs_export_matrix import generate
from lossless_json import equal
from tests.golden.npvs_protected_generate import make
from Crypto.Hash import SHA256
from Crypto.Signature import DSS


def opened(raw=None):
    return read_profile(OPEN_MAGIC + (raw or b'{"configs":[{"name":"synthetic","v2rayProfile":{"server":"example.invalid","password":"npvs1:c3ludGhldGlj","port":"00443","flags":[false,0,null],"unknown":{"empty":[],"object":{}}}}]}'))


def template():
    # The existing fixture is explicitly synthetic, not a real credential.
    value = make()['expectedRaw']['metadata']
    value['policy']['displayMessage'] = ''
    value['policy']['attestationLevel'] = 'NONE'
    raw = D._canonical(value)
    return NpvDocument(b'', 'NPVS_V5_APPKEY', {}, b'', value, raw)


def signed_change(raw, signer, mutate):
    data = bytearray(raw[:-64])
    mutate(data)
    return bytes(data) + DSS.new(signer, 'deterministic-rfc6979', encoding='binary').sign(SHA256.new(data))


class NpvExportTests(unittest.TestCase):
    def test_open_byte_identical_and_npvs1_tokens_preserved(self):
        d = opened()
        self.assertEqual(export_open(d), d.source)
        self.assertEqual(d.document['configs'][0]['v2rayProfile']['password'], 'npvs1:c3ludGhldGlj')

    def test_lexical_numbers_escapes_and_empty_containers_preserved(self):
        d = opened(b' { "configs" : [{"n":1e+02,"z":-0.0,"s":"\\u65e5","b":false,"nil":null,"empty":{},"a":[]}]}\n')
        sealed = read_profile(export_sealed(d, metadata_template=template()))
        self.assertEqual(sealed.raw_document, d.raw_document)
        self.assertEqual(export_open(sealed), d.source)

    def test_sealed_roundtrip_and_independent_backend(self):
        source = opened()
        result = read_profile(export_sealed(source, metadata_template=template()))
        checked = audit(result.source, result)
        self.assertTrue(equal(result.document, source.document))
        self.assertEqual(result.raw_metadata, template().raw_metadata)
        self.assertEqual(checked['ecdsa_signatures'], 1)
        self.assertEqual(checked['chacha20_poly1305_tags'], len(result.records) + 2)

    def test_reseal_preserves_all_original_records_and_unknown_metadata(self):
        t = template()
        t.metadata['unknown'] = {'retained': [False, 0, None, 'opaque']}
        t.metadata['policy']['unknown'] = {'opaque': True}
        t.raw_metadata = b' ' + D._canonical(t.metadata) + b'\n'
        # Start with a sealed object: no open-policy conversion is requested.
        first = opened()
        first.kind = 'NPVS_V5_APPKEY'
        first.metadata, first.raw_metadata = t.metadata, t.raw_metadata
        a = read_profile(export_sealed(first))
        b = read_profile(export_sealed(a))
        self.assertEqual(b.records, a.records)
        self.assertEqual(b.raw_document, a.raw_document)
        self.assertEqual(b.raw_metadata, t.raw_metadata)
        with self.assertRaisesRegex(NpvLabError, 'OPEN_POLICY_NOT_REPRESENTABLE'):
            export_open(b)

    def test_each_export_uses_fresh_identity_nonce_salt_and_document_key_wrapper(self):
        a = read_profile(export_sealed(opened(), metadata_template=template()))
        b = read_profile(export_sealed(opened(), metadata_template=template()))
        for x, y in ((a.source, b.source), (a.envelope['nonce'], b.envelope['nonce']),
                     (a.envelope['header'][1:17], b.envelope['header'][1:17]),
                     (a.envelope['header'][17:50], b.envelope['header'][17:50]),
                     (a.envelope['descriptor'][2:18], b.envelope['descriptor'][2:18]),
                     (a.envelope['descriptor'][18:78], b.envelope['descriptor'][18:78])):
            self.assertNotEqual(x, y)

    def test_open_requires_explicit_authenticated_policy_template_for_encryption(self):
        with self.assertRaisesRegex(NpvLabError, 'AUTHENTICATED_METADATA_TEMPLATE_REQUIRED'):
            export_sealed(opened())

    def test_nonempty_policy_not_silently_discarded_for_open_or_template(self):
        for key, value in [('expiresAt', '2027-01-01'), ('onlyMobileNetwork', True),
                           ('displayMessage', 'existing note'), ('attestationLevel', 'STRONG'),
                           ('customServerMessage', 'existing server note'), ('configVersion', True)]:
            t = template()
            t.metadata['policy'][key] = value
            t.raw_metadata = D._canonical(t.metadata)
            with self.subTest(key=key), self.assertRaises(NpvLabError):
                export_sealed(opened(), metadata_template=t)

    def test_signature_damage_and_trailing_bytes_rejected(self):
        raw = export_sealed(opened(), metadata_template=template())
        for bad in (raw[:-1], raw + b'\0', raw[:-1] + bytes([raw[-1] ^ 1])):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                read_profile(bad)

    def test_each_authenticated_layer_rejects_even_with_valid_new_signature(self):
        # Reuse a synthetic creator only to let mutated frames reach the AEADs.
        signer = make()['creator']
        t = template()
        source = opened()
        # Patch the writer's ECC generator only for this synthetic test.
        from unittest.mock import patch
        with patch('npvs_export_experiment.ECC.generate', return_value=signer):
            raw = export_sealed(source, metadata_template=t)
        hlen = int.from_bytes(raw[5:9], 'big')
        positions = {'wrapped_dek_tag': 9 + 130, 'metadata_tag': 9 + hlen - 1,
                     'inventory_hmac': len(raw) - 65}
        for label, offset in positions.items():
            def change(data, pos=offset):
                data[pos] ^= 1
            bad = signed_change(raw, signer, change)
            D.inspect_npvs(bad)  # Signature really is valid; rejection is deeper.
            with self.subTest(layer=label), self.assertRaises(ValueError):
                read_profile(bad)

    def test_field_tag_rejected_after_repairing_inventory_and_signature(self):
        from unittest.mock import patch
        signer = make()['creator']
        with patch('npvs_export_experiment.ECC.generate', return_value=signer):
            raw = export_sealed(opened(), metadata_template=template())
        env = D.inspect_npvs(raw)
        from npvs_export_experiment import hashlib, hmac
        desc = env['descriptor']
        salt, wrapped = desc[2:18], desc[18:78]
        kdk = hashlib.sha256(b'npvtunnel/appkey/v2 '+D._whitebox_block(salt)+env['header'][1:17]).digest()
        dek = D._open(kdk, wrapped[:12], wrapped[12:], salt, 'document key')
        body = bytearray(env['body'])
        length = int.from_bytes(body[40:44], 'big')
        body[44 + length - 1] ^= 1
        body[-32:] = hmac.digest(D._field_key(dek, body[4:36], b'inventory', 0), body[:-32], 'sha256')
        def change(data):
            data[-len(body):] = body
        with self.assertRaisesRegex(D.DecodeError, 'Authentication failed: field'):
            read_profile(signed_change(raw, signer, change))

    def test_password_and_recipient_modes_are_not_converted(self):
        for fixture in (make(), make(recipient=True), make(recipient=True, version=6)):
            with self.assertRaisesRegex(NpvLabError, 'ONLY_V5_APPKEY_WITHOUT_RECIPIENTS'):
                read_profile(fixture['data'])

    def test_duplicate_keys_nonfinite_empty_configs_and_wrong_types_rejected(self):
        for raw in (b'{"configs":[],"configs":[]}', b'{"configs":[{"x":NaN}]}',
                    b'{"configs":[]}', b'{"configs":[0]}', b'{"configs":{}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                read_profile(OPEN_MAGIC + raw)

    def test_matrix_rejects_existing_directory_and_preserves_all_document_bytes(self):
        t = read_profile(export_sealed(opened(), metadata_template=template()))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)/'new'
            report = generate(t.source, opened().source, folder)
            self.assertEqual(len(report['cases']), 5)
            for case in report['cases']:
                after = read_profile((folder/case['file']).read_bytes())
                self.assertEqual(after.raw_document, opened().raw_document)
                self.assertFalse(case['banner_added'])
            with self.assertRaises(NpvLabError):
                generate(t.source, opened().source, folder)

    def test_cli_no_overwrite_no_secret_logging_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp)/'source.npvs', Path(tmp)/'out.npvs'
            source.write_bytes(opened().source)
            command = [sys.executable, str(HERE/'npvs_export_experiment.py'), '--source', str(source),
                       '--mode', 'open', '--output', str(out)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('example.invalid', result.stdout + result.stderr)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            repeat = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(repeat.returncode, 1)
            self.assertEqual(out.read_bytes(), source.read_bytes())


if __name__ == '__main__':
    unittest.main()
