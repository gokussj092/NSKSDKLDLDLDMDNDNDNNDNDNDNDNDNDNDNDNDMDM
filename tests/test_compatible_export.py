"""Source-bound export jobs; only explicitly synthetic profiles enter CI."""
import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'cloud/workers/python'))
from engine import decode_file, DecodeFailure
from exports.lossless import remove_member, parse
from exports.http_custom import export as export_hc, codec
from exports.npv import export as export_npv, MAGIC
from exports.job import PROFILE, prepare
from decoders.Python.npvs_identity import generate
from tests.golden import http_custom_899 as hc_fixture
from tests.golden.npvs_protected_generate import make


class CompatibleExportTests(unittest.TestCase):
    def test_dark_native_open_and_expiry_guard_preserve_connection_without_banner(self):
        import msgpack
        from exports import dark
        lab = str(ROOT/'temporary/original-app-config-export/scripts')
        sys.path.insert(0,lab)
        try:
            from test_dark_export_lab import protected_fixture
            source = protected_fixture()
        finally: sys.path.remove(lab)
        document = dark.decode(source)
        with self.assertRaisesRegex(ValueError,'DARK_EXPIRY_NOT_REPRESENTABLE'):
            dark.unlock_configuration(document)
        document.export['LockedAppConfig']['ExpiredAtTimestamp'] = 0
        # Authenticate a newly constructed, explicitly synthetic protected file.
        outer = dict(document.outer)
        outer['encryptedLockedConfig'] = base64.b64encode(dark.crypt(
            msgpack.packb(document.export,use_bin_type=True),dark.DTConstants.KEY_256)).decode()
        source = dark.encode_json(json.dumps(outer).encode())
        result = decode_file('dark',source,compatible_export={'profile':PROFILE})
        self.assertEqual(result['compatibleExport']['status'],'ready')
        output = base64.b64decode(result['compatibleExport']['dataBase64'])
        reopened = dark.decode(output)
        self.assertFalse(reopened.protected)
        self.assertEqual(reopened.outer['sshTunnelConfig']['sshConfig']['password'],'SYNTHETIC_SECRET_ñ')
        self.assertEqual(reopened.outer['sshTunnelConfig']['injectConfig']['unknown'],[False,0])
        self.assertNotIn(b'SP-DECODE',reopened.raw_json)
        self.assertEqual(dark.unlock_configuration(reopened),output)

    def test_ehi_accepted_path_recomputes_hmac_and_inserts_or_replaces_note(self):
        from exports.injector import export as export_ehi, carrier_key
        from exports.ehi import open_profile, D
        lab = str(ROOT/'temporary/original-app-config-export/scripts')
        sys.path.insert(0,lab)
        try:
            import test_ehi_authenticated_lab as fixture
            for note in (True,False):
                with patch.object(fixture,'MAC_KEY',carrier_key()):
                    source = fixture.authenticated_fixture(note=note)
                before = open_profile(source,carrier_mac_key=carrier_key(),require_carrier_mac=True)
                output = export_ehi(source,{},'es')
                after = open_profile(output,carrier_mac_key=carrier_key(),require_carrier_mac=True)
                self.assertFalse(after.inner['isConfigLock'])
                self.assertEqual(after.outer['lockModes'],'["none"]')
                self.assertIn('configMessage',after.inner)
                self.assertIn('SP-DECODE',D._decode_config_message(after.inner['configMessage']))
                self.assertEqual(after.inner['unknown'],before.inner['unknown'])
                self.assertEqual(after.outer['unknown'],before.outer['unknown'])
                self.assertNotEqual(after.middle,before.middle)
                self.assertNotEqual(after.iv2,before.iv2)
                self.assertNotEqual(after.aead[10:50],before.aead[10:50])
                prepared = decode_file('ehi',source,compatible_export={'profile':PROFILE})
                self.assertEqual(prepared['compatibleExport']['status'],'ready')
                bad = bytearray(source);bad[-1] ^= 1
                with self.assertRaises(ValueError): export_ehi(bytes(bad),{})
        finally: sys.path.remove(lab)

    def test_remove_known_member_keeps_neighbor_tokens_and_empty_objects(self):
        for raw in (b'{"k":1,"keep":1e+03}', b'{"keep":1e+03,"k":1}',
                    b'{"a":1, "k":1, "keep":1e+03}', b'{ "k" : 1 }'):
            changed = remove_member(raw, (), 'k')
            self.assertNotIn('k', parse(changed))
            if b'1e+03' in raw: self.assertIn(b'1e+03', changed)

    def test_hc_password_hwid_both_and_open_remove_only_opening_credentials(self):
        main = copy.deepcopy(hc_fixture.MAIN)
        main.update(c=['ssh','profiles'])
        main['g'].update(a='lock_all', f=True, g=['synthetic-device'], h=True, j=True)
        options = dict(hc_fixture.OPTIONS, customPayload='')
        for locked, protected in ((False,False),(False,True),(True,False),(True,True)):
            with patch.object(hc_fixture,'MAIN',main), patch.object(hc_fixture,'OPTIONS_TEXT',json.dumps(options)):
                raw = hc_fixture.make_file(locked=locked, protected=protected, sidecar=b'Synthetic payload')
            credentials = {}
            if locked: credentials['hwid'] = hc_fixture.HWID
            if protected: credentials['password'] = hc_fixture.PASSWORD
            with self.subTest(hwid=locked,password=protected):
                output = export_hc(raw, credentials)
                doc = codec.decrypt(output)
                self.assertEqual(doc['main']['g']['a'], 'none')
                self.assertFalse(doc['main']['g']['f'])
                self.assertEqual(doc['main']['g']['g'], [])
                self.assertEqual(doc['config'][0]['password'], 'dummy')
                self.assertEqual(doc['config'][0]['options']['customPayload'], 'Synthetic payload')
                self.assertEqual(codec.open_envelope(output)['z'], {'preserve':[1,None,False,{}]})
                self.assertNotIn('o', codec.open_envelope(output))

    def test_hc_wrong_credentials_never_generate_an_artifact(self):
        raw = hc_fixture.make_file(locked=True,protected=True)
        with self.assertRaises(ValueError): export_hc(raw, {'password':'wrong','hwid':hc_fixture.HWID})

    def test_npvs_password_and_owned_private_key_v5_v6_export_open_without_keys(self):
        identity = generate()
        cases = [(make(policy_updates={'displayMessage':''}), None)]
        cases += [(make(recipient=True,version=v,identity=identity,policy_updates={'displayMessage':''}), identity) for v in (5,6)]
        for fixture, private in cases:
            credentials = {'recipientKey':json.dumps(private)} if private else {'password':fixture['password']}
            output = export_npv(fixture['data'], credentials)
            self.assertTrue(output.startswith(MAGIC))
            self.assertEqual(parse(output[len(MAGIC):]), fixture['expectedRaw']['document'])
            self.assertNotIn(b'privateKey', output)
            self.assertNotIn(b'sharedSecret', output)
            self.assertEqual(export_npv(output, {}), output)

    def test_public_key_alone_and_foreign_private_key_do_not_export(self):
        identity = generate()
        v = make(recipient=True,identity=identity,policy_updates={'displayMessage':''})
        for credentials in ({'publicKey':identity['publicKey']},{'recipientKey':json.dumps(generate())}):
            with self.assertRaises(ValueError): export_npv(v['data'],credentials)

    def test_unknown_or_nonrepresentable_policy_not_silently_deleted(self):
        v = make(policy_updates={'displayMessage':'','expiresAt':'2027-01-01'})
        with self.assertRaisesRegex(ValueError,'POLICY_NOT_REPRESENTABLE'):
            export_npv(v['data'],{'password':v['password']})

    def test_worker_prepares_bytes_bound_to_original_and_decoded_result(self):
        source = MAGIC+b'{"configs":[{"name":"Synthetic","unknown":[false,0,null]}]}'
        result = decode_file('npvs', source, compatible_export={'profile':PROFILE})
        a = result['compatibleExport']
        self.assertEqual(a['status'],'ready')
        self.assertEqual(base64.b64decode(a['dataBase64']),source)
        self.assertEqual(a['sourceSha256'],hashlib.sha256(source).hexdigest())
        self.assertEqual(a['decodedSha256'],hashlib.sha256(result['rawText'].encode()).hexdigest())
        self.assertEqual(a['sha256'],hashlib.sha256(source).hexdigest())
        self.assertNotIn('compatibleExport', decode_file('npvs',source))

    def test_export_failure_does_not_replace_successful_decryption(self):
        v = make(policy_updates={'expiresAt':'2027-01-01'})
        r = decode_file('npvs',v['data'], credentials={'password':v['password']}, compatible_export={'profile':PROFILE})
        self.assertEqual(r['status'],'success')
        self.assertFalse(r['isPartial'])
        self.assertEqual(r['compatibleExport']['status'],'unavailable')
        self.assertNotIn('dataBase64',r['compatibleExport'])

    def test_unknown_options_rejected_before_any_decode(self):
        for options in ({'profile':'guess'}, {'profile':PROFILE,'url':'https://example.invalid'}, {'profile':PROFILE,'language':'xx'}):
            with self.assertRaises(DecodeFailure) as caught:
                decode_file('npvs',b'invalid',compatible_export=options)
            self.assertEqual(caught.exception.code,'INVALID_REQUEST')

    def test_combined_reply_limit_does_not_truncate_json(self):
        source = MAGIC+b'{"configs":[{"name":"Synthetic"}]}'
        result = {'rawText':'sensitive-result','structuredJson':{'full':True}}
        with patch('exports.job.MAX_REPLY',32):
            a = prepare('npvs',source,{}, {'profile':PROFILE},result)
        self.assertEqual(a,{'status':'unavailable','code':'EXPORT_TOO_LARGE'})
        self.assertEqual(result['rawText'],'sensitive-result')


if __name__ == '__main__': unittest.main()
