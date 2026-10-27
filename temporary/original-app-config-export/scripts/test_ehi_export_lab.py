#!/usr/bin/env python3
"""Synthetic EHI regressions; no actual-app import claim."""
import base64
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

from ehi_export_experiment import (open_profile, reseal, encode_message, decode_field,
    encode_field, access_candidate_edits, EhiLabError, C, D, kdf_key, private_write)
from create_ehi_export_matrix import generate, audit, sodium_open
from audit_ehi_decode import audit_decode, canonical_text, presentation_type, audit_matrix
from scripts.android_ehi_standard_fixture import make
from lossless_json import parse, put_member, equal


def canonical_source():
    # Historical decoder-only goldens have a zero placeholder here. The real
    # vendor sample establishes the Adler-32 slot. Supply it for export tests.
    source = make()[0]
    pos = 0
    for _ in range(2):
        pos += 2 + int.from_bytes(source[pos:pos+2], 'big') + 8
    size = int.from_bytes(source[pos:pos+4], 'big')
    checksum = zlib.adler32(source[pos+12:pos+12+size]) & 0xffffffff
    return source[:pos+4] + struct.pack('>Q', checksum) + source[pos+12:]


def fixture():
    d = open_profile(canonical_source())
    for key, value in [('lockModes', '["none"]'), ('lockModesHash', 'a'*64),
                       ('isConfigLock', True), ('unknown', {'type_preserved': [False, 0, None]})]:
        d.raw_inner = put_member(d.raw_inner, (), key, value)
    d.inner = parse(d.raw_inner)
    d.raw_outer = put_member(d.raw_outer, (), 'unknown', {'raw': 'https://example.invalid/', 'flag': False})
    d.outer = parse(d.raw_outer)
    # Fresh synthetic fixture header, never reuse real-user nonce/key material.
    d.aead = d.aead[:10] + bytes(range(16, 32)) + bytes(range(24, 48)) + d.aead[50:]
    return reseal(d)


class EhiExportTests(unittest.TestCase):
    def test_bit_identical_rewrap_of_complete_fixture(self):
        source = fixture(); d = open_profile(source)
        self.assertEqual(reseal(d), source)
        self.assertEqual(audit(d)['libsodium_aead_tags'], 1)

    def test_note_utf16_code_units_bmp_and_non_bmp_match_reader(self):
        for note in ('', 'Ghost Developer', 'Español ñ 配置', 'Test \U0001f680\n<b>SP-DECODE</b>'):
            self.assertEqual(D._decode_config_message(encode_message(note)), note)

    def test_only_authorized_message_token_changes(self):
        before = open_profile(fixture())
        note = encode_message('<b>SP-DECODE</b>\nSynthetic note')
        after = open_profile(reseal(before, inner_edits={'configMessage': note},
                                    allow_unverified_middle=True))
        expected = dict(before.inner, configMessage=note)
        self.assertTrue(equal(after.inner, expected))
        self.assertNotEqual(before.aead[10:50], after.aead[10:50])
        self.assertEqual(before.inner['serverHost'], after.inner['serverHost'])
        self.assertEqual(before.inner['unknown'], after.inner['unknown'])
        self.assertEqual(before.outer['unknown'], after.outer['unknown'])

    def test_access_tuple_rekeys_both_layers_and_keeps_connection(self):
        d = open_profile(fixture()); outer, inner = access_candidate_edits(d)
        after = open_profile(reseal(d, outer_edits=outer, inner_edits=inner,
                                    allow_unverified_middle=True))
        self.assertNotEqual(D._generate_master_key(d.outer), D._generate_master_key(after.outer))
        self.assertEqual(after.outer['lockModesHash'], d.inner['lockModesHash'])
        self.assertIs(after.inner['isConfigLock'], False)
        self.assertEqual(after.inner['serverHost'], d.inner['serverHost'])
        self.assertEqual(audit(after)['openssl_cbc_layers'], 2)

    def test_missing_none_metadata_is_not_guessed(self):
        with self.assertRaisesRegex(EhiLabError, 'OBSERVED_NONE_METADATA_REQUIRED'):
            access_candidate_edits(open_profile(canonical_source()))

    def test_field_xor_keeps_nuls_and_hex_case(self):
        for upper in (False, True):
            clear = b'\x00\x01synthetic\x00'
            token = encode_field(clear, 'EVZJNI', upper)
            result, case = decode_field(token, 'EVZJNI')
            self.assertEqual(result, clear)
            self.assertEqual(encode_field(result, 'EVZJNI', case), token)

    def test_unknown_frame_longs_and_tail_survive(self):
        source = bytearray(fixture());source[5:13] = b'OPAQUE01';source += b'UNKNOWN_PRIVATE_TRAILER'
        d = open_profile(bytes(source));out = reseal(d, inner_edits={'configMessage': encode_message('new')},
                                                   allow_unverified_middle=True)
        self.assertEqual(out[:d.length_offset], bytes(source[:d.length_offset]))
        after = open_profile(out)
        self.assertEqual(int.from_bytes(out[d.length_offset+4:d.payload_offset], 'big'),
                         zlib.adler32(out[after.payload_offset:after.payload_offset+after.payload_size]) & 0xffffffff)
        self.assertTrue(out.endswith(b'UNKNOWN_PRIVATE_TRAILER'))

    def test_unsupported_paths_or_type_change_fail(self):
        d = open_profile(fixture())
        for kwargs in ({'inner_edits': {'serverHost': 'other'}}, {'outer_edits': {'configSalt': 'other'}},
                       {'inner_edits': {'isConfigLock': 0}}, {'inner_edits': {'configMessage': False}}):
            with self.assertRaises(EhiLabError):
                reseal(d, **kwargs)

    def test_bounded_kdf_and_unsupported_version(self):
        d = open_profile(fixture())
        for version, memory in ((2, 32), (1, 0xffffffff)):
            body = bytearray(d.aead);body[0]=version;body[5:9]=struct.pack('<I',memory)
            with self.assertRaises(EhiLabError):
                kdf_key(d.outer, body)

    def test_aead_tampering_fails_in_independent_backend(self):
        d = open_profile(fixture());key=kdf_key(d.outer,d.aead)
        for index in (10, 26, 50, len(d.aead)-1):
            body=bytearray(d.aead);body[index]^=1
            with self.assertRaisesRegex(EhiLabError, 'INDEPENDENT_AEAD_AUTH_FAILED'):
                sodium_open(key, bytes(body))

    def test_corrupt_framing_and_cbc_are_not_success(self):
        source=fixture()
        for raw in (source[:-1], b'bad'+source[3:], source[:20], source[:-16]+bytes(16)):
            with self.assertRaises(EhiLabError):
                open_profile(raw)

    def test_stale_checksum_rejected_before_crypto(self):
        d=open_profile(fixture());changed=bytearray(d.source)
        changed[d.length_offset+4:d.payload_offset]=bytes(8)
        with self.assertRaisesRegex(EhiLabError,'FRAME_ADLER32_MISMATCH'):
            open_profile(bytes(changed))
        out=reseal(d,inner_edits={'configMessage':encode_message('changed note')},
                   allow_unverified_middle=True)
        self.assertNotEqual(out[d.length_offset+4:d.payload_offset],d.source[d.length_offset+4:d.payload_offset])
        self.assertEqual(open_profile(out).inner['configMessage'],encode_message('changed note'))

    def test_matrix_scope_permissions_and_no_overwrite(self):
        source=fixture()
        with tempfile.TemporaryDirectory() as directory:
            dest=Path(directory)/'matrix';report=generate(source,dest,reproduce_rejected_exports=True)
            self.assertEqual(len(report['cases']),7)
            self.assertEqual((dest/'A_REWRAP_ORIGINAL.ehi').read_bytes(),source)
            self.assertFalse(report['access_hash_algorithm_confirmed'])
            for record in report['cases']:
                self.assertEqual((dest/record['file']).stat().st_mode & 0o777,0o600)
                self.assertTrue(record['connection_fields_unchanged'])
            with self.assertRaises(EhiLabError):generate(source,dest)
            p=dest/'A_REWRAP_ORIGINAL.ehi'
            with self.assertRaises(FileExistsError):private_write(p,b'overwrite')
            self.assertEqual(p.read_bytes(),source)

    def test_modified_exports_blocked_without_carrier_verification(self):
        d=open_profile(fixture())
        self.assertEqual(reseal(d),d.source)
        with self.assertRaisesRegex(EhiLabError,'MODIFIED_EXPORT_BLOCKED_UNVERIFIED_CARRIER_SEGMENT'):
            reseal(d,inner_edits={'configMessage':encode_message('new note')})
        with tempfile.TemporaryDirectory() as directory:
            dest=Path(directory)/'must-not-exist'
            with self.assertRaisesRegex(EhiLabError,'REJECTED_EHI_MATRIX_REPRODUCTION_OPT_IN_REQUIRED'):
                generate(d.source,dest)
            self.assertFalse(dest.exists())

    def test_tls_default_key_candidate_is_bounded_and_does_not_mutate_source(self):
        d=open_profile(fixture())
        token=encode_field(b'TLSv1.2','EVZJNI').replace('=','?')
        dynamic='ABCDEF'
        d.outer['configSalt']=dynamic
        d.inner['tlsVersion']=token
        d.inner['password']=encode_field(b'007030',dynamic)
        d.inner['lockModes']='["none"]'
        d.inner['not_a_known_field']='synthetic-unresolved-string'
        before=dict(d.inner)
        result=audit_decode(d)
        tls=next(f for f in result['fields'] if f['known_name']=='tlsVersion')
        self.assertEqual(tls['default_salt_tls_candidate'],'TLSv1.2')
        self.assertTrue(tls['default_salt_codec_roundtrip'])
        self.assertFalse(tls['android_tls_setting_verified'])
        password=next(f for f in result['fields'] if f['known_name']=='password')
        self.assertEqual(password['legacy_decoded_type'],'str')
        self.assertEqual(canonical_text(d.inner['password'],dynamic),'007030')
        self.assertEqual(d.inner,before)
        raw=__import__('json').dumps(result)
        self.assertNotIn('007030',raw)
        self.assertNotIn('synthetic-unresolved-string',raw)
        self.assertNotIn('not_a_known_field',raw)

    def test_observed_question_padding_requires_exact_roundtrip(self):
        token=encode_field(b'TLSv1.2','EVZJNI')
        self.assertIn('=',token)
        self.assertEqual(canonical_text(token.replace('=','?'),'EVZJNI'),'TLSv1.2')
        self.assertIsNone(canonical_text(token[:5]+'?'+token[5:],'EVZJNI'))
        nul=encode_field(b'\0TLSv1.2','EVZJNI')
        self.assertEqual(canonical_text(nul,'EVZJNI'),'\0TLSv1.2')

    def test_presentation_reparse_loses_string_types(self):
        self.assertEqual(presentation_type('81234567'),'int')
        self.assertEqual(presentation_type('["none"]'),'list')
        self.assertEqual(presentation_type('literal-string'),'str')
        self.assertEqual(presentation_type(False),'bool')

    def test_wrong_salt_does_not_become_globally_approved_plaintext(self):
        d=open_profile(fixture())
        d.inner['tlsVersion']=encode_field(b'not-a-TLS-enum','EVZJNI')
        result=audit_decode(d)
        tls=next(f for f in result['fields'] if f['known_name']=='tlsVersion')
        self.assertNotIn('default_salt_tls_candidate',tls)
        self.assertFalse(result['all_fields_fully_interpreted'])
        self.assertFalse(result['outer_carrier_integrity_verified'])

    def test_audit_exposes_only_known_names_types_and_safe_metadata(self):
        d=open_profile(fixture())
        d.inner['secret-personal-field-name']='secret-personal-value'
        d.inner['configMessage']='invalid-ciphertext-message'
        result=audit_decode(d)
        raw=__import__('json').dumps(result)
        for secret in ('secret-personal-field-name','secret-personal-value','invalid-ciphertext-message'):
            self.assertNotIn(secret,raw)
        self.assertTrue(any(f['status']=='unresolved_message' for f in result['fields']))

    def test_matrix_audit_retains_version_error_as_unconfirmed_root_cause(self):
        d=open_profile(fixture())
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'historical'
            generate(d.source,output,reproduce_rejected_exports=True)
            report=audit_matrix(d,output)
            self.assertFalse(report['version_error_root_cause_confirmed'])
            self.assertFalse(report['hmac_algorithm_or_key_recovered'])
            for row in report['cases']:
                self.assertTrue(row['outer_version_unchanged'])
                self.assertTrue(row['inner_version_unchanged'])
                self.assertTrue(row['carrier_middle_unchanged'])
                self.assertTrue(row['frame_adler32_verified'])
                self.assertFalse(row['carrier_integrity_verified'])

    def test_cli_works_from_another_directory_without_plaintext_logs(self):
        script=Path(__file__).with_name('ehi_export_experiment.py')
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'source.ehi';p.write_bytes(fixture())
            result=subprocess.run([sys.executable,str(script),str(p)],cwd=directory,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn(b'example.org',result.stdout+result.stderr)

    def test_redacted_audit_cli_keeps_private_values_out_of_stdout(self):
        script=Path(__file__).with_name('audit_ehi_decode.py')
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'source.ehi';p.write_bytes(fixture())
            result=subprocess.run([sys.executable,str(script),str(p)],cwd=directory,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            report=__import__('json').loads(result.stdout)
            self.assertFalse(report['all_fields_fully_interpreted'])
            self.assertEqual(report['source']['authentication_scope'],'inner_aead_only')
            self.assertNotIn(b'example.org',result.stdout+result.stderr)
            self.assertNotIn(b'synthetic-parity-test',result.stdout+result.stderr)


if __name__=='__main__':unittest.main()
