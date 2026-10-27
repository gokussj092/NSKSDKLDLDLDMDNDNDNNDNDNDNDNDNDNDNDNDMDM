"""Synthetic full-container tests; real Android acceptance remains manual."""
import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_ehi_export_lab import fixture
from ehi_export_experiment import (open_profile, reseal, encode_message,
    observed_open_access_edits, lock_hash_rule, EhiLabError, C, D)
from ehi_carrier_keys import derive_carrier_keys
from create_ehi_authenticated_matrix import generate
from create_ehi_export_matrix import audit

MAC_KEY = bytes(range(32))  # reserved synthetic material only


def authenticated_fixture(*, explicit_salt=True, locked=True, note=True):
    d = open_profile(fixture())
    if not explicit_salt:
        del d.outer['configSalt']
    d.outer['configVersionCode'] = 244
    d.outer['lockModes'] = '["payload"]' if locked else '["none"]'
    text = (d.outer['lockModes'] + d.outer['configSalt'] if locked and explicit_salt
            else d.outer['configIdentifier'] + d.outer['lockModes'])
    d.outer['lockModesHash'] = hashlib.sha256(text.encode()).hexdigest()
    d.inner['isConfigLock'] = locked
    if not note:
        d.inner.pop('configMessage', None)
    d.raw_outer = json.dumps(d.outer, separators=(',', ':')).encode()
    d.raw_inner = json.dumps(d.inner, separators=(',', ':')).encode()
    d.carrier_mac_key = MAC_KEY
    return reseal(d)


class AuthenticatedEhiTests(unittest.TestCase):
    def test_verified_rewrap_is_identical(self):
        source = authenticated_fixture()
        d = open_profile(source, carrier_mac_key=MAC_KEY, require_carrier_mac=True)
        self.assertEqual(reseal(d), source)
        self.assertTrue(audit(d)['openssl_carrier_hmac_verified'])

    def test_absent_salt_uses_codec_default_without_inserting_metadata(self):
        source = authenticated_fixture(explicit_salt=False, locked=False)
        d = open_profile(source, carrier_mac_key=MAC_KEY)
        self.assertNotIn('configSalt', d.outer)
        self.assertEqual(d.field_salt, 'EVZJNI')
        after = open_profile(reseal(d, inner_edits={'configMessage': encode_message('text')}),
                             carrier_mac_key=MAC_KEY)
        self.assertNotIn('configSalt', after.outer)
        self.assertEqual(after.inner['serverHost'], d.inner['serverHost'])

    def test_note_change_refreshes_both_authenticated_envelopes(self):
        d = open_profile(authenticated_fixture(), carrier_mac_key=MAC_KEY)
        after = open_profile(reseal(d, inner_edits={'configMessage': encode_message('<b>SP-DECODE</b>')}),
                             carrier_mac_key=MAC_KEY)
        self.assertNotEqual(after.iv2, d.iv2)
        self.assertNotEqual(after.middle, d.middle)
        self.assertNotEqual(after.aead[10:50], d.aead[10:50])
        self.assertTrue(audit(after)['openssl_carrier_hmac_verified'])

    def test_stale_mac_reproduces_legacy_reader_false_success(self):
        d = open_profile(authenticated_fixture(), carrier_mac_key=MAC_KEY)
        changed = open_profile(reseal(d, inner_edits={'configMessage': encode_message('changed')}),
                               carrier_mac_key=MAC_KEY)
        stale = reseal(replace(changed, carrier_mac_key=None, middle=d.middle))
        self.assertIsNotNone(D.execute(stale))
        with self.assertRaisesRegex(EhiLabError, 'CARRIER_HMAC_MISMATCH'):
            open_profile(stale, carrier_mac_key=MAC_KEY)

    def test_mac_required_and_wrong_key_rejected(self):
        source = authenticated_fixture()
        with self.assertRaisesRegex(EhiLabError, 'CARRIER_MAC_KEY_REQUIRED'):
            open_profile(source, require_carrier_mac=True)
        with self.assertRaisesRegex(EhiLabError, 'CARRIER_HMAC_MISMATCH'):
            open_profile(source, carrier_mac_key=bytes(32))

    def test_access_target_hash_uses_observed_open_context(self):
        d = open_profile(authenticated_fixture(), carrier_mac_key=MAC_KEY)
        self.assertEqual(lock_hash_rule(d), 'modes_then_explicit_salt')
        outer, inner = observed_open_access_edits(d)
        self.assertEqual(outer['lockModesHash'], hashlib.sha256(
            (d.outer['configIdentifier'] + '["none"]').encode()).hexdigest())
        self.assertNotEqual(outer['lockModesHash'], d.inner['lockModesHash'])
        after = open_profile(reseal(d, outer_edits=outer, inner_edits=inner), carrier_mac_key=MAC_KEY)
        self.assertIs(after.inner['isConfigLock'], False)
        self.assertEqual(lock_hash_rule(after), 'identifier_then_modes')
        self.assertEqual(after.inner['serverHost'], d.inner['serverHost'])
        self.assertEqual(after.outer['configSalt'], d.outer['configSalt'])

    def test_unsupported_hash_not_guessed(self):
        d = open_profile(authenticated_fixture(), carrier_mac_key=MAC_KEY)
        d.outer['lockModesHash'] = '0' * 64
        with self.assertRaisesRegex(EhiLabError, 'LOCK_HASH_CONTEXT_UNVERIFIED'):
            observed_open_access_edits(d)

    def test_known_note_slot_can_be_added_and_unknown_sections_survive(self):
        d = open_profile(authenticated_fixture(explicit_salt=False, locked=False, note=False),
                         carrier_mac_key=MAC_KEY)
        self.assertNotIn('configMessage', d.inner)
        after = open_profile(reseal(d, inner_edits={'configMessage': encode_message('personalized')}),
                             carrier_mac_key=MAC_KEY)
        self.assertEqual(D._decode_config_message(after.inner['configMessage']), 'personalized')
        self.assertEqual(after.inner['unknown'], d.inner['unknown'])
        with self.assertRaises(EhiLabError):
            reseal(d, inner_edits={'inventedNote': 'invalid'})

    def test_unrecognized_apk_cannot_supply_keys(self):
        with self.assertRaisesRegex(ValueError, 'AUDITED_HTTP_INJECTOR_APK_REQUIRED'):
            derive_carrier_keys(b'not-the-audited-apk')

    def test_matrix_all_eight_cases_verify_independently(self):
        source = authenticated_fixture()
        owned = authenticated_fixture(explicit_salt=False, locked=False, note=False)
        with tempfile.TemporaryDirectory() as directory, patch(
                'create_ehi_authenticated_matrix.derive_carrier_keys', return_value=C.L2_KEY_STATIC + MAC_KEY):
            target = Path(directory)/'matrix'
            report = generate(source, owned, b'reserved-test-apk', target)
            self.assertEqual(len(report['cases']), 8)
            self.assertEqual((target/'A_REWRAP_ORIGINAL.ehi').read_bytes(), source)
            self.assertEqual((target/'owned_open/O_A_OPEN_REWRAP.ehi').read_bytes(), owned)
            for row in report['cases']:
                self.assertTrue(row['checks']['openssl_carrier_hmac_verified'])
                self.assertEqual(row['original_app_import'], 'pending')
                self.assertEqual((target/row['file']).stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
