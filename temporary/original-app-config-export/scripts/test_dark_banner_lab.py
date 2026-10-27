#!/usr/bin/env python3
"""Banner serialization regressions. Real Android rendering remains pending."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from create_dark_banner_matrix import banner, generate, verify_change
from dark_tunnel_experiment import decode, rewrap, LabError, encode_json
from test_dark_export_lab import protected_fixture


class DarkBannerTests(unittest.TestCase):
    def test_only_message_changes_in_both_designs(self):
        d = decode(protected_fixture(unknown=True))
        for kind in ('compatible', 'amoled'):
            html = banner(kind)
            out = rewrap(d, note=html)
            after = verify_change(d, out, html)
            self.assertEqual(after.raw_locked, d.raw_locked)
            self.assertEqual(after.export['LockedAppConfig']['Message'], html)
            self.assertTrue(html.startswith(b'<'))
            self.assertNotIn(b'\n', html)
            self.assertNotIn(b'\r', html)

    def test_control_and_text_tokens_match_and_remain_private(self):
        source = protected_fixture()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'banners'
            report = generate(source, target)
            self.assertEqual(len(report['cases']), 3)
            for record in report['cases']:
                data = (target/record['file']).read_bytes()
                self.assertEqual((target/record['file']).stat().st_mode & 0o777, 0o600)
                self.assertEqual(record['independent_cfb_checks'], 16)
                if record['kind'] == 'control':
                    self.assertEqual(decode(data).raw_json, decode(source).raw_json)
                else:
                    self.assertEqual(data, (target/record['text_file']).read_bytes())

    def test_no_partial_files_on_open_source_or_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'banners'
            with self.assertRaisesRegex(LabError, 'EXISTING_NOTE_WRAPPER_REQUIRED'):
                generate(encode_json(b'{"type":"VLESS","name":"Synthetic"}'), target)
            self.assertFalse(target.exists())
            target.mkdir()
            with self.assertRaisesRegex(LabError, 'NEW_OUTPUT_DIRECTORY_REQUIRED'):
                generate(protected_fixture(), target)

    def test_credits_links_and_no_remote_assets(self):
        for kind in ('compatible', 'amoled'):
            html = banner(kind).decode()
            for expected in ('SP-DECODE', 'Ghost Developer', 'Ghost Nexora Studio',
                             'https://spdecode.xyz', 'https://t.me/GhostDeve',
                             'https://t.me/CodeBreakersHub', 'https://t.me/Gh0stDeveloper'):
                self.assertIn(expected, html)
            for forbidden in ('<script', '<iframe', '<img', '<form', 'javascript:', 'src='):
                self.assertNotIn(forbidden, html)

    def test_empty_message_is_replaced_instead_of_appended(self):
        d = decode(protected_fixture())
        empty = decode(rewrap(d, note=b''))
        html = banner('compatible')
        after = verify_change(empty, rewrap(empty, note=html), html)
        self.assertEqual(after.export['LockedAppConfig']['Message'], html)
        self.assertNotIn(b'old note', after.export['LockedAppConfig']['Message'])

    def test_unrelated_crypto_or_metadata_changes_are_rejected(self):
        d = decode(protected_fixture())
        tampered = deepcopy(d)
        tampered.raw_locked = b'changed'
        with self.assertRaises(LabError):
            verify_change(tampered, rewrap(d, note=b'<b>SP-DECODE</b>'), b'<b>SP-DECODE</b>')


if __name__ == '__main__':
    unittest.main()
