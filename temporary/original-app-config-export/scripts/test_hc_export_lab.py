#!/usr/bin/env python3
"""Synthetic regressions only; not proof of acceptance by Android's importer."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hc_hcx4_n11_experiment import (check_changes, codec, hc, open_original,
                                    private_write, rewrap, seal)
from lossless_json import equal, parse, replace_values
from create_hc_import_matrix import generate, NOTE, URL
from tests.golden.http_custom_899 import make_file, seal as fixture_seal


def fixture(carrier=0):
    raw = make_file()
    env = codec.open_envelope(raw)
    key, aad = codec.derive(env, None, None)
    main = codec.decrypt(raw)['main']
    main['g']['v'] = 'Synthetic note'
    main['g']['a'] = 'lock_all'
    # Deliberately include whitespace, escaped slash, non-ASCII and exponent
    # spelling which ordinary json.dumps would normalize.
    main['unknown'] = {'unicode': 'ñ配置', 'url': 'https://example.invalid/', 'float': 1000.0}
    clear = json.dumps(main, ensure_ascii=True, indent=2).replace('https://', 'https:\\/\\/')
    clear = clear.replace('1000.0', '1.000e+03').encode()
    env['i']['b'], env['i']['c'] = seal(key, aad + b'\0m', clear)
    env['i']['unknown'] = {'preserve': [False, 0, {}]}
    side_nonce, side_cipher = seal(key, aad + b'\0m:x', b'synthetic main sidecar')
    env['i']['d'] = {'a': side_nonce, 'b': side_cipher}
    return fixture_seal(env, carrier)


class LabTests(unittest.TestCase):
    def test_raw_baseline_and_unknown_fields_survive_all_carriers(self):
        for depth in (0, 1, 2):
            with self.subTest(depth=depth):
                raw = fixture(depth)
                before = codec.open_envelope(raw)
                key, aad = codec.derive(before, None, None)
                out = rewrap(raw, codec.decrypt(raw))
                after = codec.open_envelope(out)
                self.assertEqual(hc._dec_section(before['i'], key, aad),
                                 hc._dec_section(after['i'], key, aad))
                self.assertEqual(before['j'], after['j'])
                self.assertEqual(before['i']['d'], after['i']['d'])
                self.assertEqual(before['i']['unknown'], after['i']['unknown'])
                self.assertEqual(open_original(out)[0], depth)
                self.assertNotEqual(out, raw)

    def test_five_case_matrix_has_exact_changes(self):
        raw = fixture()
        desired = codec.decrypt(raw)
        desired['main']['g']['v'], desired['main']['u'] = NOTE, URL
        desired['main']['g']['a'] = False
        desired['protections'] = hc._norm_prot(desired['main']['g'])
        _, result = generate(raw, desired)
        self.assertEqual([r['changed_paths'] for r in result],
                         [[], ['main.g.v'], ['main.u'], ['main.g.a'],
                          ['main.g.a', 'main.g.v', 'main.u']])
        self.assertEqual([r['source_field_types_preserved'] for r in result],
                         [True, True, True, False, False])

    def test_boolean_requires_diagnostic_opt_in(self):
        raw = fixture()
        desired = codec.decrypt(raw)
        desired['main']['g']['a'] = False
        desired['protections'] = hc._norm_prot(desired['main']['g'])
        with self.assertRaises(ValueError):
            rewrap(raw, desired)
        rewrap(raw, desired, allow_access_type_change=True)

    def test_unobserved_access_strings_rejected(self):
        raw = fixture()
        for mode in ('false', 'unlocked', ''):
            desired = codec.decrypt(raw)
            desired['main']['g']['a'] = mode
            desired['protections'] = hc._norm_prot(desired['main']['g'])
            with self.assertRaises(ValueError):
                rewrap(raw, desired)

    def test_rejected_none_reproduction_preserves_all_other_restrictions(self):
        from create_hc_access_followup import generate_followup
        raw = fixture()
        with self.assertRaises(ValueError):
            generate_followup(raw)
        outputs, records = generate_followup(raw, reproduce_rejected=True)
        self.assertEqual([r['changed_paths'] for r in records],
                         [['main.g.a'], ['main.g.a', 'main.g.v', 'main.u']])
        self.assertTrue(all(r['unedited_restrictions_preserved'] for r in records))
        for data in outputs:
            self.assertEqual(codec.decrypt(data)['main']['g']['a'], 'none')

    def test_mode_only_none_with_hpr1_is_rejected_by_default(self):
        raw = fixture()
        edited = codec.decrypt(raw)
        edited['main']['g']['a'] = 'none'
        edited['protections'] = hc._norm_prot(edited['main']['g'])
        with self.assertRaises(ValueError):
            rewrap(raw, edited)

    def test_python_boolean_integer_equality_cannot_hide_edit(self):
        original = codec.decrypt(fixture())
        for path in ('config', 'main'):
            candidate = copy.deepcopy(original)
            if path == 'config':
                candidate['config'][0]['options']['nested'][0]['zero'] = False
            else:
                candidate['main']['extra']['bool'] = 1
            with self.assertRaises(ValueError):
                check_changes(original, candidate)

    def test_missing_or_added_main_keys_are_rejected(self):
        original = codec.decrypt(fixture())
        for kind in ('add', 'remove'):
            candidate = copy.deepcopy(original)
            if kind == 'add':
                candidate['main']['g']['invented'] = False
            else:
                del candidate['main']['c']
            with self.assertRaises(ValueError):
                check_changes(original, candidate)

    def test_nested_notes_and_escaped_keys_preserve_unedited_tokens(self):
        raw = b' {"g": {"v": "old", "url": "https:\\/\\/example.invalid", "num": 1e+03}, "arr":[false,0], "\\u0061": "\\u00f1"} \n'
        changed = replace_values(raw, {('g', 'v'): 'ñ\n"\\配置'})
        self.assertIn(b'"num": 1e+03', changed)
        self.assertIn(b'"\\u0061": "\\u00f1"', changed)
        self.assertIn(b'https:\\/\\/example.invalid', changed)
        self.assertEqual(parse(changed)['g']['v'], 'ñ\n"\\配置')
        self.assertEqual(replace_values(raw, {}), raw)

    def test_no_duplicate_keys_non_finite_or_unobserved_paths(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError):
                parse(raw)
        with self.assertRaises(ValueError):
            replace_values(b'{"g":{}}', {('g', 'v'): ''})
        with self.assertRaises(ValueError):
            replace_values(b'{"g":{"a":1}}', {('g',): {}, ('g', 'a'): 2})

    def test_tampered_aead_layers_fail_closed(self):
        candidate = codec.decrypt(fixture())
        for layer in ('outer', 'main', 'profile', 'hpr', 'sidecar'):
            with self.subTest(layer=layer), self.assertRaises(ValueError):
                rewrap(make_file(tamper=layer), candidate)

    def test_protected_and_other_builds_not_exported(self):
        candidate = codec.decrypt(fixture())
        with self.assertRaises(ValueError):
            rewrap(make_file(protected=True), candidate)
        env = codec.open_envelope(fixture())
        env['n'] = 900
        with self.assertRaises(ValueError):
            rewrap(fixture_seal(env), candidate)

    def test_private_write_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'a.hc'
            private_write(path, b'original')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                private_write(path, b'changed')
            self.assertEqual(path.read_bytes(), b'original')
            link = Path(directory) / 'link.hc'
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                private_write(link, b'changed')

    def test_both_cli_commands_work_from_unrelated_directory(self):
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as directory:
            for name in ('hc_hcx4_n11_experiment.py', 'create_hc_import_matrix.py'):
                result = subprocess.run([sys.executable, str(scripts / name), '--help'],
                                        cwd=directory, capture_output=True)
                self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
