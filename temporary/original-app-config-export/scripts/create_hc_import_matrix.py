#!/usr/bin/env python3
"""Create A-E isolated private HCX4 experiments; vendor import stays pending."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

# Import this first: it sets the repository import path for direct CLI execution.
from hc_hcx4_n11_experiment import rewrap, private_write, check_changes, open_original
from decoders.Python.apps.HTTP_Custom import codec
from decoders.Python import _hc_hccfg as hc
from lossless_json import differences, equal, parse

NOTE = ('Exported with SP-DECODE\nDeveloper: Ghost Developer\n'
        'Organization: Ghost Nexora Studio\nTelegram: @GhostDeve')
URL = 'https://spdecode.xyz'
CASES = ('A_baseline_rewrap', 'B_note_only', 'C_url_only', 'D_access_only', 'E_combined')


def generate(raw, desired):
    original = codec.decrypt(raw)
    check_changes(original, desired, allow_access_type_change=True)
    env = codec.open_envelope(raw)
    key, aad = codec.derive(env, None, None)
    old_clear = hc._dec_section(env['i'], key, aad)
    outputs, results = [], []
    for index, case in enumerate(CASES):
        candidate = copy.deepcopy(original)
        if index in (1, 4):
            candidate['main']['g']['v'] = desired['main']['g']['v']
        if index in (2, 4):
            candidate['main']['u'] = desired['main']['u']
        if index in (3, 4):
            candidate['main']['g']['a'] = desired['main']['g']['a']
        candidate['protections'] = hc._norm_prot(candidate['main']['g'])
        cipher = rewrap(raw, candidate, allow_access_type_change=index in (3, 4))
        output_env = codec.open_envelope(cipher)
        clear = hc._dec_section(output_env['i'], key, aad)
        paths = differences(original['main'], candidate['main'])
        changed = ['main.' + '.'.join(path) for path in paths]
        type_changes = [path for path in paths if path == ('g', 'a') and
                        type(original['main']['g']['a']) is not type(candidate['main']['g']['a'])]
        metadata_before, metadata_after = copy.deepcopy(env), copy.deepcopy(output_env)
        for obj in (metadata_before, metadata_after):
            del obj['i']['b'], obj['i']['c']
        results.append({
            'case': case, 'sha256': hashlib.sha256(cipher).hexdigest(), 'bytes': len(cipher),
            'changed_paths': changed, 'local_crypto_roundtrip': True,
            'main_json_syntax_valid': True, 'main_plaintext_byte_identical': clear == old_clear,
            'source_field_types_preserved': not type_changes,
            'vendor_schema_validation': 'NOT_EXECUTED',
            'encrypted_profiles_and_sidecars_identical': equal(env['j'], output_env['j']),
            'all_untouched_envelope_fields_identical': equal(metadata_before, metadata_after),
            'carrier_depth_preserved': open_original(raw)[0] == open_original(cipher)[0],
            'vendor_import_result': 'PENDING_MANUAL_TEST',
        })
        outputs.append(cipher)
    return outputs, results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--edited', type=Path, help='Optional complete private projection')
    parser.add_argument('--output-dir', required=True, type=Path,
                        help='Must be a NEW directory; exclusive create prevents clobbering')
    args = parser.parse_args()
    try:
        raw = args.source.read_bytes()
        original = codec.decrypt(raw)
        desired = parse(args.edited.read_bytes()) if args.edited else copy.deepcopy(original)
        if not args.edited:
            desired['main']['g']['v'], desired['main']['u'] = NOTE, URL
            # Historical negative/control probe explicitly requested by the owner.
            # No unobserved "unlocked" enum is guessed here.
            desired['main']['g']['a'] = False
            desired['protections'] = hc._norm_prot(desired['main']['g'])
        outputs, results = generate(raw, desired)
        args.output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        for case, data in zip(CASES, outputs):
            private_write(args.output_dir / (case + '.hc'), data)
        record = {'source_sha256': hashlib.sha256(raw).hexdigest(),
                  'source_bytes': len(raw), 'cases': results}
        private_write(args.output_dir / 'import_matrix.json',
                      (json.dumps(record, indent=2) + '\n').encode())
    except (ValueError, OSError, AssertionError):
        parser.exit(2, 'Matrix failed; check supported source, schema and NEW output directory. No plaintext logged.\n')
    print('Generated A-E; all local AEAD checks pass. D/E boolean mode is diagnostic. Android import: PENDING.')


if __name__ == '__main__':
    main()
