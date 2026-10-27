#!/usr/bin/env python3
"""Historical EHI A-E reproduction. Changed files were rejected by the owner."""
import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from ehi_export_experiment import (open_profile, reseal, access_candidate_edits,
    encode_message, kdf_key, private_write, summary, EhiLabError, C, D)
from lossless_json import differences
from spdecode_note import html_note, plain_note


def sodium_open(key, body):
    library = ctypes.util.find_library('sodium')
    if library is None:
        raise EhiLabError('INDEPENDENT_SODIUM_BACKEND_REQUIRED')
    sodium = ctypes.CDLL(library)
    f = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt
    f.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p,
                  ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                  ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p]
    f.restype = ctypes.c_int
    output = ctypes.create_string_buffer(len(body))
    length = ctypes.c_ulonglong()
    encrypted = body[50:]
    if f(output, ctypes.byref(length), None, encrypted, len(encrypted),
         body[:26], 26, body[26:50], key) != 0:
        raise EhiLabError('INDEPENDENT_AEAD_AUTH_FAILED')
    return output.raw[:length.value]


def audit(document):
    """OpenSSL CBC + libsodium XChaCha, independent of PyCryptodome ciphers."""
    def cbc(ciphertext, key, iv):
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpad = PKCS7(128).unpadder()
        return unpad.update(padded) + unpad.finalize()

    payload = document.source[document.payload_offset:document.payload_offset+document.payload_size]
    first = cbc(payload, C.L1_KEY, (C.BYPASS_IVS+C.STANDARD_IVS)[document.iv_index])
    parts = first.split(b':')
    second = cbc(base64.b64decode(parts[2]), C.L2_KEY_STATIC, base64.b64decode(parts[0]))
    if D._xxtea_decrypt(second, C.EOO_MASTER_KEY) != document.xx_prefix + document.raw_outer:
        raise EhiLabError('INDEPENDENT_CBC_MISMATCH')
    if sodium_open(kdf_key(document.outer, document.aead), document.aead) != document.raw_inner:
        raise EhiLabError('INDEPENDENT_AEAD_PLAINTEXT_MISMATCH')
    return {'openssl_cbc_layers': 2, 'libsodium_aead_tags': 1,
            'argon2id_backend': 'argon2-cffi', 'argon2id_independent_backend': False}


def generate(source, output_dir, *, reproduce_rejected_exports=False):
    out = Path(output_dir)
    if out.exists():
        raise EhiLabError('NEW_OUTPUT_DIRECTORY_REQUIRED')
    if not reproduce_rejected_exports:
        raise EhiLabError('REJECTED_EHI_MATRIX_REPRODUCTION_OPT_IN_REQUIRED')
    original = open_profile(source)
    outer_access, inner_access = access_candidate_edits(original)
    plain = encode_message(plain_note('es'))
    # Use a single line: the source message algorithm preserves literal LF.
    html = encode_message(html_note('es').replace('\r', '').replace('\n', ''))
    specs = [
        ('A_REWRAP_ORIGINAL.ehi', {}, {}, 'unchanged'),
        ('B_NOTE_TEXT_ONLY.ehi', {}, {'configMessage': plain}, 'note_only'),
        ('C_NOTE_HTML_ONLY.ehi', {}, {'configMessage': html}, 'html_only'),
        ('D_ACCESS_CANDIDATE.ehi', outer_access, inner_access, 'access_candidate'),
        ('E_ACCESS_HTML_CANDIDATE.ehi', outer_access, dict(inner_access, configMessage=html), 'combined_candidate'),
        ('diagnostics/FLAG_ONLY.ehi', {}, inner_access, 'inner_flag_only'),
        ('diagnostics/OUTER_NONE_ONLY.ehi', outer_access, {}, 'outer_none_tuple_only'),
    ]
    report = {'source': summary(original), 'target_app': {'package': 'com.evozi.injector',
              'version': '6.5.0', 'build': 244}, 'cases': [],
              'preserve_unknown_fields': True, 'original_app_import': 'pending',
              'editable_access': 'pending', 'banner_rendering': 'pending',
              'access_hash_algorithm_confirmed': False,
              'carrier_integrity_verified': False,
              'purpose': 'historical_reproduction_of_rejected_candidates',
              'prior_owner_result': 'A accepted; B-E version-error rejection',
              'access_candidate_basis': 'reuse the observed inner none lockModes/hash tuple; not an invented hash',
              'connection_fields_changed': False}
    files = []
    for name, outer, inner, kind in specs:
        raw = reseal(original, outer_edits=outer, inner_edits=inner,
                     allow_unverified_middle=True)
        after = open_profile(raw)
        check = audit(after)
        if name.startswith('A_') and raw != source:
            raise EhiLabError('UNCHANGED_CONTROL_NOT_BYTE_IDENTICAL')
        report['cases'].append({'file': name, 'kind': kind, 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'outer_changed_paths': [list(p) for p in differences(original.outer, after.outer)],
            'inner_changed_paths': [list(p) for p in differences(original.inner, after.inner)],
            'connection_fields_unchanged': True, 'independent_crypto': check,
            'source_frame_metadata_preserved': True,
            'derived_frame_checksum': 'adler32_recomputed_and_verified',
            'byte_identical_to_source': raw == source,
            'local_decode': 'passed', 'original_app_import': 'pending',
            'carrier_integrity_verified': False,
            'editor_access': 'pending', 'banner_rendering': 'pending' if 'HTML' in name else 'not_tested'})
        files.append((name, raw))
    out.mkdir(parents=True, mode=0o700)
    (out/'diagnostics').mkdir(mode=0o700)
    for name, raw in files:
        private_write(out/name, raw)
    private_write(out/'REPORT.json', (json.dumps(report, indent=2)+'\n').encode())
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--reproduce-rejected-exports', action='store_true',
        help='diagnóstico histórico: las variantes modificadas fueron rechazadas')
    args = parser.parse_args()
    try:
        result = generate(args.source.read_bytes(), args.output_dir,
            reproduce_rejected_exports=args.reproduce_rejected_exports)
        print(json.dumps({'files': len(result['cases']), 'source_config_version_code':
            result['source']['source_config_version_code'], 'local_checks': 'passed',
            'original_app_import': 'pending', 'editor_access': 'pending'}))
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print(json.dumps({'error': str(error) if isinstance(error, EhiLabError) else 'INPUT_OR_OUTPUT_ERROR'}), file=sys.stderr)
        sys.exit(1)
