"""Bounded KDF composition checks using only the owner's supplied password.

This does not enumerate passwords or keys. Each named hypothesis must pass
all AEAD layers in the supplied reader, not merely produce plausible JSON.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from decoders.Python.apps.HTTP_Custom.codec import open_envelope


def candidates(reader, env, password):
    salt = bytes.fromhex(env['g'])
    aad = reader._aad_base_v4(env, password_protected=True)
    inner = reader._finish_hmac_state_v4(reader.N15_IPAD_STATE,
                                       b'\xf1' + reader.V4_CERT_DIGEST + aad)
    folded = reader._finish_hmac_state_v4(reader.N15_OPAD_STATE, inner)
    pkey = reader._argon2id13(password.encode(), salt[:16], env['l'], env['m'])
    base = reader._derive_n15(salt, aad)
    hkdf = reader._hkdf_sha256
    label = b'hc-config-content-v12'
    yield 'fold-plus-password-before-content-hkdf', hkdf(folded + pkey, salt, label)
    yield 'password-plus-fold-before-content-hkdf', hkdf(pkey + folded, salt, label)
    yield 'base-plus-password-content-hkdf', hkdf(base + pkey, salt, label)
    yield 'password-plus-base-content-hkdf', hkdf(pkey + base, salt, label)
    yield 'password-hkdf-with-base-salt', hkdf(pkey, base, label)
    yield 'password-inside-fold-before-content-hkdf', hkdf(
        reader._finish_hmac_state_v4(reader.N15_OPAD_STATE,
            reader._finish_hmac_state_v4(reader.N15_IPAD_STATE,
                b'\xf1' + reader.V4_CERT_DIGEST + aad + pkey)), salt, label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('script', type=Path)
    parser.add_argument('samples', type=Path)
    args = parser.parse_args()
    auth = json.load(sys.stdin)
    spec = importlib.util.spec_from_file_location('supplied_hc', args.script)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    for path in sorted(args.samples.glob('*.hc')):
        raw = path.read_bytes()
        env = open_envelope(raw)
        if (env.get('b'), env.get('e'), env.get('h')) != (12, 'n15', 1):
            continue
        if not (type(env.get('l')) is int and 1 <= env['l'] <= 10 and
                type(env.get('m')) is int and 8192 <= env['m'] <= 256 * 1024 * 1024):
            raise ValueError('unsafe KDF limits')
        original = reader._v4_section_material
        aad = reader._aad_base_v4(env, password_protected=True)
        results = []
        try:
            for name, key in candidates(reader, env, auth['password']):
                reader._v4_section_material = lambda e, password=None, hwid=None, k=key: (k, aad, 12)
                try:
                    result = reader.decrypt_hc_v4(raw, **auth)
                    results.append({'hypothesis': name, 'all_reader_layers_authenticated': True,
                                    'profiles': len(result['config'])})
                except reader.HCDecryptError:
                    results.append({'hypothesis': name, 'all_reader_layers_authenticated': False})
        finally:
            reader._v4_section_material = original
        print(json.dumps({'sample': path.name, 'hypotheses': results}, ensure_ascii=False))


if __name__ == '__main__':
    main()
