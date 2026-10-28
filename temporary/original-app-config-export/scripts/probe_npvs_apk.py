#!/usr/bin/env python3
"""Hash-pinned static evidence for the owner's NPV 124.0.37 APK set."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile

from loguru import logger
logger.remove()
from androguard.core.dex import DEX

BASE_SHA256 = '1999c5748b1ab1cc9a314573052665c96619cdd3bef570704e778ad5b5901a74'
GO_SHA256 = 'ea5c68f088256b648b91c0ca009ad7f6d144e5d107608f622a5f564c9bc8891b'
NATIVE_SHA256 = '6ba05d3ac27f28b1b058b1162c0c0de0009fff47fc876b7e924f3288b1fd7c89'


def probe(apks):
    with zipfile.ZipFile(apks) as archive:
        base = archive.read('base.apk')
        split = archive.read('split_config.arm64_v8a.apk')
    if hashlib.sha256(base).hexdigest() != BASE_SHA256:
        raise ValueError('Unsupported base APK hash')
    with zipfile.ZipFile(io.BytesIO(split)) as archive:
        hashes = {name: hashlib.sha256(archive.read('lib/arm64-v8a/'+name)).hexdigest()
                  for name in ('libgojni.so', 'libnpvtunnel.so')}
    if hashes != {'libgojni.so': GO_SHA256, 'libnpvtunnel.so': NATIVE_SHA256}:
        raise ValueError('Unsupported native library hashes')
    wanted = {'Luh/t4;', 'Lah/k3;', 'Lah/f0;', 'Lah/c0;', 'Lah/r2;'}
    classes = {}
    with zipfile.ZipFile(io.BytesIO(base)) as archive:
        for name in archive.namelist():
            if name.startswith('classes') and name.endswith('.dex'):
                dex = DEX(archive.read(name))
                classes.update({c.get_name(): c for c in dex.get_classes() if c.get_name() in wanted})
    if set(classes) != wanted:
        raise ValueError('Missing audited DEX classes')
    def strings(cls, name):
        matches = [m for m in classes[cls].get_methods() if m.get_name() == name]
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous method')
        return {operand[2] for ins in matches[0].get_instructions()
                if ins.get_name().startswith('const-string')
                for operand in ins.get_operands()[1:]}
    checks = {
        'open_import_prefix': {'NPVO1\n', 'NPVO1'} <= strings('Luh/t4;', 'o'),
        'open_import_error_path': any('open config parse failed' in s for s in strings('Luh/t4;', 'o')),
        'secret_string_npvs1_decode': 'npvs1:' in strings('Lah/k3;', 'b'),
        'secret_string_npvs1_encode': 'npvs1:' in strings('Lah/k3;', 'd'),
        'config_list_schema': 'configs' in strings('Lah/f0;', '<clinit>'),
        'config_body_schema': {'name', 'address', 'v2rayProfile', 'sshConfig', 'message',
                               'customServerMessage'} <= strings('Lah/c0;', '<clinit>'),
    }
    if not all(checks.values()):
        raise ValueError('Original DEX evidence differs from laboratory assumptions')
    return {'application': 'NPV Tunnel', 'version': '124.0.37', 'build': 577,
            'apks_sha256': hashlib.sha256(Path(apks).read_bytes()).hexdigest(),
            'base_apk_sha256': BASE_SHA256, 'native_libraries': hashes,
            'previously_audited_native_binaries_identical': True,
            'static_dex_checks': checks, 'original_apk_executed': False,
            'android_import': 'pending', 'banner_added': False,
            'note_support': 'string_fields_observed_HTML_rendering_not_verified'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apks', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.apks), indent=2))
