#!/usr/bin/env python3
"""Offline, hash-pinned build1391 research. Outputs are private, never Git inputs.

Recovers the original application's configuration recipe, not login, payment,
VIP, license, reward, device access, or Play Integrity credentials.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'scripts/apk_analysis'))
from elf_inspect import ElfImage

LIB_SHA256 = 'e42ea94147e04390f27c35f1d2e067e10c4c5a170f4a70b3ac59f56fc18c04d0'
BASE_SHA256 = 'bd5a259b37427914a44a3e49f7ad4f9a8b22823285f6dc9d94f4e809036b8aac'

def xor_literal(image, address, length):
    return bytes(b ^ ((i + 0x77) & 255) for i, b in enumerate(image.read(address, length)))

def recover(library: Path, apk: Path):
    if hashlib.sha256(library.read_bytes()).hexdigest() != LIB_SHA256:
        raise ValueError('Unrecognized library build')
    if hashlib.sha256(apk.read_bytes()).hexdigest() != BASE_SHA256:
        raise ValueError('Unrecognized base APK')
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK
    app = APK(str(apk))
    if app.get_package() != 'com.halcon.connect' or app.get_androidversion_code() != '1391':
        raise ValueError('Wrong package or build')
    certificates = app.get_certificates_der_v2()
    if len(certificates) != 1:
        raise ValueError('Expected one original certificate')
    image = ElfImage(library)
    certificate_hash = hashlib.sha256(base64.b64encode(certificates[0])).hexdigest().upper()
    fragments = b''.join(xor_literal(image, a, 8) for a in range(0xc29f0, 0xc2a28, 8))
    fragments += xor_literal(image, 0xc2a28, 9)
    expected = xor_literal(image, 0xc22f8, 64).decode()
    return image, {
        'catalog_password': fragments.decode() + certificate_hash,
        'certificate_hash': certificate_hash,
        'certificate_sha256': hashlib.sha256(certificates[0]).hexdigest(),
        'primary_test': xor_literal(image, 0xc243d, 53).decode(),
        'primary_prod': xor_literal(image, 0xc2472, 53).decode(),
        'backup': xor_literal(image, 0xc24a7, 76).decode(),
        'primary': xor_literal(image, 0xc243d if certificate_hash == expected else 0xc2472, 53).decode(),
        'request_secret': xor_literal(image, 0xc2b3f, 22).decode(),
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('base_apk', type=Path)
    parser.add_argument('private_output', type=Path)
    args = parser.parse_args()
    image, recipe = recover(args.library, args.base_apk)
    args.private_output.mkdir(parents=True, exist_ok=True, mode=0o700)
    out = args.private_output / 'recipe.json'
    out.touch(mode=0o600, exist_ok=True)
    out.chmod(0o600)
    out.write_text(json.dumps(recipe, indent=2) + '\n')
    for name in ('nativeDecrypt', 'getSecretHost', 'getBackupHost', 'getDefaultConfig'):
        address, size = image.names['Java_halcon_vip_vpn_util_NativeSecurity_' + name]
        path = args.private_output / (name + '.asm')
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)
        path.write_text('\n'.join(image.disassemble(address, size)) + '\n')
    print(json.dumps({'package': 'com.halcon.connect', 'build': 1391,
                      'certificate_sha256': recipe['certificate_sha256'],
                      'default_config_is_empty': image.cstring(0x44d17) == '{}'}))

if __name__ == '__main__':
    main()
