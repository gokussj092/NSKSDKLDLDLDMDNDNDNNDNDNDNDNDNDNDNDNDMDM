#!/usr/bin/env python3
"""Read build-pinned Wolf 13 constants and confirm their Go function bindings."""
import argparse
import hashlib
import json
from pathlib import Path
from go_inspect import GoImage

BUILDS = (
    ('libgojni.so', '909d2a470dee286d4b9fdcf425b2972966f7ba4be54654036ff493408862ca2d',
     'github.com/2dust/AndroidLibXrayLite.Decrypt', 0x100ad80, 0x363810),
    ('libgoinjector.so', '9bd2ff407ee3371894239826a5677749129453b4fdadf7bdce10decdccfcd5d5',
     'main.Decrypt2', 0x2b2580, 0x87e7a),
)

def inspect(folder):
    result = []
    for name, digest, function, address, key_address in BUILDS:
        path = Path(folder) / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Unsupported Wolf native build')
        image = GoImage(path)
        if image.functions.get(function) != (address, 560):
            raise ValueError('Unexpected native method')
        code = '\n'.join(image.disassemble(address, 560))
        if not all(s in code for s in ('encoding/base64.(*Encoding).DecodeString', 'crypto/aes.NewCipher', 'crypto/cipher.NewGCM')):
            raise ValueError('Unexpected native crypto path')
        result.append({'library': name, 'sha256': digest, 'function': function,
                       'address': hex(address), 'keyAddress': hex(key_address),
                       'rawKeyHex': image.read(key_address, 32).hex(),
                       'format': 'Base64(nonce12 || AES-256-GCM ciphertext || tag16), no AAD'})
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    print(json.dumps(inspect(parser.parse_args().folder), indent=2))
