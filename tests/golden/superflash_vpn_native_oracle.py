"""Compare private SV5C captures using original ARM64 KDF/AAD, host libsodium/JDK.

Requires the owner's original libspeigoshield.so; no APK/SO or captures in Git.
Usage: python tests/golden/superflash_vpn_native_oracle.py library.so input output
The output may contain account data: keep it outside Git.
"""
from __future__ import annotations
import base64
import ctypes as C
import ctypes.util
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/apk_analysis'))
from arm64_function import Arm64Function

# APK resource names, independently extracted; do not import the reader.
FIELDS = {'2kDKELRmSE143VdcX3FPzw==', '66P9ZUEM1ju4WGhv856BSg==',
 'ACqWMY4zuZWzSEs8cZMXIw==', 'B5jcTSGuJUFbTtH5O1IaBg==',
 'BWTPMwR0iRu1N9twHCpbAg==', 'EtNSBhechjWxm2t50NyB9Q==',
 'Fo3TT4oONvv69IQIMg1aLg==', 'ITkWvEHp29BmMaLMEGUFcw==',
 'MkRXl4D9vpREVCJ0w4qrgg==', 'PFFSWRJKZmOcNLTZxFwgjQ==',
 'QSln2zKCBJvqH9qV4M0ifg==', 'SbDP19AbQur0YtkkyRlVMA==',
 'U7V8DoP4cYkXJjCnpqW6nQ==', 'UxdyIntdYykCdV76crKnwg==',
 'W4CbS1nMWo6Y2noeUFHmXQ==', 'aH2nzD4eDLxPSxIAlVivdg==',
 'asmRO4zXsRjhDYX42dbNuw==', 'b3MPypEFR83rzFKUa4UbCw==',
 'b6stZNVaFUjLCw88dn03Ng==', 'iW1aO5DgThVAeo23xTsXSw==',
 'l7MIgkbuXMmGaaQGd54F2w==', 'mtw364P3ZslP2CZYuHTCHQ==',
 'oAqgFKE3WywLRvSvKffLOA==', 'p0PgL3l0d89mnssz7ImPJA==',
 'p9ZPlMv9V7gDszRoUaNaJw==', 'tmSbWiCK1hvytJ9f3gflkQ==',
 'vXfVafVdyaCRTDj6uBT6lg==', 'Auth', 'ID', 'Obfs', 'Password', 'Path', 'Username'}


def decode(library, data):
    emu = Arm64Function(library)
    if hashlib.sha256(emu.image.data).hexdigest() != 'd98368bf814482a9eb29fe246916cfc43e465ce07e17cd3de949d5def8a186fb':
        raise ValueError('Oracle requires the inspected SuperFlash native library')
    sodium = C.CDLL(ctypes.util.find_library('sodium'))
    verify = sodium.crypto_sign_verify_detached
    verify.argtypes = [C.c_char_p, C.c_char_p, C.c_ulonglong, C.c_char_p]
    decrypt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt
    decrypt.argtypes = [C.c_void_p, C.POINTER(C.c_ulonglong), C.c_void_p, C.c_char_p,
                       C.c_ulonglong, C.c_char_p, C.c_ulonglong, C.c_char_p, C.c_char_p]
    purpose = data[5]
    count, length = struct.unpack_from('<II', data, 12)
    message = hashlib.sha256(b'SV5C-SIG-V2\0' + data[:-64] + bytes.fromhex('d2f5270a3b6c91e4')).digest()
    assert verify(data[-64:], message, 32, emu.image.read(0x2119, 32)) == 0
    metadata = json.loads(data[20:20 + length])
    section = 'Servers' if purpose == 1 else 'Usuarios'
    pos = 20 + length
    source = emu.alloc(data)
    meta_hash = emu.alloc(hashlib.sha256(data[20:pos]).digest())
    key_ptr, aad_ptr = emu.alloc(32), emu.alloc(105)
    result = []
    for index in range(count):
        ordinal, size = struct.unpack_from('<II', data, pos)
        assert ordinal == index
        emu.call(0x19234, purpose, index, meta_hash, key_ptr)
        emu.call(0x1997c, source, meta_hash, purpose, index, size, aad_ptr)
        plain, actual = C.create_string_buffer(size), C.c_ulonglong()
        assert decrypt(plain, C.byref(actual), None, data[pos + 32:pos + 48 + size], size + 16,
                       emu.read(aad_ptr, 105), 105, data[pos + 8:pos + 32], emu.read(key_ptr, 32)) == 0
        assert actual.value == size
        result.append({**metadata[section][index], **json.loads(plain.raw)})
        pos += 48 + size
    assert pos == len(data) - 64
    pending = [(item, key) for item in result for key in item if key in FIELDS]
    commands = ''.join('field\t' + base64.b64encode(item[key].encode()).decode() + '\n' for item, key in pending)
    p = subprocess.run(['java', str(Path(__file__).with_name('superflash_vpn_oracle.java'))],
                       input=commands, text=True, capture_output=True, check=True, timeout=30)
    answers = p.stdout.splitlines()
    assert len(answers) == len(pending)
    for (item, key), answer in zip(pending, answers):
        item[key] = base64.b64decode(answer).decode()
    metadata[section] = result
    return metadata, len(pending)


if __name__ == '__main__':
    library, source, target = map(Path, sys.argv[1:])
    doc, fields = decode(library, source.read_bytes())
    with target.open('w', encoding='utf-8') as out:
        target.chmod(0o600)
        json.dump(doc, out, ensure_ascii=False)
    print(json.dumps({'records': len(doc.get('Servers', doc.get('Usuarios', []))), 'fields': fields}))
