#!/usr/bin/env python3
"""Offline, hash-pinned HTTP Injector 244 inspection artifacts, outside git.

Reads the supplied APKS (or its ZIP wrapper). Does not run Android, patch an
APK, repair DEX checksums, publish vendor code or contact any VPN server.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile
import zlib

from Crypto.Cipher import ARC4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ehi_carrier_keys import APK_SHA256
from ehi_export_experiment import private_write, EhiLabError

NATIVE_HASHES = {
    'libdatajar.so': '2563039f827ff936035abfbe7aeb0cb9d4bac8bf42f414bb6c68cf7241081a4d',
    'libDexHelper.so': '1aea4de158534b5bc28958d9b343e31adfe4609495978c4785719398ea271a68',
    'libdexjniehi.so': '771f0e37d0ebb55a9e3c4543c97ae8dc5652338090817554fa8155be40dc5e29',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_inputs(raw):
    if len(raw) > 100 * 1024 * 1024:
        raise EhiLabError('APK_ARCHIVE_TOO_LARGE')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        nested = [i for i in archive.infolist() if i.filename.endswith('.apks')]
        if nested:
            if len(nested) != 1 or nested[0].file_size > 100 * 1024 * 1024:
                raise EhiLabError('UNSUPPORTED_APKS_WRAPPER')
            raw = archive.read(nested[0])
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for entry in archive.infolist():
            if not entry.filename.endswith('.apk'):
                continue
            if entry.file_size > 64 * 1024 * 1024:
                raise EhiLabError('SPLIT_APK_TOO_LARGE')
            apk = archive.read(entry)
            if digest(apk) == APK_SHA256:
                files['base.apk'] = apk
            with zipfile.ZipFile(io.BytesIO(apk)) as split:
                for name in NATIVE_HASHES:
                    path = 'lib/arm64-v8a/' + name
                    if path in split.namelist():
                        item = split.getinfo(path)
                        if item.file_size > 32 * 1024 * 1024:
                            raise EhiLabError('NATIVE_FILE_TOO_LARGE')
                        files[name] = split.read(item)
    if set(files) != {'base.apk', *NATIVE_HASHES}:
        raise EhiLabError('AUDITED_BASE_AND_ARM64_LIBRARIES_REQUIRED')
    for name, expected in NATIVE_HASHES.items():
        if digest(files[name]) != expected:
            raise EhiLabError('NATIVE_HASH_MISMATCH')
    return files


def unpack_native(raw):
    marker = raw.find(b'd!a@t#a$')
    if marker < 16:
        raise EhiLabError('NATIVE_WRAPPER_MARKER_REQUIRED')
    meta = marker - 16
    start = struct.unpack_from('<I', raw, meta + 32)[0]
    key_offset = struct.unpack_from('<I', raw, meta + 56)[0]
    if not (start + 128 < len(raw) and key_offset + 16 <= len(raw)):
        raise EhiLabError('NATIVE_WRAPPER_BOUNDS')
    header = ARC4.new(raw[key_offset:key_offset+16]).decrypt(raw[start:start+64])
    if header[:6] != b'\x7fELF\x02\x01':
        raise EhiLabError('NATIVE_HEADER_DECRYPT_FAILED')
    key = raw[start+65]
    clear = header + bytes(x ^ key for x in raw[start+64:])
    if struct.unpack_from('<II', clear, 64) != (1, 5):
        raise EhiLabError('NATIVE_PROGRAM_HEADER_INVALID')
    return clear


def recover(files):
    data = files['libdatajar.so']
    plain_size, compressed_size, expanded_size = struct.unpack_from('>III', data, 0x400c)
    start = 0x4018
    if not (expanded_size <= 64 * 1024 * 1024 and start+plain_size+compressed_size <= len(data)):
        raise EhiLabError('DEX_POOL_BOUNDS')
    compressed = data[start+plain_size:start+plain_size+compressed_size]
    if compressed[:4] != bytes.fromhex('28b52ffd'):
        raise EhiLabError('OBSERVED_ZSTD_POOL_REQUIRED')
    library = ctypes.util.find_library('zstd')
    if library is None:
        raise EhiLabError('SYSTEM_LIBZSTD_REQUIRED')
    zstd = ctypes.CDLL(library)
    zstd.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    zstd.ZSTD_decompress.restype = ctypes.c_size_t
    buffer = ctypes.create_string_buffer(expanded_size)
    size = zstd.ZSTD_decompress(buffer, expanded_size, compressed, len(compressed))
    if size != expanded_size:
        raise EhiLabError('ZSTD_POOL_SIZE_MISMATCH')
    pool = data[start:start+plain_size] + buffer.raw
    # Original helper constant and package-bound XOR, also described for the
    # older RC4 variant by Quarkslab/DxFx. This APK selects SM4-ECB instead.
    key = bytes(x ^ y for x, y in zip(bytes.fromhex('66976ce86d4638b0095aa5d70fcb9aa0'),
                                     b'com.evozi.injector'))
    output, records = {}, []
    for offset in range(0x1000, len(pool)-112, 0x1000):
        dec = Cipher(algorithms.SM4(key), modes.ECB()).decryptor()
        header = dec.update(pool[offset:offset+112]) + dec.finalize()
        if header[:4] != b'dex\n':
            continue
        length = struct.unpack_from('<I', header, 32)[0]
        if not 0x20000 <= length <= len(pool)-offset:
            raise EhiLabError('RECOVERED_DEX_SIZE_INVALID')
        dec = Cipher(algorithms.SM4(key), modes.ECB()).decryptor()
        prefix = dec.update(pool[offset:offset+0x20000]) + dec.finalize()
        dex = prefix + pool[offset+0x20000:offset+length]
        adler_ok = zlib.adler32(dex[12:]) & 0xffffffff == struct.unpack_from('<I', dex, 8)[0]
        if not adler_ok:
            raise EhiLabError('ORIGINAL_DEX_ADLER32_MISMATCH')
        name = f'classes{len(output)+2}.dex'
        output[name] = dex
        records.append({'file': name, 'pool_offset': offset, 'bytes': len(dex),
            'sha256': digest(dex), 'stored_adler32_matches': True,
            'stored_sha1_matches': hashlib.sha1(dex[32:]).digest() == dex[12:32],
            'header_checksums_rewritten': False})
    if len(output) != 5:
        raise EhiLabError('EXPECTED_FIVE_RECOVERED_DEX_FILES')
    return output, records


def generate(source, output_dir):
    out = Path(output_dir)
    if out.exists():
        raise EhiLabError('NEW_OUTPUT_DIRECTORY_REQUIRED')
    files = read_inputs(source)
    dex, records = recover(files)
    inner = {n.replace('.so', '-inner.so'): unpack_native(files[n])
             for n in ('libDexHelper.so', 'libdexjniehi.so')}
    report = {'input_sha256': digest(source), 'base_apk_sha256': APK_SHA256,
        'native_inputs': NATIVE_HASHES, 'native_recovered': {n: digest(b) for n, b in inner.items()},
        'dex': records, 'android_executed': False, 'apk_modified_or_built': False,
        'decompiler_completeness': 'not guaranteed; VM/native methods and decompiler errors remain'}
    out.mkdir(parents=True, mode=0o700)
    for name, raw in {**files, **inner, **dex}.items():
        private_write(out/name, raw)
    private_write(out/'RECOVERY.json', (json.dumps(report, indent=2)+'\n').encode())
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apks', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    try:
        report = generate(args.apks.read_bytes(), args.output_dir)
        print(json.dumps({'recovered_dex_files': len(report['dex']), 'android_executed': False}))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(json.dumps({'error': str(error) if isinstance(error, EhiLabError) else 'INPUT_OR_OUTPUT_ERROR'}))
        raise SystemExit(1)
