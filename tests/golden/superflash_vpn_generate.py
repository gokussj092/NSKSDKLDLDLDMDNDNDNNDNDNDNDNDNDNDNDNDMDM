"""Synthetic SV5C: original native KDF/AAD + host libsodium + JDK fields.

Pass a known SuperFlash 184.0.1 or TurboMX 143.1.26 library path. Fixture signing
seed is public test data; it is unrelated to the application's signing key.
"""
import base64
import ctypes as C
import ctypes.util
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from superflash_vpn_native_oracle import Arm64Function, LAYOUTS

HERE = Path(__file__).resolve().parent


def main():
    emu = Arm64Function(sys.argv[1])
    layout = LAYOUTS.get(hashlib.sha256(emu.image.data).hexdigest())
    if not layout: raise ValueError('Unknown native library')
    sodium = C.CDLL(ctypes.util.find_library('sodium'))
    public, secret = C.create_string_buffer(32), C.create_string_buffer(64)
    assert sodium.crypto_sign_seed_keypair(public, secret, bytes(range(32))) == 0
    sign = sodium.crypto_sign_detached
    sign.argtypes = [C.c_void_p, C.POINTER(C.c_ulonglong), C.c_char_p, C.c_ulonglong, C.c_char_p]
    encrypt = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt
    encrypt.argtypes = [C.c_void_p, C.POINTER(C.c_ulonglong), C.c_char_p, C.c_ulonglong,
                       C.c_char_p, C.c_ulonglong, C.c_void_p, C.c_char_p, C.c_char_p]

    def signed(data):
        signature, size = C.create_string_buffer(64), C.c_ulonglong()
        msg = hashlib.sha256(b'SV5C-SIG-V2\0' + data + bytes.fromhex('d2f5270a3b6c91e4')).digest()
        assert sign(signature, C.byref(size), msg, 32, secret.raw) == 0
        return data + signature.raw

    def seal(purpose, metadata, records):
        meta = json.dumps(metadata, ensure_ascii=False, separators=(',', ':')).encode()
        header = struct.pack('<4sBBHIII', b'SV5C', 2, purpose, 0, layout['release'], len(records), len(meta))
        source = emu.alloc(header);mh = emu.alloc(hashlib.sha256(meta).digest())
        key, aad = emu.alloc(32), emu.alloc(105)
        parts = [header, meta]
        for i, record in enumerate(records):
            plain = record.encode() if isinstance(record, str) else json.dumps(record, ensure_ascii=False).encode()
            nonce = bytes([i + purpose]) * 24
            emu.call(layout['kdf'], purpose, i, mh, key)
            emu.call(layout['aad'], source, mh, purpose, i, len(plain), aad)
            output, size = C.create_string_buffer(len(plain) + 16), C.c_ulonglong()
            assert encrypt(output, C.byref(size), plain, len(plain), emu.read(aad, 105), 105,
                           None, nonce, emu.read(key, 32)) == 0
            parts += [struct.pack('<II', i, len(plain)), nonce, output.raw]
        return signed(b''.join(parts))

    # Real field encryption is performed by JDK. Everything below is synthetic.
    commands = [('seal', 'Fixture server'), ('seal', 'example.invalid'), ('seal', 'fixture-user'),
                ('seal', 'fixture-password'), ('seal', 'GET /\r\nHost: example.invalid\r\n\r\n')]
    source = ''.join(k + '\t' + base64.b64encode(v.encode()).decode() + '\n' for k, v in commands)
    p = subprocess.run(['java', str(HERE / 'superflash_vpn_oracle.java')], input=source,
                       text=True, capture_output=True, check=True, timeout=30)
    name, host, user, password, payload = [base64.b64decode(v).decode() for v in p.stdout.splitlines()]
    name_key, host_key, payload_key = 'p0PgL3l0d89mnssz7ImPJA==', 'U7V8DoP4cYkXJjCnpqW6nQ==', 'PFFSWRJKZmOcNLTZxFwgjQ=='
    servers_meta = {'Version': 'synthetic-27', 'ReleaseNotes': 'Perú 日本 🧪', 'future': [None, True],
                    'Servers': [{name_key: name, 'serverType': 1, 'metadataOnly': 7}, {name_key: name, 'serverType': 1}]}
    server_record = {name_key: name, 'serverType': 1, host_key: host, payload_key: payload,
                     'unknown': {'keep': [True, None, 2.5]}, 'xhttp_http_host': 'plain.example.invalid'}
    users_meta = {'Version': 'synthetic-5', 'Usuarios': [{'Name': 'Fixture user'}]}
    user_record = {'Name': 'Fixture user', 'Username': user, 'Password': password, 'Obfs': '', 'unknown': False}
    server_bytes = seal(1, servers_meta, [server_record, {name_key: name, 'serverType': 1, host_key: ''}])
    user_bytes = seal(2, users_meta, [user_record])
    expected_servers = json.loads(json.dumps(servers_meta))
    expected_servers['Servers'] = [{**servers_meta['Servers'][0], **server_record, name_key: 'Fixture server', host_key: 'example.invalid', payload_key: commands[4][1]},
                                   {name_key: 'Fixture server', 'serverType': 1, host_key: ''}]
    expected_users = {**users_meta, 'Usuarios': [{**user_record, 'Username': 'fixture-user', 'Password': 'fixture-password'}]}
    tag = bytearray(user_bytes[:-64]);tag[-1] ^= 1
    index = bytearray(user_bytes[:-64]);struct.pack_into('<I', index, 20 + struct.unpack_from('<I', index, 16)[0], 9)
    invalid = [signed(bytes(tag)), signed(bytes(index)), signed(user_bytes[:-64] + b'extra'),
               seal(2, users_meta, ['{"Name":"Fixture user","Name":"duplicate"}']),
               seal(2, users_meta, [{**user_record, 'Password': 'invalid-cipher'}]),
               seal(2, users_meta, [{**user_record, 'Name': 'conflict'}])]
    encoded = lambda data: base64.b64encode(data).decode()
    fixture = {'source': 'Synthetic only; native ARM64 KDF/AAD, libsodium AEAD/Ed25519, JDK AES/rotation',
               'testPublicKey': public.raw.hex(), 'servers': encoded(server_bytes), 'users': encoded(user_bytes),
               'expectedServers': expected_servers, 'expectedUsers': expected_users,
               'invalid': [encoded(v) for v in invalid]}
    (HERE / layout['fixture']).write_text(json.dumps(fixture, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__': main()
