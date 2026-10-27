#!/usr/bin/env python3
"""Bounded original Go MessagePack serializers; no Android/JNI/network execution.

Requires the owner's Dark Tunnel 1.0.26 arm64 libgojni.so. Only the pinned
binary is accepted. Synthetic values only; results contain schema and counts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/apk_analysis"))
from arm64_function import Arm64Function
from go_inspect import GoImage
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X28, UC_ARM64_REG_X30
import msgpack

LIB_SHA256 = "dc70bfc8a4c50d874ae7361e40098fedaf96dd6157a9d6370718658fd820adfb"
PREFIX = "github.com/aztecrabbit/libdarktunnel/"
TYPES = {
    "app": (0x138E2A0, PREFIX + "liblockedconfig.(*LockedAppConfig).MarshalMsg"),
    "ssh": (0x1397980, PREFIX + "libssh.(*SshConfig).MarshalMsg"),
    "inject": (0x13CD320, PREFIX + "libinject.(*InjectConfig).MarshalMsg"),
    "v2ray": (0x13A9B20, PREFIX + "libv2ray.(*V2RayConfig).MarshalMsg"),
    "export": (0x12904C0, PREFIX + "liblockedconfig.(*LockedConfigToExport).MarshalMsg"),
    "locked": (0x12D37C0, PREFIX + "liblockedconfig.(*LockedConfig).MarshalMsg"),
}


class Probe(Arm64Function):
    STACK, TLS, HEAP, STOP = 0x10000000, 0x20000000, 0x30000000, 0x40000000

    def __init__(self, path):
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != LIB_SHA256:
            raise ValueError("Unsupported native library checksum")
        super().__init__(path)
        self.go = GoImage(path)
        self.relative = {r['r_offset']: r['r_addend'] for r in self.go.relocations
                         if r['r_info_type'] == 1027}
        self.uc.reg_write(UC_ARM64_REG_X28, self.alloc(256))
        self.ranges = []
        for name, (address, size) in self.go.functions.items():
            if ((name.startswith(PREFIX) and name.endswith((".MarshalMsg", ".Msgsize")))
                    or (name.startswith("github.com/tinylib/msgp/msgp.") and
                        name.rsplit('.', 1)[-1].startswith("Append"))):
                self.ranges.append((address, address + size))
        self.memmove = self.go.functions['runtime.memmove'][0]
        self.growslice = self.go.functions['runtime.growslice'][0]

    def pointer(self, address):
        return self.relative.get(address, struct.unpack('<Q', self.go.read(address, 8))[0])

    def _name(self, address):
        flags = self.go.read(address, 1)[0]

        def string_at(pos):
            length = shift = 0
            for _ in range(5):
                byte = self.go.read(pos, 1)[0]
                pos += 1
                length |= (byte & 127) << shift
                if byte < 128:
                    return self.go.read(pos, length).decode('utf-8'), pos + length
                shift += 7
            raise ValueError('Invalid native name')

        name, pos = string_at(address + 1)
        tag = string_at(pos)[0] if flags & 2 else ''
        return name, tag

    def fields(self, type_address):
        if self.go.read(type_address + 23, 1)[0] & 31 != 25:
            raise ValueError('Expected native struct')
        count = self.pointer(type_address + 64)
        if count > 32:
            raise ValueError('Unexpected native field count')
        out = []
        for i in range(count):
            p = self.pointer(type_address + 56) + 24 * i
            name, tag = self._name(self.pointer(p))
            t = self.pointer(p + 8)
            out.append((name, tag, self.pointer(p + 16), t,
                        self.go.read(t + 23, 1)[0] & 31))
        return out

    def synthetic(self, type_address):
        """Fill native fields with reserved/sentinel values, never user data."""
        size = self.pointer(type_address)
        address = self.alloc(size)
        for name, tag, offset, field_type, kind in self.fields(type_address):
            if 'msg:"-"' in tag:
                continue
            target = address + offset
            if kind == 1:
                self.uc.mem_write(target, b'\x01')
            elif kind in (2, 6):
                self.uc.mem_write(target, struct.pack('<q', 32 if name == 'VersionCode' else 443))
            elif kind == 24:
                data = b'SENTINEL_' + name.encode('ascii')
                self.uc.mem_write(target, struct.pack('<QQ', self.alloc(data), len(data)))
            elif kind == 23:
                element_kind = self.go.read(self.pointer(field_type + 48) + 23, 1)[0] & 31
                if element_kind == 8:
                    data = b'SENTINEL_' + name.encode('ascii')
                    self.uc.mem_write(target, struct.pack('<QQQ', self.alloc(data), len(data), len(data)))
                elif element_kind == 24:
                    data = b'SYNTHETIC_HWID'
                    item = self.alloc(struct.pack('<QQ', self.alloc(data), len(data)))
                    self.uc.mem_write(target, struct.pack('<QQQ', item, 1, 1))
                else:
                    raise ValueError('Unmodeled native slice')
            elif kind == 22:
                child = self.synthetic(self.pointer(field_type + 48))
                self.uc.mem_write(target, struct.pack('<Q', child))
            else:
                raise ValueError('Unmodeled native field')
        return address

    def _step(self, uc, address, size, user):
        try:
            if address == self.memmove:
                n = self.reg(2)
                if n > 65536:
                    raise ValueError('Oversized native copy')
                if n:
                    uc.mem_write(self.reg(0), self.read(self.reg(1), n))
                uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
                return
            if not any(lo <= address < hi for lo, hi in self.ranges):
                raise ValueError('Native call outside approved serializer ranges: ' + hex(address))
            super()._step(uc, address, size, user)
        except Exception as exc:
            self.error = exc
            uc.emu_stop()

    def marshal(self, kind):
        type_address, name = TYPES[kind]
        obj = self.synthetic(type_address)
        buf = self.alloc(65536)
        self.call(self.go.functions[name][0], obj, buf, 0, 65536, limit=500000)
        if self.reg(3) or not 0 < self.reg(1) <= 65536:
            raise ValueError('Original serializer failed')
        raw = self.read(self.reg(0), self.reg(1))
        value = msgpack.unpackb(raw, raw=False)
        return raw, value


def probe(path):
    p = Probe(path)
    result = {'library_sha256': LIB_SHA256, 'execution': 'bounded_original_go_serializers',
              'synthetic_only': True, 'android_import': 'pending', 'types': {}}
    for kind, (type_address, _) in TYPES.items():
        raw, value = p.marshal(kind)
        result['types'][kind] = {
            'serialized_fields': {k: type(v).__name__ for k, v in value.items()},
            'native_fields': [{'name': n, 'tag': t, 'offset': o, 'kind': k}
                              for n, t, o, _, k in p.fields(type_address)],
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        }
    from dark_tunnel_experiment import DTConstants, APP_FIELDS, GROUP_FIELDS
    expected = {
        'app': APP_FIELDS,
        'export': {'LockedAppConfig', 'EncryptedLockedConfig'},
        'locked': {'InjectConfig', 'SshConfig', 'V2RayConfig'},
        'ssh': {'IsEncrypted', 'IsLocked', *('Encrypted'+k for k in GROUP_FIELDS['SshConfig'])},
        'inject': {'IsEncrypted', *('Encrypted'+k for k in GROUP_FIELDS['InjectConfig'])},
        'v2ray': {'IsEncrypted', 'IsInjectModeEnabled', 'EncryptedConfig'},
    }
    if any(set(result['types'][k]['serialized_fields']) != set(v) for k, v in expected.items()):
        raise ValueError('Laboratory schema differs from original serializer')
    if (p.go.read(0x336E61, 24) != DTConstants.KEY_192 or
            p.go.read(0x343455, 32) != DTConstants.KEY_256):
        raise ValueError('Laboratory AES keys differ from original code constants')
    for address in (0x1D48310, 0x1D48370, 0x1D48390, 0x1D483B0):
        if p.pointer(address + 8) != 16 or p.go.read(p.pointer(address), 16) != DTConstants.IV:
            raise ValueError('Laboratory CFB IV differs from native global')
    result['laboratory_schema_matches_original'] = True
    result['native_crypto_constants_match'] = {'keys': 2, 'iv_globals': 4}
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.library), indent=2))
