#!/usr/bin/env python3
"""Pinned, bounded extraction of HTTP Custom 899's access enum in Unicorn.

This models a small JNI surface and stops after four enum constructions.
It does not execute Android or certify import, unlocking, or remote policy.
No host-native loading, networking, APK patching, real configs, or secrets.
"""

import argparse
import hashlib
import sys, struct, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/apk_analysis"))
EXPECTED_SHA256 = "62804ffbad47f599ad0bbb71eec31fad41a4ea3a8eb45cee3410742a299af220"
from arm64_function import Arm64Function
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_PC


class Probe(Arm64Function):
    STACK = 0x10000000
    TLS = 0x20000000
    HEAP = 0x30000000
    STOP = 0x40000000
    STUB = 0x50000000

    def __init__(self, library):
        from collections import deque

        self.trace = deque(maxlen=35)
        self.capture = False
        self.verify_xor = False
        self.accelerate = True
        self.static = {}
        self.objects = {}
        self.random_state = 0x1234ABCD330E
        self.events = []
        self.native_methods = []
        self.strings = []
        self.handles = {}
        self.next_handle = 0x60000000
        super().__init__(library)
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        import re

        self.fastloops = {}
        section = self.image.elf.get_section_by_name(".text")
        data = section.data()
        base = section["sh_addr"]
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        sample = struct.unpack("<I", self.image.read(0x9841A4, 4))[0] & 0xFFE0FC00
        for off in range(0, len(data) - 32, 4):
            if struct.unpack_from("<I", data, off)[0] & 0xFFE0FC00 != sample:
                continue
            seq = list(cs.disasm(data[off : off + 32], base + off))
            if len(seq) != 8 or [i.mnemonic for i in seq] != [
                "ldrb",
                "bfxil",
                "ldrb",
                "eor",
                "strb",
                "add",
                "cmp",
                "b.ne",
            ]:
                continue
            src = re.search(r"\[(x\d+), (x\d+)\]", seq[0].op_str)
            dst = re.search(r"\[(x\d+), (x\d+)\]", seq[4].op_str)
            temp = re.search(r"\[(x\d+)\]", seq[2].op_str)
            length = re.match(r"(x\d+),", seq[6].op_str)
            if src and dst and temp and length:
                self.fastloops[base + off] = [
                    int(x[1:]) for x in [src[1], src[2], dst[1], temp[1], length[1]]
                ]
        syms = self.image.elf.get_section_by_name(".dynsym")
        for r in self.image.relocations:
            if r["r_info_type"] in (1025, 257):
                sym = syms.get_symbol(r["r_info_sym"])
                target = sym["st_value"] or next(
                    (a for a, n in self.image.plt.items() if n == sym.name), 0
                )
                if not target and sym.name:
                    target = self.STUB + 0x2000 + r["r_info_sym"] * 8
                    self.image.plt[target] = sym.name
                if target:
                    self.uc.mem_write(
                        r["r_offset"], struct.pack("<Q", target + r["r_addend"])
                    )
        self.uc.mem_map(self.STUB, 0x4000)
        self.env_table = self.alloc(
            b"".join(struct.pack("<Q", self.STUB + 0x100 + 8 * i) for i in range(240))
        )
        self.env = self.alloc(struct.pack("<Q", self.env_table))
        self.vm_table = self.alloc(
            b"".join(struct.pack("<Q", self.STUB + 8 * i) for i in range(8))
        )
        self.vm = self.alloc(struct.pack("<Q", self.vm_table))

    def cstr(self, p, limit=65536):
        if not p:
            return ""
        out = bytearray()
        for i in range(limit):
            b = self.read(p + i, 1)
            if b == b"\0":
                return out.decode("utf-8", errors="replace")
            out += b
        raise ValueError("unterminated string")

    def handle(self, value):
        h = self.next_handle
        self.next_handle += 16
        self.handles[h] = value
        return h

    def ret(self, value=0):
        self.uc.reg_write(UC_ARM64_REG_X0, value & ((1 << 64) - 1))
        self.uc.reg_write(UC_ARM64_REG_PC, self.uc.reg_read(UC_ARM64_REG_X30))

    def _step(self, uc, address, size, arg):
        try:
            if self.capture:
                self.trace.append(address)
            if self.verify_xor and address == 0x9841C4:
                uc.reg_write(UC_ARM64_REG_PC, self.STOP)
                return
            if self.accelerate and address in self.fastloops:
                src, idx, dst, tmp, leng = self.fastloops[address]
                n = self.reg(leng)
                offset = self.reg(idx)
                if offset == 0 and 0 < n < 2 * 1024 * 1024:
                    key = self.read(self.reg(tmp), 8)
                    raw = self.read(self.reg(src), n)
                    plain = bytes(b ^ key[i % 8] for i, b in enumerate(raw))
                    uc.mem_write(self.reg(dst), plain)
                    uc.reg_write(UC_ARM64_REG_X0 + idx, n)
                    uc.reg_write(UC_ARM64_REG_PC, address + 32)
                    return
            if address in (0xCFB900, 0xCFB930):
                target = self.reg(1)
                old = struct.unpack("<I", self.read(target, 4))[0]
                uc.mem_write(
                    target, struct.pack("<I", old | (self.reg(0) & 0xFFFFFFFF))
                )
                self.ret(old)
                return
            if self.STUB <= address < self.STUB + 0x2000:
                if address < self.STUB + 0x100:
                    i = (address - self.STUB) // 8
                    self.events.append({"vm": i})
                    if i == 6:
                        uc.mem_write(self.reg(1), struct.pack("<Q", self.env))
                        self.ret(0)
                        return
                    raise ValueError("unmodeled vm call")
                i = (address - self.STUB - 0x100) // 8
                if i == 6:  # FindClass
                    name = self.cstr(self.reg(1))
                    self.events.append(
                        {
                            "FindClass": name,
                            "ptr": hex(self.reg(1)),
                            "lr": hex(self.uc.reg_read(UC_ARM64_REG_X30)),
                            "trace": [hex(x) for x in self.trace],
                        }
                    )
                    self.ret(self.handle(("class", name)))
                    return
                if i in (21, 25):
                    self.ret(self.reg(1))
                    return  # NewGlobal/LocalRef
                if i in (22, 23, 26):
                    self.ret()
                    return
                if i in (15, 17, 228):
                    self.ret()
                    return  # exceptions
                if i == 167:  # NewStringUTF
                    s = self.cstr(self.reg(1))
                    self.strings.append(s)
                    self.ret(self.handle(("string", s)))
                    return
                if i == 145:
                    field = self.handles.get(self.reg(2))
                    cls = self.handles.get(self.reg(1))
                    self.ret(
                        self.static.get(
                            (str(cls), field[1]), self.handle(("staticobj", field))
                        )
                    )
                    return
                if i == 171:
                    self.ret(len(self.handles[self.reg(1)][1]))
                    return
                if i == 172:
                    self.ret(self.handle(("array", [self.reg(3)] * self.reg(1))))
                    return
                if i == 173:
                    self.ret(self.handles[self.reg(1)][1][self.reg(2)])
                    return
                if i == 174:
                    self.handles[self.reg(1)][1][self.reg(2)] = self.reg(3)
                    self.ret()
                    return
                if i == 32:
                    obj = self.handles.get(self.reg(1))
                    cls = self.handles.get(self.reg(2))
                    name = cls[1] if cls else ""
                    yes = bool(obj) and (
                        name == "java/lang/Object"
                        or (obj[0] == "boxed" and name == "java/lang/Integer")
                        or (obj[0] == "string" and name == "java/lang/String")
                        or (obj[0] == "object" and obj[1][1] == name)
                    )
                    self.events.append({"instanceof": name, "obj": obj, "result": yes})
                    self.ret(int(yes))
                    return
                if i == 31:
                    self.ret(self.handle(("class", "java/lang/Object")))
                    return
                if i == 24:
                    self.ret(int(self.reg(1) == self.reg(2)))
                    return
                if i == 27:
                    self.ret(self.handle(("object", self.handles[self.reg(1)])))
                    return
                if i in (28, 30):
                    cls = self.handles[self.reg(1)]
                    method = self.handles[self.reg(2)]
                    self.events.append({"new_object": cls, "method": method})
                    self.ret(self.handle(("object", cls)))
                    return
                if i == 143:
                    method = self.handles[self.reg(2)]
                    vals = struct.unpack("<2Q", self.read(self.reg(3), 16))
                    self.events.append(
                        {
                            "static_void": method,
                            "args": [self.handles.get(v, v) for v in vals],
                        }
                    )
                    if method[1] == "fill":
                        ar = self.handles[vals[0]][1]
                        ar[:] = [vals[1]] * len(ar)
                    self.ret()
                    return
                if i == 93:
                    method = self.handles[self.reg(3)]
                    if method[2] == "(Ljava/lang/String;ILjava/lang/String;)V":
                        values = struct.unpack("<3Q", self.read(self.reg(4), 24))
                        decoded = [self.handles.get(v, v) for v in values]
                        self.events.append({"enum_constructor": decoded})
                        self.objects[self.reg(1)] = {
                            "a": values[2],
                            "ordinal": values[1],
                        }
                    self.ret()
                    return
                if i in (114, 116):
                    method = self.handles.get(self.reg(2))
                    self.events.append({"call_static": method})
                    val = (
                        self.reg(3)
                        if i == 114
                        else struct.unpack("<Q", self.read(self.reg(3), 8))[0]
                    )
                    self.ret(
                        self.handle(("boxed", val))
                        if method[1] == "valueOf"
                        else self.handle(("static_result", method))
                    )
                    return
                if i in (49, 51):
                    obj = self.handles.get(self.reg(1))
                    self.ret(obj[1] if obj and obj[0] == "boxed" else 0)
                    return
                if i == 104:
                    field = self.handles[self.reg(2)]
                    self.objects.setdefault(self.reg(1), {})[field[1]] = self.reg(3)
                    self.events.append(
                        {
                            "set_object_field": field[1],
                            "value": self.handles.get(self.reg(3), self.reg(3)),
                        }
                    )
                    self.ret()
                    return
                if i == 95:
                    method = self.handles[self.reg(2)]
                    self.ret(self.objects.get(self.reg(1), {}).get(method[1], 0))
                    return
                if i == 215:  # RegisterNatives
                    cls = self.handles.get(self.reg(1))
                    table, count = self.reg(2), self.reg(3)
                    if not 0 <= count <= 10000:
                        raise ValueError("registration count")
                    for j in range(count):
                        a, b, c = struct.unpack("<3Q", self.read(table + j * 24, 24))
                        self.native_methods.append(
                            {
                                "class": cls,
                                "name": self.cstr(a),
                                "sig": self.cstr(b),
                                "address": hex(c),
                            }
                        )
                    self.events.append({"RegisterNatives": count})
                    self.ret()
                    return
                if i in (33, 94, 113, 144):
                    name, sig = self.cstr(self.reg(2)), self.cstr(self.reg(3))
                    self.events.append(
                        {
                            "id": i,
                            "class": self.handles.get(self.reg(1)),
                            "name": name,
                            "sig": sig,
                        }
                    )
                    self.ret(self.handle(("id", name, sig)))
                    return
                self.events.append({"unmodeled_jni": i})
                raise ValueError("unmodeled jni")
            name = self.image.plt.get(address)
            if name:
                a, b, c = self.reg(0), self.reg(1), self.reg(2)
                if name in ("malloc", "calloc"):
                    n = a * b if name == "calloc" else a
                    if not 0 <= n <= 8 * 1024 * 1024:
                        raise ValueError("allocation limit")
                    self.ret(self.alloc(n))
                    return
                if name in (
                    "free",
                    "pthread_mutex_lock",
                    "pthread_mutex_unlock",
                    "pthread_once",
                    "pthread_rwlock_rdlock",
                    "pthread_rwlock_wrlock",
                    "pthread_rwlock_unlock",
                    "__cxa_atexit",
                    "__register_atfork",
                ):
                    self.ret()
                    return
                if name == "lrand48":
                    self.random_state = (self.random_state * 0x5DEECE66D + 11) & (
                        (1 << 48) - 1
                    )
                    self.ret(self.random_state >> 17)
                    return
                if name == "getauxval":
                    self.ret(0)
                    return
                if name == "__system_property_get":
                    uc.mem_write(b, b"\0")
                    self.ret(0)
                    return
                if name == "strlen":
                    self.ret(len(self.cstr(a).encode()))
                    return
                if name in ("strcmp", "strncmp", "memcmp"):
                    x, y = (
                        (self.read(a, c), self.read(b, c))
                        if name == "memcmp"
                        else (self.cstr(a).encode(), self.cstr(b).encode())
                    )
                    if name == "strncmp":
                        x, y = x[:c], y[:c]
                    self.ret((x > y) - (x < y))
                    return
                if name == "__strncpy_chk":
                    data = self.cstr(b).encode()[:c]
                    uc.mem_write(a, data + b"\0" * (c - len(data)))
                    self.ret(a)
                    return
            super()._step(uc, address, size, arg)
        except Exception as ex:
            self.error = ex
            uc.emu_stop()


def extract(library):
    if hashlib.sha256(library.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Unknown libf2c build; refusing unpinned native input")
    p = Probe(library)
    im = p.image
    # Compare the accelerator's XOR primitive against the original ARM64 loop
    # with synthetic input. Stop at the loop boundary, before any JNI call.
    data = bytes(range(256)) + b"X"
    source, target = p.alloc(data), p.alloc(len(data))
    key = 0x9142510812B2D544
    for index, value in [(8, 0), (9, len(data)), (10, source), (25, target), (26, key)]:
        p.uc.reg_write(UC_ARM64_REG_X0 + index, value)
    p.verify_xor, p.accelerate = True, False
    p.call(0x98419C, limit=10000)
    expected = bytes(v ^ struct.pack("<Q", key)[i % 8] for i, v in enumerate(data))
    if p.read(target, len(data)) != expected:
        raise ValueError("Native XOR verification failed")
    p.verify_xor, p.accelerate = False, True
    rel = {
        r["r_offset"]: r["r_addend"] for r in im.relocations if r["r_info_type"] == 1027
    }
    section = im.elf.get_section_by_name(".init_array")
    initializers = 0
    for off in range(0, section["sh_size"], 8):
        address = rel.get(
            section["sh_addr"] + off,
            struct.unpack("<Q", section.data()[off : off + 8])[0],
        )
        p.call(address, limit=100000)
        initializers += 1
    if p.call(0xC410F8, p.vm, 0, limit=2000000) != 0x10006:
        raise ValueError("Modeled JNI initialization failed")
    for ident in (2022, 1525):
        p.call(
            0x9E1D4C,
            p.env,
            p.handle(("class", "z/zuybp/gebowc/zidwuyof")),
            ident,
            limit=2000000,
        )
    name = "dev/epro/r0/K12246845678248903666"
    methods = [v for v in p.native_methods if v["class"] == ("class", name)]
    addresses = {v["name"]: int(v["address"], 16) for v in methods}
    if (
        addresses.get("rwtjywulztvb") != 0x9C4BCC
        or addresses.get("dimyragisjrn") != 0xA65E44
    ):
        raise ValueError("Native method mapping changed")
    cls, arr = p.handle(("class", name)), p.handle(("array", [0] * 9))
    instances = []
    for step in range(4):
        code = p.call(addresses["rwtjywulztvb"], p.env, cls, arr, limit=2000000)
        if code != step + 1:
            raise ValueError("Unexpected enum initializer state")
        obj = p.handles[arr][1][1]
        p.static[(str(("class", name)), ["c", "d", "e", "f"][step])] = obj
        instances.append(obj)
    constructed = [e["enum_constructor"] for e in p.events if "enum_constructor" in e]
    if len(constructed) != 4:
        raise ValueError("Incomplete enum capture")
    modes = []
    for obj, values in zip(instances, constructed):
        enum_name, ordinal, wire = values
        if enum_name[0] != "string" or wire[0] != "string":
            raise ValueError("Enum wire value is not a string")
        # Run the actual native constructor, rather than trusting the mock's
        # interpretation of the Java constructor call.
        p.objects[obj].pop("a", None)
        p.call(
            addresses["dimyragisjrn"],
            p.env,
            obj,
            p.handle(tuple(enum_name)),
            ordinal,
            p.handle(tuple(wire)),
            limit=2000000,
        )
        stored = p.handles[p.objects[obj]["a"]]
        if stored != tuple(wire):
            raise ValueError("Native constructor field does not match captured value")
        modes.append(
            dict(
                enum_name=enum_name[1],
                ordinal=ordinal,
                wire_value=wire[1],
                native_string_field="a",
                constructor_store_verified=True,
            )
        )
    return dict(
        library_sha256=EXPECTED_SHA256,
        engine="Unicorn; modeled JNI; offline",
        scope="four enum constants and constructor only; not Android import",
        native_xor_loop_verified=True,
        initializers_completed=initializers,
        enum_class=name,
        enum_initializer=hex(addresses["rwtjywulztvb"]),
        enum_constructor=hex(addresses["dimyragisjrn"]),
        modes=modes,
        original_app_import_tested=False,
        full_parser_executed=False,
        policies_or_expiry_disabled=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = extract(args.library)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(
        "Recovered 4 native enum strings; native constructor stores verified. Android import not executed."
    )


if __name__ == "__main__":
    main()
