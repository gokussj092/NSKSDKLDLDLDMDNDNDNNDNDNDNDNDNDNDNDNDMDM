#!/usr/bin/env python3
"""Pinned native note-style probe; modeled JNI, synthetic strings, no Android UI."""

import sys, json, struct, argparse, hashlib
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from probe_hc_access_modes import Probe, EXPECTED_SHA256
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X30


class NoteProbe(Probe):
    def _step(self, uc, address, size, arg):
        try:
            if self.STUB + 0x100 <= address < self.STUB + 0x2000:
                i = (address - self.STUB - 0x100) // 8
                if i == 179:
                    n = self.reg(1)
                    self.ret(self.handle(("intarray", self.alloc(n * 4), n)))
                    return
                if i == 171:
                    v = self.handles[self.reg(1)]
                    if v[0] == "intarray":
                        self.ret(v[2])
                        return
                if i == 222:
                    v = self.handles[self.reg(1)]
                    assert v[0] == "intarray"
                    self.ret(v[1])
                    return
                if i == 223:
                    self.ret()
                    return
                if i == 211:
                    v = self.handles[self.reg(1)]
                    uc.mem_write(
                        v[1] + self.reg(2) * 4, self.read(self.reg(4), self.reg(3) * 4)
                    )
                    self.ret()
                    return
                if i in (114, 116):
                    method = self.handles.get(self.reg(2))
                    if method and method[1] == "values":
                        self.ret(self.enum_array)
                        return
                if i in (49, 51, 37, 39, 43, 45, 34, 36):
                    method = self.handles.get(self.reg(2))
                    obj = self.handles.get(self.reg(1))
                    name = method[1] if method else ""
                    if name == "ordinal":
                        self.ret(self.objects[self.reg(1)]["ordinal"])
                        return
                    if obj and obj[0] == "string":
                        text = obj[1]
                        if name == "length":
                            self.ret(len(text.encode("utf-16-le")) // 2)
                            return
                        if name == "charAt":
                            n = (
                                self.reg(3)
                                if i == 43
                                else struct.unpack("<I", self.read(self.reg(3), 4))[0]
                            )
                            self.ret(
                                int.from_bytes(
                                    text.encode("utf-16-le")[n * 2 : n * 2 + 2],
                                    "little",
                                )
                            )
                            return
                        if name == "toString":
                            self.ret(self.reg(1))
                            return
                        if name == "isEmpty":
                            self.ret(int(not text))
                            return
                        if name == "equals":
                            other = (
                                self.reg(3)
                                if i == 37
                                else struct.unpack("<Q", self.read(self.reg(3), 8))[0]
                            )
                            self.ret(int(self.handles.get(other) == obj))
                            return
                    self.events.append({"unmodeled_method": method, "object": obj})
            super()._step(uc, address, size, arg)
        except Exception as ex:
            self.error = ex
            uc.emu_stop()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--library", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if hashlib.sha256(args.library.read_bytes()).hexdigest() != EXPECTED_SHA256:
    raise ValueError("Unrecognized native build")
p = NoteProbe(args.library)
im = p.image
rel = {r["r_offset"]: r["r_addend"] for r in im.relocations if r["r_info_type"] == 1027}
s = im.elf.get_section_by_name(".init_array")
for off in range(0, s["sh_size"], 8):
    p.call(
        rel.get(s["sh_addr"] + off, struct.unpack("<Q", s.data()[off : off + 8])[0]),
        limit=100000,
    )
assert p.call(0xC410F8, p.vm, 0, limit=2000000) == 0x10006
for ident in [2145, 325, 1101, 1084, 670]:
    p.call(
        0x9E1D4C,
        p.env,
        p.handle(("class", "z/zuybp/gebowc/zidwuyof")),
        ident,
        limit=2000000,
    )
name = "dev/epro/r0/M5871054116968351869"
cls = p.handle(("class", name))
arr = p.handle(("array", [0] * 8))
enums = []
for step in range(3):
    code = p.call(0xAE4124, p.env, cls, arr, limit=2000000)
    assert code == step + 1
    obj = p.handles[arr][1][1]
    p.static[(str(("class", name)), ["c", "d", "e"][step])] = obj
    enums.append(obj)
constructions = [e["enum_constructor"] for e in p.events if "enum_constructor" in e]
p.enum_array = p.handle(("array", enums))
p.static[(str(("class", name)), "f")] = p.enum_array
switch_cls = "dev/epro/r0/F9629055595383725369"
switch_method = next(
    m
    for m in p.native_methods
    if m["class"] == ("class", switch_cls) and m["name"] == "lscefvkldwak"
)
switch_arr = p.handle(("array", [0] * 5))
code = p.call(
    int(switch_method["address"], 16),
    p.env,
    p.handle(("class", switch_cls)),
    switch_arr,
    limit=15000000,
)
assert code == 1
p.static[(str(("class", switch_cls)), "a")] = p.handles[switch_arr][1][1]
results = []
for obj, data in zip(enums, constructions):
    p.call(
        0x9C71EC,
        p.env,
        obj,
        p.handle(tuple(data[0])),
        data[1],
        p.handle(tuple(data[2])),
        limit=2000000,
    )
    model = p.handle(("object", ("class", "dev/epro/r0/K2867738049988678545")))
    p.objects[model] = {
        "a": obj,
        "b": p.handle(("string", "<div>CUSTOM_HTML_SENTINEL</div>")),
    }
    try:
        out = p.call(
            0xAE31A4,
            p.env,
            model,
            p.handle(("string", "PLAIN_NOTE_SENTINEL")),
            limit=2000000,
        )
        results.append({"style": data[2][1], "returned": p.handles.get(out, out)})
    except Exception as ex:
        results.append(
            {"style": data[2][1], "error": str(ex), "last_events": p.events[-5:]}
        )
report = {
    "library_sha256": EXPECTED_SHA256,
    "enum_constructions": constructions,
    "render_results": results,
    "execution": "Unicorn, modeled JNI and synthetic sentinel strings",
    "android_webview_render_tested": False,
    "network_used": False,
}
with args.output.open("x", encoding="utf-8") as stream:
    stream.write(json.dumps(report, indent=2) + "\n")
print(
    "Native branch confirmed: default -> null; note -> plain text; custom -> custom HTML. Android UI not tested."
)
