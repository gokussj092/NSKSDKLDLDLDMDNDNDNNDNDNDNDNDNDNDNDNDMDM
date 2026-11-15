#!/usr/bin/env python3
"""Deobfuscate Lr64;->e([B [B) XOR strings in HTTP Tweak DEX files.

r64.e(data, key): out[i] = data[i] ^ key[i % len(key)], UTF-8.
Every obfuscated string in the app is built as two inline byte arrays
(fill-array-data and/or aput-byte) and decoded through r64.e.

This script does a small Dalvik abstract interpretation per method:
tracks registers holding byte[] literals and int constants, resolves
fill-array-data payloads, and decodes every r64.e call whose two
arguments are known byte arrays. Also records plain const-string values
for context.
"""
import ast
import sys
import logging
logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX

TARGET = 'Lr64;->e([B [B)Ljava/lang/String;'


def regnum(op):
    # operand tuple: (Operand.REGISTER, n) etc.
    return op[1]


def interpret(method, dex_path):
    code = method.get_code()
    if code is None:
        return []
    bc = code.get_bc()
    insns = list(bc.get_instructions())
    # address map: instruction index -> byte offset (in 16-bit units)
    addr = []
    off = 0
    for ins in insns:
        addr.append(off)
        off += ins.get_length()
    # payload map: byte address -> bytes (offsets are in 16-bit code units)
    payloads = {}
    for idx, ins in enumerate(insns):
        if ins.get_name() == 'fill-array-data-payload':
            raw = ins.get_operands()[0][1]
            if isinstance(raw, str):
                try:
                    raw = ast.literal_eval(raw)
                except Exception:
                    raw = raw.encode('latin1')
            payloads[addr[idx]] = bytes(raw)

    regs = {}  # reg -> ('bytes', bytearray) | ('int', int) | ('str', str)
    results = []  # (decoded_str, insn_index)

    def get_int(r):
        v = regs.get(r)
        if v and v[0] == 'int':
            return v[1]
        return None

    for idx, ins in enumerate(insns):
        name = ins.get_name()
        ops = ins.get_operands()
        try:
            if name in ('const/4', 'const/16', 'const'):
                regs[regnum(ops[0])] = ('int', ops[1][1])
            elif name == 'const-string':
                regs[regnum(ops[0])] = ('str', ops[1][2])
            elif name == 'const-string/jumbo':
                regs[regnum(ops[0])] = ('str', ops[1][2])
            elif name in ('move', 'move-object', 'move/16', 'move-object/16'):
                regs[regnum(ops[0])] = regs.get(regnum(ops[1]))
            elif name == 'new-array':
                size = get_int(regnum(ops[1]))
                if size is not None and 0 <= size <= 4096:
                    regs[regnum(ops[0])] = ('bytes', bytearray(size))
                else:
                    regs[regnum(ops[0])] = None
            elif name == 'aput-byte':
                arr = regs.get(regnum(ops[1]))
                val = get_int(regnum(ops[0]))
                ix = get_int(regnum(ops[2]))
                if arr and arr[0] == 'bytes' and val is not None and ix is not None:
                    if 0 <= ix < len(arr[1]):
                        arr[1][ix] = val & 0xFF
            elif name == 'fill-array-data':
                tgt = regnum(ops[0])
                rel = ops[1][1]
                paddr = (addr[idx] // 2 + rel) * 2
                data = payloads.get(paddr)
                if data is not None:
                    regs[tgt] = ('bytes', bytearray(data))
                else:
                    regs[tgt] = None
            elif name in ('move-result', 'move-result-object', 'move-result-wide'):
                regs[regnum(ops[0])] = None
            elif name.startswith('invoke-'):
                # find method ref operand (string is the 3rd tuple element)
                ref = None
                for o in ops:
                    for el in o:
                        if isinstance(el, str) and '->' in el:
                            ref = el
                            break
                    if ref:
                        break
                if ref and ref.endswith('Lr64;->e([B [B)Ljava/lang/String;'):
                    argregs = [regnum(o) for o in ops[:-1]]
                    if len(argregs) >= 2:
                        a = regs.get(argregs[0])
                        b = regs.get(argregs[1])
                        if a and a[0] == 'bytes' and b and b[0] == 'bytes' and len(b[1]) > 0:
                            dec = bytes(x ^ b[1][i % len(b[1])] for i, x in enumerate(a[1]))
                            try:
                                s = dec.decode('utf-8')
                            except UnicodeDecodeError:
                                s = repr(dec)
                            results.append((s, idx))
                            # result register is the first operand of the following
                            # move-result-object; mark unknown for now
                # any invoke clobbers nothing else we track (conservative: keep)
        except Exception:
            continue
    return results


def main():
    out = {}
    for path in sys.argv[1:]:
        d = DEX(open(path, 'rb').read())
        for c in d.get_classes():
            for m in c.get_methods():
                res = interpret(m, path)
                for s, _ in res:
                    out.setdefault(s, []).append(
                        f"{c.get_name()}->{m.get_name()}")
    for s in sorted(out):
        print(f"{s!r}   [{len(out[s])}x] {out[s][0]}")


if __name__ == '__main__':
    main()
