#!/usr/bin/env python3
"""Extract Lvq; string table from classes3.dex <clinit> and decode all
Lvq;->a(J) call-site constants across all dex files (LSParanoid-style
string obfuscation used by the RENZ family).

Implements t0.L and vq.a exactly as disassembled (Dalvik semantics).
"""
import glob
import json
import re
import sys

from loguru import logger
logger.remove()
from androguard.core.dex import DEX

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def rotl32(x, n):
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def t0_L(x):
    """Lt0;->L(J)J reimplementation (Dalvik 64-bit two's complement)."""
    x &= MASK64
    a = s16(x & 0xFFFF)
    b = s16((x >> 16) & 0xFFFF)
    s = s16(a + b)
    s = s16(rotl32(s, 9))
    s = s16(s + a)
    t = s16(b ^ a)
    u = s16(rotl32(a, 13))
    u = s16(u ^ t)
    u = s16(u ^ ((t << 5) & MASK32))
    w = s16(rotl32(t, 10))
    # sign-extend shorts to 64-bit
    s_se = s & 0xFFFF if s >= 0 else (0xFFFFFFFFFFFF0000 | (s & 0xFFFF))
    w_se = w & 0xFFFF if w >= 0 else (0xFFFFFFFFFFFF0000 | (w & 0xFFFF))
    u_se = u & 0xFFFF if u >= 0 else (0xFFFFFFFFFFFF0000 | (u & 0xFFFF))
    v = ((w_se | ((s_se << 16) & MASK64)) << 16) & MASK64
    v = (v | u_se) & MASK64
    return v


def tdiv(a, b):
    """Java int division (truncates toward zero)."""
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


def tmod(a, b):
    return a - tdiv(a, b) * b


def vq_a(j, table):
    j &= MASK64
    j2 = j & 0xFFFFFFFF
    j3 = (j2 ^ (j2 >> 33)) & MASK64
    j3 = (j3 * 7109453100751455733) & MASK64
    j3 = (j3 ^ (j3 >> 28)) & MASK64
    j3 = (j3 * (MASK64 - 3808689974395783757 + 1)) & MASK64  # -3808689974395783757 mod 2^64
    jL = t0_L((j3 >> 32) & MASK64)
    j4 = (jL >> 32) & 0xFFFF
    jL2 = t0_L(jL)
    i = (((j >> 32) ^ j4 ^ ((jL2 >> 16) & 0xFFFF0000)) & MASK64)
    i = i if i < (1 << 63) else i - (1 << 64)  # to signed long
    i = i & MASK32
    i = i if i < (1 << 31) else i - (1 << 32)  # (int)j
    jL3 = t0_L(jL2) ^ ((ord(table[tdiv(i, 8191)][tmod(i, 8191)]) << 32) & MASK64)
    jL3 &= MASK64
    length = (jL3 >> 32) & 0xFFFF
    out = []
    for k in range(length):
        i4 = i + k + 1
        jL3 = t0_L(jL3) ^ ((ord(table[tdiv(i4, 8191)][tmod(i4, 8191)]) << 32) & MASK64)
        jL3 &= MASK64
        out.append(chr((jL3 >> 32) & 0xFFFF))
    return ''.join(out)


def get_string_table(dex):
    """Lvq; static field 'a' initialised in <clinit> with 5 const-strings."""
    for c in dex.get_classes():
        if c.get_name() == 'Lvq;':
            for m in c.get_methods():
                if m.get_name() == '<clinit>':
                    code = m.get_code()
                    table = []
                    for ins in code.get_bc().get_instructions():
                        if ins.get_name() == 'const-string':
                            out = ins.get_output()
                            # output like: v2, "...."
                            mm = re.search(r', "(.*)"$', out, re.S)
                            if mm:
                                table.append(mm.group(1))
                    return table
    return None


def main():
    dexes = {}
    table = None
    for f in sorted(glob.glob('/home/hatch/workspace/catalogs/chn/apk/base/classes*.dex')):
        d = DEX(open(f, 'rb').read())
        dexes[f] = d
        if table is None:
            table = get_string_table(d)
    print('string table entries:', len(table) if table else None,
          'lengths:', [len(s) for s in table] if table else None, file=sys.stderr)
    assert table and len(table) == 5

    # sanity: decode a known constant from al1.java static init
    # vq.a(-155550575342682L) is used in <clinit> of al1; just test decoder runs
    test = vq_a(-155550575342682 & MASK64, table)
    print('TEST decode -155550575342682 ->', repr(test), file=sys.stderr)

    # scan all methods for invoke-static Lvq;->a(J) with preceding const-wide
    results = []
    const_re = re.compile(r'^(v\d+),\s+(-?\d+)$')
    for f, d in dexes.items():
        for c in d.get_classes():
            cname = c.get_name()
            for m in c.get_methods():
                code = m.get_code()
                if code is None:
                    continue
                insns = list(code.get_bc().get_instructions())
                # track last const-wide value per register
                last_const = {}
                for idx, ins in enumerate(insns):
                    name = ins.get_name()
                    out = ins.get_output()
                    cm = const_re.match(out.strip()) if name.startswith('const-wide') else None
                    if cm:
                        kind, reg, val = name, cm.group(1), int(cm.group(2))
                        if kind == 'const-wide/16':
                            v = val & 0xFFFF
                            v = v - 0x10000 if v & 0x8000 else v
                        elif kind == 'const-wide/32':
                            v = val & MASK32
                            v = v - (1 << 32) if v & 0x80000000 else v
                        elif kind == 'const-wide/high16':
                            v = (val & 0xFFFF) << 48
                            v = v - (1 << 64) if v & (1 << 63) else v
                        else:
                            v = val
                        last_const[reg] = v & MASK64
                        continue
                    if name == 'invoke-static':
                        if 'Lvq;->a(J)Ljava/lang/String;' in out:
                            mm = re.search(r'^(v\d+),', out)
                            if mm and mm.group(1) in last_const:
                                const = last_const[mm.group(1)]
                                try:
                                    dec = vq_a(const, table)
                                except Exception as e:
                                    dec = f'<DECODE ERROR {e}>'
                                results.append({
                                    'dex': f.split('/')[-1],
                                    'class': cname,
                                    'method': m.get_name(),
                                    'const': const if const < (1 << 63) else const - (1 << 64),
                                    'decoded': dec,
                                })
    with open('/home/hatch/workspace/catalogs/chn/work/decoded_strings.json', 'w', encoding='utf-8', errors='surrogatepass') as fh:
        json.dump(results, fh, ensure_ascii=False, indent=1)
    print('total call sites:', len(results), file=sys.stderr)


if __name__ == '__main__':
    main()
