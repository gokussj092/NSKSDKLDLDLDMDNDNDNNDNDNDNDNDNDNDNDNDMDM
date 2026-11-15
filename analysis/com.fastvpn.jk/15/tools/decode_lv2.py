#!/usr/bin/env python3
"""Reimplementacion en Python del decodificador de strings ofuscados de JK VPN.

lv2.m(long) en defpackage/lv2.java + pi.k(long) en defpackage/pi.java.
Semantica Java (long 64 bits con signo, int 32 bits, short 16 bits) emulada
con mascaras explicitas.
"""
import re, sys, json

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
MASK16 = 0xFFFF

def s64(x):
    x &= MASK64
    return x - (1 << 64) if x >= (1 << 63) else x

def s32(x):
    x &= MASK32
    return x - (1 << 32) if x >= (1 << 31) else x

def u16(x):
    return x & MASK16

def s16(x):
    x &= MASK16
    return x - 0x10000 if x >= 0x8000 else x

def pi_k(j):
    """pi.k(long): OJO — el bytecode usa shl-long (64 bits), no int.
    Devuelve un long de 64 bits con signo. jadx lo descompilo mal como int."""
    s = s16(j & MASK16)
    s2 = s16((j >> 16) & MASK16)
    s3 = s16(s + s2)
    s4 = s16(s2 ^ s)
    # B = (short)((s3 >>> 23) | (s3 << 9)); C = (short)(B + s)
    b16 = s16(((0x1FF if s3 < 0 else 0) | ((s3 << 9) & MASK32)))
    c = s16(b16 + s)
    # E = (short)((s << 13) | (s >>> 19)); D = (short)(((short)(E ^ s4)) ^ (s4 << 5))
    e = s16(((0x1FFF if s < 0 else 0) | ((s << 13) & MASK32)))
    d = s16(s16(e ^ s4) ^ ((s4 << 5) & MASK32))
    # A = (short)((s4 >>> 22) | (s4 << 10))
    a = s16(((0x3FF if s4 < 0 else 0) | ((s4 << 10) & MASK32)))
    # return (((A | (C << 16)) << 16) | D)  — todo en long de 64 bits
    x = (s64(a) | ((s64(c) << 16) & MASK64)) & MASK64
    x = (x << 16) & MASK64
    return s64(x | (s64(d) & MASK64))

# ---------------- tabla b ----------------
def parse_java_string_literal(src, i):
    """src[i] == '"'. Devuelve (texto_decodificado, indice_despues_de_cierre)."""
    assert src[i] == '"'
    i += 1
    out = []
    while i < len(src):
        ch = src[i]
        if ch == '"':
            return ''.join(out), i + 1
        if ch == '\\':
            esc = src[i + 1]
            if esc == 'u':
                # \uXXXX (puede haber varias 'u')
                j = i + 2
                while src[j] == 'u':
                    j += 1
                out.append(chr(int(src[j:j + 4], 16)))
                i = j + 4
            elif esc == 'n':
                out.append('\n'); i += 2
            elif esc == 't':
                out.append('\t'); i += 2
            elif esc == 'r':
                out.append('\r'); i += 2
            elif esc == 'b':
                out.append('\b'); i += 2
            elif esc == 'f':
                out.append('\f'); i += 2
            elif esc == '\\':
                out.append('\\'); i += 2
            elif esc == '"':
                out.append('"'); i += 2
            elif esc == "'":
                out.append("'"); i += 2
            elif esc == '/':
                out.append('/'); i += 2
            else:
                raise ValueError('escape desconocido \\%s en %d' % (esc, i))
        else:
            out.append(ch)
            i += 1
    raise ValueError('literal sin cerrar')

def load_table(path):
    with open(path, encoding='utf-8', errors='surrogatepass') as f:
        src = f.read()
    m = re.search(r'public static final String\[\] b = \{', src)
    start = src.index('{', m.start())
    # el inicializador termina en '};' a nivel 0
    depth = 0
    i = start
    strings = []
    while i < len(src):
        ch = src[i]
        if ch == '"':
            s, i = parse_java_string_literal(src, i)
            strings.append(s)
        elif ch == '{':
            depth += 1
            i += 1
        elif ch == '}':
            depth -= 1
            i += 1
            if depth == 0:
                break
        else:
            i += 1
    return strings

TABLE = None

def lv2_m(j):
    """lv2.m(long j) -> str decodificado."""
    j = s64(j)
    j2 = j & 0xFFFFFFFF
    j3 = s64((j2 ^ (j2 >> 33)) * 7109453100751455733)
    arg = s64((s64(j3 ^ ((j3 & MASK64) >> 28)) * -3808689974395783757) >> 32)
    # pi.k recibe el long; solo importan sus 32 bits bajos
    jK = pi_k(arg)
    j4 = (jK >> 32) & MASK16 if jK < 0 else 0
    # en Java: (jK >>> 32) & 65535 ; jK es long con extension de signo
    jK_u = jK & MASK64
    j4 = (jK_u >> 32) & MASK16
    jK2 = pi_k(jK)
    # i = (int)(((j >>> 32) ^ j4) ^ ((jK2 >>> 16) & (-65536)))
    jK2_u = jK2 & MASK64
    i = s32(((j & MASK64) >> 32) ^ j4 ^ ((jK2_u >> 16) & (MASK64 ^ 0xFFFF)))
    jK3 = pi_k(jK2)
    flat = TABLE
    total = sum(len(s) for s in flat)
    def char_at(idx):
        # indice virtual sobre la concatenacion en bloques de 8191
        return ord(flat[idx // 8191][idx % 8191])
    jCharAt = s64(jK3 ^ (char_at(i) << 32))
    i2 = ((jCharAt & MASK64) >> 32) & MASK16
    out = []
    for i3 in range(i2):
        i4 = i + i3 + 1
        jCharAt = s64(pi_k(jCharAt) ^ (char_at(i4) << 32))
        out.append(chr(((jCharAt & MASK64) >> 32) & MASK16))
    return ''.join(out)

if __name__ == '__main__':
    TABLE = load_table('/home/hatch/workspace/catalogs/jkvpn/jadx-out/sources/defpackage/lv2.java')
    print('tabla b: %d strings, %d chars totales' % (len(TABLE), sum(len(s) for s in TABLE)), file=sys.stderr)
    for arg in sys.argv[1:]:
        print('%s -> %r' % (arg, lv2_m(int(arg))))
