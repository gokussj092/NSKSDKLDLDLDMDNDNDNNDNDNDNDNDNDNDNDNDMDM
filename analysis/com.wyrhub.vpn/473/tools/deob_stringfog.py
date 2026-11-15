#!/usr/bin/env python3
"""Decrypt all StringFog.decrypt(new byte[]{...}, new byte[]{...}) calls in jadx output."""
import re, sys, glob

PAT = re.compile(r'StringFog\.decrypt\(new byte\[\]\{(.*?)\},\s*new byte\[\]\{(.*?)\}\)', re.S)

def parse_arr(s):
    vals = []
    for tok in s.replace('\n', ' ').split(','):
        tok = tok.strip()
        if not tok: continue
        vals.append(int(tok) & 0xFF)
    return bytes(vals)

def dec(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

out = {}
for path in sys.argv[1:]:
    txt = open(path, encoding='utf-8', errors='replace').read()
    for m in PAT.finditer(txt):
        try:
            data, key = parse_arr(m.group(1)), parse_arr(m.group(2))
            s = dec(data, key).decode('utf-8')
        except Exception as e:
            s = f'<ERR {e}>'
        out.setdefault(s, []).append(path)
for s in sorted(out):
    print(f"{s!r}   [{len(out[s])}x] {out[s][0]}")
