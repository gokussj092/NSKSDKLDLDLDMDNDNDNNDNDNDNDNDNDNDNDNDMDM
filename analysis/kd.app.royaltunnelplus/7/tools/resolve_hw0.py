"""Resolve ALL defpackage/AbstractC0415Hw0.p(J) obfuscated strings in Royal Tunnel VPN
(kd.app.royaltunnelplus). Adapted from the TCx resolver (same pattern).
Usage: resolve_hw0.py <Hw0.java> <apk> <out.txt>
"""
import sys, zipfile, re
sys.path.insert(0, '/home/hatch/workspace/http-custom-update/venv/lib/python3.12/site-packages')
from paranoid_deobfuscator.paranoid import deobfuscate_string

JAVA_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f',
                '"': '"', "'": "'", '\\': '\\', '/': '/'}

def java_unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            if n == 'u' and i + 5 < len(s) + 1:
                try:
                    out.append(chr(int(s[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            if n in JAVA_ESCAPES:
                out.append(JAVA_ESCAPES[n])
                i += 2
                continue
            out.append(n)
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)

def parse_chunks(java_path):
    src = open(java_path, encoding='utf-8', errors='surrogateescape').read()
    m = re.search(r'String\[\] b = \{(.*?)\};', src, re.S)
    if not m:
        raise SystemExit('chunk array not found in ' + java_path)
    body = m.group(1)
    lits = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
    chunks = [java_unescape(l) for l in lits]
    return chunks

hw0_java, apk_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
chunks = parse_chunks(hw0_java)
print(f'chunks={len(chunks)} total_chars={sum(len(c) for c in chunks)}', file=sys.stderr)

from androguard.core.dex import DEX
z = zipfile.ZipFile(apk_path)
out = open(out_path, 'w', encoding='utf-8', errors='surrogatepass')
total = ok = 0
for dexname in [n for n in z.namelist() if n.endswith('.dex')]:
    d = DEX(z.read(dexname))
    for cls in d.get_classes():
        cname = cls.get_name()
        for m in cls.get_methods():
            code = m.get_code()
            if code is None:
                continue
            pending = None
            for ins in code.get_bc().get_instructions():
                op = ins.get_name()
                o = ins.get_output()
                if op == 'const-wide':
                    try:
                        reg, val = o.split(',', 1)
                        pending = (reg.strip(), int(val.strip()))
                    except ValueError:
                        pending = None
                elif op == 'invoke-static' and 'LHw0;->p(J)' in o:
                    if pending is not None:
                        total += 1
                        try:
                            s = deobfuscate_string(pending[1], chunks, True)
                            ok += 1
                        except Exception as e:
                            s = f'<ERR {type(e).__name__}: {e}>'
                        out.write(f'{cname} | {m.get_name()}{m.get_descriptor()} | {pending[1]} | {s}\n')
                    pending = None
                elif op.startswith('const') or op.startswith('move'):
                    pass
                else:
                    if op not in ('move-result-object', 'move-object', 'move-result'):
                        pending = None
out.close()
print(f'resolved {ok}/{total}', file=sys.stderr)
