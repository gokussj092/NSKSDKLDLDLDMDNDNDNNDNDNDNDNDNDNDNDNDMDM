import base64, re, sys, os

KEY = b"stringfog"

def fog_dec(s):
    s = s.strip()
    try:
        raw = base64.b64decode(s)
    except Exception:
        return None
    out = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(raw))
    try:
        return out.decode('utf-8')
    except Exception:
        return out.decode('utf-8', 'replace')

if __name__ == '__main__':
    # decode all L5.b.a("...") in given files
    pat = re.compile(r'L5\.b\.a\("((?:[^"\\]|\\.)*)"\)')
    for path in sys.argv[1:]:
        with open(path, encoding='utf-8', errors='replace') as f:
            src = f.read()
        for m in pat.finditer(src):
            lit = m.group(1).replace('\\n', '\n').replace('\\"', '"')
            dec = fog_dec(lit)
            if dec is not None:
                print(f"{path}:{src[:m.start()].count(chr(10))+1}: {dec!r}")
