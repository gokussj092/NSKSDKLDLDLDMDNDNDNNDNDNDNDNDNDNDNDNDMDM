#!/usr/bin/env python3
"""Desofusca las cadenas StringFog (q3.g.a) del jadx de RH Tunnel Lite.

g.a(data_b64, key_b64) = XOR(Base64.decode(data), Base64.decode(key))
repetido, UTF-8. Recorre todos los .java y vuelca file:linea -> texto.
"""
import base64
import re
import sys
from pathlib import Path


def java_unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "n":
                out.append("\n")
            elif n == "t":
                out.append("\t")
            elif n == "r":
                out.append("\r")
            elif n == "\\":
                out.append("\\")
            elif n == '"':
                out.append('"')
            elif n == "'":
                out.append("'")
            elif n == "u" and i + 5 < len(s):
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 4
            else:
                out.append(n)
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def fog(data_b64, key_b64):
    data = base64.b64decode(data_b64)
    key = base64.b64decode(key_b64)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


PAT = re.compile(r'(?:q3\.)?g\.a\("((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\)')

def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("jadx-out/sources")
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("work/deofuscado.txt")
    n = 0
    lines = []
    for jf in sorted(root.rglob("*.java")):
        text = jf.read_text(errors="replace")
        for m in PAT.finditer(text):
            try:
                pt = fog(java_unescape(m.group(1)), java_unescape(m.group(2)))
                s = pt.decode("utf-8", "replace")
            except Exception as e:
                s = f"<ERR {e}>"
            lineno = text.count("\n", 0, m.start()) + 1
            lines.append(f"{jf.relative_to(root)}:{lineno}: {s!r}")
            n += 1
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"{n} cadenas desofuscadas -> {out}")


if __name__ == "__main__":
    main()
