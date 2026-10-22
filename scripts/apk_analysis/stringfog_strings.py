#!/usr/bin/env python3
"""Resolve confirmed StringFog Base64/XOR literal calls offline, without APK execution."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import re


def decode(value: str, key: bytes) -> str:
    if not key:
        raise ValueError('Empty XOR key')
    raw = base64.b64decode(''.join(value.split()), validate=True)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode('utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    p.add_argument('call', help='Confirmed method, e.g. L5.b.a')
    p.add_argument('output', type=Path)
    p.add_argument('--key-hex', required=True, help='Key independently recovered from the wrapper')
    a = p.parse_args()
    source, output = a.source.resolve(), a.output.resolve()
    if source == output or source in output.parents or output in source.parents:
        p.error('Source and output must be separate, without nesting')
    key = bytes.fromhex(a.key_hex)
    rx = re.compile(re.escape(a.call) + r'\(("(?:\\.|[^"\\])*")\)')
    count = files = 0
    for f in source.rglob('*.java'):
        s = f.read_text('utf-8')
        hits = list(rx.finditer(s))
        if not hits:
            continue
        s = rx.sub(lambda m: json.dumps(decode(json.loads(m[1]), key), ensure_ascii=True), s)
        target = output / f.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text(s, 'utf-8')
        target.chmod(0o600)
        count += len(hits)
        files += 1
    if not count:
        raise ValueError('No supported literal calls found')
    print(json.dumps({'resolvedCalls': count, 'sourceFiles': files}))


if __name__ == '__main__':
    main()
