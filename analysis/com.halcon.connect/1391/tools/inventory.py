#!/usr/bin/env python3
"""Record sample identity and native/DEX inventory without printing constants or data."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

def record(name, data):
    return {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('xapk', type=Path)
    p.add_argument('private_output', type=Path)
    a = p.parse_args()
    report = {'input': record('halcon-1391.xapk', a.xapk.read_bytes()), 'entries': []}
    with zipfile.ZipFile(a.xapk) as z:
        if z.testzip() is not None: raise ValueError('Corrupt XAPK')
        manifest = json.loads(z.read('manifest.json'))
        report['declared_identity'] = {k: manifest[k] for k in
            ['package_name', 'name', 'version_code', 'version_name', 'min_sdk_version', 'target_sdk_version']}
        for name in z.namelist():
            if name.endswith('.apk'):
                report['entries'].append(record(name, z.read(name)))
    a.private_output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    a.private_output.touch(mode=0o600, exist_ok=True)
    a.private_output.chmod(0o600)
    a.private_output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__': main()
