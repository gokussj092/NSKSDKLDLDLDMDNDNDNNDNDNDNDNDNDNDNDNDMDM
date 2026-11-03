#!/usr/bin/env python3
"""Fixed public acquisition recipe used for build1391. No authentication.

Stores downloaded HTML/APK privately; nothing from these downloads is copied to
Git automatically. --apk explicitly downloads the pinned public mirror sample.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

SOURCES = {
    'play.html': 'https://play.google.com/store/apps/details?id=com.halcon.connect&hl=en&gl=US',
    'apkpure.html': 'https://apkpure.com/halcon-connect/com.halcon.connect',
    'download.html': 'https://apkpure.com/halcon-ramos-conectividad/com.halcon.connect/download',
}
APK_URL = 'https://d.apkpure.com/b/XAPK/com.halcon.connect?versionCode=1391&nc=arm64-v8a&sv=24'
APK_SHA256 = 'f90ef42a4c610afd35eb5ea496cccfc3fb3ded473cf8949d8a1056a51b879077'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('private_output', type=Path)
    p.add_argument('--apk', action='store_true')
    p.add_argument('--verify-existing', action='store_true', help='Inventory earlier downloads without network')
    a = p.parse_args()
    a.private_output.mkdir(parents=True, exist_ok=True, mode=0o700)
    sources = dict(SOURCES)
    if a.apk: sources['halcon-1391.xapk'] = APK_URL
    report = []
    for name, url in sources.items():
        out = a.private_output / name
        if out.exists() and not a.verify_existing:
            raise ValueError('Use an empty private destination')
        if a.verify_existing:
            exit_code = 0
        else:
            out.touch(mode=0o600)
            result = subprocess.run(['curl', '--silent', '--show-error', '--location', '--fail',
                                     '--max-time', '120', '--max-filesize', '60000000', url,
                                     '--output', str(out)], check=False)
            exit_code = result.returncode
        data = out.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        report.append({'file': name, 'exit': exit_code, 'bytes': len(data), 'sha256': digest,
                       'mode': 'existing_local_inventory' if a.verify_existing else 'download'})
        if exit_code: break
        if name.endswith('.xapk'):
            if digest != APK_SHA256: raise ValueError('Mirror sample changed; do not reuse offsets')
            with zipfile.ZipFile(out) as z:
                if z.testzip() is not None: raise ValueError('Corrupt archive')
    print(json.dumps(report, indent=2))
    return 0 if all(x['exit'] == 0 for x in report) else 1

if __name__ == '__main__': raise SystemExit(main())
