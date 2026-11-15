#!/usr/bin/env python3
"""Static inventory; detailed strings remain in private output, never Git."""
import argparse, hashlib, json, re, zipfile
from pathlib import Path
from androguard.core.apk import APK
from androguard.core.dex import DEX
from loguru import logger
logger.disable('androguard')

def inspect(path, output):
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    apk = APK(str(path))
    report = {'package': apk.get_package(), 'versionCode': apk.get_androidversion_code(),
              'icon': apk.get_app_icon(), 'files': []}
    strings = []
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            name = info.filename
            if name.startswith(('assets/', 'lib/')):
                report['files'].append({'name': name, 'bytes': info.file_size})
            if re.fullmatch(r'classes\d*\.dex', name):
                dex = DEX(z.read(name))
                strings.extend(str(s) for s in dex.get_strings())
    (output/'inventory.json').write_text(json.dumps(report,indent=2))
    (output/'strings.txt').write_text('\n'.join(strings), errors='backslashreplace')
    print(json.dumps({'package':report['package'],'icon':report['icon'],
                      'assetCount':sum(f['name'].startswith('assets/') for f in report['files']),
                      'dexStringCount':len(strings)}))

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();inspect(a.apk,a.output)
