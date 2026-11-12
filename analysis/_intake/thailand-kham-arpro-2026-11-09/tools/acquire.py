#!/usr/bin/env python3
"""Acquire requested public-store mirrors for static analysis; never execute APKs."""
import argparse
import hashlib
import importlib.util
import json
import zipfile
from io import BytesIO
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger

logger.disable('androguard')
ROOT = Path(__file__).resolve().parents[4]
PACKAGES = ('thailand.vpn.globalvpn', 'com.khamvpn.net', 'noob.arpro.vpn')

def acquire(package, output):
    spec = importlib.util.spec_from_file_location('acquirer', ROOT / 'analysis/com.tunneldoom.http/432/tools/acquire.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SOURCE = 'https://d.apkpure.net/b/XAPK/' + package + '?version=latest'
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    path = output / 'distribution.xapk'
    if path.is_symlink():
        raise ValueError('UNSAFE_INPUT')
    data = path.read_bytes() if path.exists() else module.fetch_xapk()
    if len(data) > module.MAX_BYTES:
        raise ValueError('OVERSIZED_INPUT')
    if not path.exists():
        module.save_private(data, path)
    with zipfile.ZipFile(BytesIO(data)) as archive:
        if package + '.apk' in archive.namelist():
            entry = archive.getinfo(package + '.apk')
            if entry.file_size > module.MAX_BYTES:
                raise ValueError('OVERSIZED_APK')
            raw = archive.read(entry)
        elif 'AndroidManifest.xml' in archive.namelist():
            raw = data
        else:
            raise ValueError('BASE_APK_MISSING')
    apk = APK(raw, raw=True)
    if apk.get_package() != package:
        raise ValueError('PACKAGE_MISMATCH')
    result = dict(package=package, versionName=apk.get_androidversion_name(),
                  versionCode=int(apk.get_androidversion_code()),
                  apkBytes=len(raw), apkSha256=hashlib.sha256(raw).hexdigest(),
                  distributionBytes=len(data), distributionSha256=hashlib.sha256(data).hexdigest(),
                  certificateSha256=sorted(c.sha256.hex() for c in apk.get_certificates()),
                  cryptographicApkSignatureVerified=False, apkCodeExecuted=False)
    base = output / 'base.apk'
    if not base.exists():
        module.save_private(raw, base)
    (output / 'identity.json').write_text(json.dumps(result, indent=2) + '\n')
    return result

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('package', choices=PACKAGES)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    print(json.dumps(acquire(args.package, args.output)))
