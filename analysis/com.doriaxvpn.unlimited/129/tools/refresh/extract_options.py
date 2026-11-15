#!/usr/bin/env python3
"""Rebuild public Android Firebase client options, never minted tokens, from APK129."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger

ROOT=Path(__file__).resolve().parents[5]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('private',type=Path)
    args=parser.parse_args()
    base=args.private/'unpacked/apks/com.doriaxvpn.unlimited.apk'
    assert hashlib.sha256(base.read_bytes()).hexdigest()=='d55c4ce6181ccd82b1846fac4a2c2298b6e5f6e807b07509c84cfe654b777d82'
    logger.remove();app=APK(str(base));table=app.get_android_resources()
    def value(name):return table.get_string(app.get_package(),name)[1]
    options={'api_key':value('google_api_key'),'app_id':value('google_app_id'),'project_id':value('project_id'),
             'certificate_sha1':hashlib.sha1(app.get_certificates_der_v2()[0]).hexdigest().upper()}
    for path,pattern,replacement in [
        ('decoders/Python/apps/HTTP_Conexion/firebase.py',r'^PUBLIC_OPTIONS = .*$', 'PUBLIC_OPTIONS = '+repr(options)),
        ('cloud/web/lib/http-conexion-firebase.mjs',r'^export const HTTP_CONEXION_FIREBASE_OPTIONS=.*$',
         'export const HTTP_CONEXION_FIREBASE_OPTIONS=Object.freeze('+json.dumps(options,separators=(',',':'))+');')]:
        file=ROOT/path;s=file.read_text();s,count=re.subn(pattern,lambda _:replacement,s,flags=re.M);assert count==1;file.write_text(s)
    target=args.private/'firebase-options.json';target.write_text(json.dumps(options));target.chmod(0o600)
    report={'base_sha256':hashlib.sha256(base.read_bytes()).hexdigest(),'package':app.get_package(),
            'version':app.get_androidversion_name(),'build':app.get_androidversion_code(),
            'public_options_sha256':hashlib.sha256(json.dumps(options,sort_keys=True).encode()).hexdigest(),
            'certificate_sha1':options['certificate_sha1'],'note':'Public Android client options, not an Admin/service-account key. No generated FIS credentials in code.'}
    (args.private/'options-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


if __name__=='__main__':main()
