#!/usr/bin/env python3
"""Inventory certificate DER from the pinned APK; do not claim Play equivalence."""
import argparse,hashlib,json
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('apk',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    assert hashlib.sha256(a.apk.read_bytes()).hexdigest()=='995d5d9d70e0f929bd92e29125bf1c9ab87f6f8a3d064b6657c6d230d8e8b31a'
    logger.remove();app=APK(str(a.apk))
    certs=app.get_certificates_der_v2() if app.is_signed_v2() else app.get_certificates_der_v3() if app.is_signed_v3() else []
    report={'signed_v1':app.is_signed_v1(),'signed_v2':app.is_signed_v2(),'signed_v3':app.is_signed_v3(),
      'certificate_sha256':[hashlib.sha256(c).hexdigest() for c in certs],
      'certificate_sha1':[hashlib.sha1(c).hexdigest() for c in certs],
      'scope':'Signature block presence and certificate fingerprint, not full signature verification or official Play signing equivalence.'}
    a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
