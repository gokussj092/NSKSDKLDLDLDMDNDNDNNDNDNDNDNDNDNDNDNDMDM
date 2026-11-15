#!/usr/bin/env python3
"""Resolve build76 strings, certificate fingerprints and original launcher bitmap."""
import argparse
import hashlib
import io
import json
from pathlib import Path
from loguru import logger
from androguard.core.apk import APK
from PIL import Image

logger.remove()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('private', type=Path)
    a = p.parse_args()
    path = a.private/'unpacked/apks/com.doriaxvip.tunnel.apk'
    assert hashlib.sha256(path.read_bytes()).hexdigest()=='172da6fc4405d1cc4b70f69ce48b0f17f1b867c89a01017c991234f58ade229d'
    app = APK(str(path))
    table = app.get_android_resources()
    values = table.get_resolved_strings()[app.get_package()]['DEFAULT']
    names = {str(k):v for k,v in values.items()}
    target = a.private/'resources.json'
    target.write_text(json.dumps(names,ensure_ascii=False,indent=2)+'\n')
    target.chmod(0o600)
    configs = table.get_resolved_res_configs(0x7f0f0001)
    source = next(v for c,v in configs if c.get_density()==640 and v.endswith('.webp'))
    data = app.get_file(source)
    pixels = Image.open(io.BytesIO(data)).convert('RGBA')
    icon = a.private/'icon.png'
    pixels.save(icon)
    icon.chmod(0o600)
    assert Image.open(icon).convert('RGBA').tobytes()==pixels.tobytes()
    certs = app.get_certificates_der_v3() or app.get_certificates_der_v2()
    report = {'package':app.get_package(),'version':app.get_androidversion_name(),'versionCode':app.get_androidversion_code(),
              'launcherResource':app.get_app_icon(),'bitmapResource':source,'sourceBytes':len(data),
              'sourceSha256':hashlib.sha256(data).hexdigest(),'pngBytes':icon.stat().st_size,
              'pngSha256':hashlib.sha256(icon.read_bytes()).hexdigest(),'width':pixels.width,'height':pixels.height,
              'pixelEquality':True,'note':'Original legacy launcher WEBP decoded to lossless PNG, no redraw. Certificate fingerprints/scheme presence do not constitute full apksigner verification.',
              'v1':app.is_signed_v1(),'v2':app.is_signed_v2(),'v3':app.is_signed_v3(),
              'certificateSha1':[hashlib.sha1(c).hexdigest() for c in certs],
              'certificateSha256':[hashlib.sha256(c).hexdigest() for c in certs]}
    (a.private/'resources-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
