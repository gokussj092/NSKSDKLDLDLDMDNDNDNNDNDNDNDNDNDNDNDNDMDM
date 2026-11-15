#!/usr/bin/env python3
"""Static identity/resources/source inventory for two exact public samples."""
import argparse,hashlib,json,zipfile
from pathlib import Path
from io import BytesIO
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
PROFILES={
 'open':{'package':'com.opentunnel.app','build':61,'sha':'b4351ea4b967da946066a27b45a369a657842b36bedaa32562be37ff3cb74d36','icon':'res/mipmap-xxxhdpi-v4/ic_launcher.png','sources':['defpackage/pf.java','defpackage/wd1.java','defpackage/k30.java','defpackage/ji.java','defpackage/ba0.java','com/opentunnel/app/activities/ConfigExportFileActivity.java']},
 'mdproxy':{'package':'com.vpnproxymd.mdproxyvpn','build':29,'sha':'69b73ec144a2e25afa7ed0e57ec1d7690ba2901cd0c9a27a1478494de06dede5','icon':'res/mipmap-xxxhdpi-v4/ic_launcher.webp','sources':['com/v2ray/ang/Hometab.java','com/v2ray/ang/ui/HomeFragment.java','com/v2ray/ang/viewmodel/ConfigData.java','com/v2ray/ang/viewmodel/ServerList.java','com/v2ray/ang/viewmodel/NetworkList.java','com/v2ray/ang/util/ConfigUpdate$configUpdate$1.java','go/Seq.java']}}
def inspect(kind,folder):
    folder=Path(folder);profile=PROFILES[kind];raw=(folder/'base.apk').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=profile['sha']:raise ValueError('BASE_MISMATCH')
    app=APK(raw,raw=True)
    if app.get_package()!=profile['package'] or int(app.get_androidversion_code())!=profile['build']:raise ValueError('PACKAGE_BUILD_MISMATCH')
    with zipfile.ZipFile(BytesIO(raw)) as z:
        icon=profile['icon']
        if icon is None:
            candidates=[n for n in z.namelist() if ('ic_launcher' in n or 'app_icon' in n) and n.endswith(('.png','.webp'))]
            if not candidates:raise ValueError('RASTER_ICON_NOT_FOUND')
            print(json.dumps({'iconCandidates':candidates}));icon=candidates[0]
        data=z.read(icon);(folder/('icon'+Path(icon).suffix)).write_bytes(data)
    sources={name:hashlib.sha256((folder/'jadx/sources'/name).read_bytes()).hexdigest() for name in profile['sources']}
    result={'package':app.get_package(),'versionName':app.get_androidversion_name(),'versionCode':int(app.get_androidversion_code()),'apkBytes':len(raw),'apkSha256':profile['sha'],'certificateSha256':sorted(c.sha256.hex() for c in app.get_certificates()),'icon':{'source':icon,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()},'sourceSha256':sources,'apkCodeExecuted':False,'cryptographicApkSignatureVerified':False}
    (folder/'inspection.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('kind',choices=PROFILES);p.add_argument('private',type=Path);a=p.parse_args();inspect(a.kind,a.private)
