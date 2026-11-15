#!/usr/bin/env python3
"""Pinned static APK/source/native inventory; never loads third-party code."""
import argparse,hashlib,json,os,zipfile
from androguard.core.apk import APK
from loguru import logger
logger.disable('androguard')
from pathlib import Path
from io import BytesIO
def save(raw,path):
    if path.exists():
        if path.is_symlink() or path.read_bytes()!=raw:raise ValueError('EXISTING_OUTPUT_MISMATCH')
    else:
        with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(raw)
def inspect(folder):
    folder=Path(folder);base=folder/'base.apk'
    if hashlib.sha256(base.read_bytes()).hexdigest()!='37b2524bb63404e74abbfc52b73308180d141a2a0f32d182e9dfd63ced872826':raise ValueError('APK_MISMATCH')
    paths=['com/google/webview/Configs.java','s8q/GSDdW6o8kgK7vQX.java','s8q/qZkq7BhAGyLyNBl.java','x/h7/q.java']
    source={p:(folder/'jadx/sources'/p).read_text() for p in paths}
    assert 'servr_speigosx_sv5c' in source[paths[1]] and 'user_speigo_sv5c' in source[paths[1]]
    assert 'PURPOSE_SERVERS = 1' in source[paths[0]] and 'PURPOSE_USERS = 2' in source[paths[0]]
    files={}
    with zipfile.ZipFile(base) as z:
        for name,output in [('assets/flags/config.png','embedded-configs.bin'),('assets/flags/usr.png','embedded-ssh.bin'),('res/mipmap-xxxhdpi/ic_launcher.png','icon.png')]:
            raw=z.read(name);save(raw,folder/output);files[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    with zipfile.ZipFile(folder/'distribution.xapk') as x:
        with zipfile.ZipFile(BytesIO(x.read('config.armeabi_v7a.apk'))) as z:
            raw=z.read('lib/armeabi-v7a/libspeigoshield.so');save(raw,folder/'libspeigoshield.so');files['lib/armeabi-v7a/libspeigoshield.so']={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    app=APK(base.read_bytes(),raw=True);resources=app.get_android_resources().get_resolved_strings()[app.get_package()]['DEFAULT']
    names=json.loads((Path(__file__).resolve().parents[4]/'decoders/Python/apps/HTTP_FenixVPN/field_names.json').read_text())
    opaque=names['servers'];matched=[k for k in opaque if k in set(resources.values())]
    if len(matched)!=27:raise ValueError('FIELD_RESOURCE_CONTRACT_CHANGED')
    result={'serverFieldNamesFoundInApkResources':matched,'package':'netfree.mx.speigovpn','build':159,'splitSources':True,'purposes':{'configs':1,'ssh':2},'securityRelease':112,'signaturePublicKey':'4733a5521e426f82a124adc047e68e486579da747944cfe8d80081b3e2fc92ce','staticSourceSha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in source.items()},'files':files,'apkCodeExecuted':False}
    (folder/'recipe.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();inspect(a.private)
