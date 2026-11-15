#!/usr/bin/env python3
"""Extract the exact catalog raw resource referenced by build 118 df1.p()."""
import argparse,hashlib,json,zipfile
from pathlib import Path
from androguard.core.apk import APK
from loguru import logger

BASE_SHA='d2ddad1a78d99f24ba674a2aefe1e1a1ab0a61641725a953defe342e84e1d141'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args();logger.remove()
    base=a.private/'unpacked/apks/pro.xxpicore.tunnel.apk'
    assert hashlib.sha256(base.read_bytes()).hexdigest()==BASE_SHA
    app=APK(str(base));r=app.get_android_resources()
    values=r.get_resolved_res_configs(2131755011)
    names=sorted({value for _,value in values})
    assert len(names)==1 and names[0].startswith('res/')
    with zipfile.ZipFile(base) as z:data=z.read(names[0])
    f=a.private/'included.bin';f.touch(mode=0o600,exist_ok=True);f.chmod(0o600);f.write_bytes(data)
    report={'resource_id':hex(2131755011),'path':names[0],'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    (a.private/'resource-summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
