#!/usr/bin/env python3
"""Resolve resource identity, field names, KEY_CONFIG and certificate fingerprints."""
import argparse,hashlib,json,re,zipfile
from pathlib import Path
from loguru import logger
logger.remove()
from androguard.core.apk import APK
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();d=a.private
    apk=d/'unpacked/apks/netfree.mx.anuncios.apk';app=APK(str(apk));table=app.get_android_resources()
    s=(d/'jadx2/sources/t5p215r1/zsjgznfgm3gxduyfq.java').read_text();rid=int(re.search(r'zhxk3yses = (\d+)',s)[1]);paths={v for _,v in table.get_resolved_res_configs(rid)};assert paths=={'res/raw/pdnsd_config'}
    with zipfile.ZipFile(apk) as z:raw=z.read(next(iter(paths)))
    key=re.search(r'^KEY_CONFIG=(.*)$',raw.decode(),re.M)[1];recipe=json.loads((d/'recipe.json').read_text());recipe['fieldPassword']=key
    target=d/'recipe.json';target.write_text(json.dumps(recipe));target.chmod(0o600)
    values=table.get_resolved_strings()[app.get_package()]['DEFAULT'];s=(d/'jadx1/sources/t5p215r1/zpkp4jdm3eupjct.java').read_text()
    names={n:values.get(int(v)) for n,v in re.findall(r'public static int (\w+) = (\d+)',s)};target=d/'resource-fields.json';target.write_text(json.dumps(names,ensure_ascii=False,indent=2));target.chmod(0o600)
    certs=app.get_certificates_der_v3() or app.get_certificates_der_v2()
    report={'resourceId':rid,'resourcePath':next(iter(paths)),'resourceBytes':len(raw),'resourceSha256':hashlib.sha256(raw).hexdigest(),'fieldPasswordBytes':len(key.encode()),'fieldKeySha256':hashlib.sha256(key.encode()[:32].ljust(32,b'\0')).hexdigest(),'resourceFieldIds':len(names),'v1':app.is_signed_v1(),'v2':app.is_signed_v2(),'v3':app.is_signed_v3(),'certificateSha1':[hashlib.sha1(c).hexdigest() for c in certs],'certificateSha256':[hashlib.sha256(c).hexdigest() for c in certs],'note':'Certificate fingerprints and scheme presence, not full apksigner verification.'}
    (d/'resources-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
