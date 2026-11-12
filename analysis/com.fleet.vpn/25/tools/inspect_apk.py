#!/usr/bin/env python3
"""Confirm the base Litron identity, updater and public cipher inputs statically."""
import argparse,hashlib,json,re,zipfile
from pathlib import Path
PIN='8d3818e7a60998f18275e9339f5578aba68153d79b50cfac7c0b7a1201f24a52'
def inspect(folder):
    folder=Path(folder).resolve();identity=json.loads((folder/'identity.json').read_text())
    if identity['package']!='com.fleet.vpn' or identity['versionCode']!=25 or hashlib.sha256((folder/'base.apk').read_bytes()).hexdigest()!=PIN:raise ValueError('BASE_LITRON_IDENTITY_MISMATCH')
    sources=folder/'jadx/sources';paths={
      'defpackage/lh0.java':['"godtech25"','q.f(b,','"Networks"','"Servers"'],
      'defpackage/q.java':['AES/CBC/PKCS7Padding','"SHA-256"','0123456789ABCDEF','l(d(str))','Base64.decode(strK, 2)'],
      'com/slipkprojects/ultrasshservice/util/securepreferences/model/vagol.java':['https://godtechprime.github.io/latestv2ray.txt'],
      'com/slipkprojects/sockshttp/MainActivity.java':['public static final String F2 = new k().toString()','defpackage.q.f(F2,']}
    digests={}
    for name,markers in paths.items():
        text=(sources/name).read_text()
        if not all(s in text for s in markers):raise ValueError('STATIC_CIPHER_TRACE_MISMATCH '+name)
        digests[name]=hashlib.sha256((sources/name).read_bytes()).hexdigest()
    main=(sources/'com/slipkprojects/sockshttp/MainActivity.java').read_text()
    block=main.split('public class k {',1)[1].split('public class l ',1)[0]
    expressions=re.findall(r'\(?(-?\d+)\)? >>> (\d+)',block)
    seed=bytes(((int(value)&0xffffffff)>>int(shift))&255 for value,shift in expressions)
    if seed!=b'godtech25':raise ValueError('FIELD_SEED_MISMATCH')
    with zipfile.ZipFile(folder/'base.apk') as z:
        info=z.getinfo('assets/config/config.json')
        if info.file_size>5*1024*1024:raise ValueError('ASSET_BOUNDS')
        data=z.read(info)
    (folder/'embedded.bin').write_bytes(data);(folder/'embedded.bin').chmod(0o600)
    result={'package':'com.fleet.vpn','build':25,'notProPackage':True,'sourceSha256':digests,
       'fieldSeedMatchesCatalogSeed':True,'seedSha256':hashlib.sha256(seed).hexdigest(),
       'embeddedBytes':len(data),'embeddedSha256':hashlib.sha256(data).hexdigest(),
       'source':'https://godtechprime.github.io/latestv2ray.txt','apkCodeExecuted':False}
    (folder/'recipe.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();inspect(a.private)
