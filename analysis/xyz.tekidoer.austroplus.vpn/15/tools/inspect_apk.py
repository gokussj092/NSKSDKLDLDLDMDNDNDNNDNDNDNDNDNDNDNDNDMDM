#!/usr/bin/env python3
"""Reproduce build15 static source trace and extract only its initial ciphertext."""
import argparse,hashlib,json,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.AustroPlus_VPN import codec
def inspect(folder):
    folder=Path(folder).resolve();identity=json.loads((folder/'identity.json').read_text())
    if identity['apkSha256']!='72b5976c94cbfa757f414af0634fda922910ad998d651c1b256ff139b89d1691':raise ValueError('PINNED_APK_MISMATCH')
    if identity['package']!='xyz.tekidoer.austroplus.vpn' or identity['versionCode']!=15:raise ValueError('IDENTITY_MISMATCH')
    if hashlib.sha256((folder/'base.apk').read_bytes()).hexdigest()!=identity['apkSha256']:raise ValueError('APK_MISMATCH')
    result=subprocess.run([sys.executable,str(ROOT/'scripts/apk_analysis/random_strings.py'),
        str(folder/'jadx/sources'),'g40',str(folder/'resolved')],capture_output=True,text=True,timeout=90,check=True)
    sources=folder/'resolved';plain=folder/'jadx/sources';checks={
      'defpackage/gj.java':['AustroPlusVPN_GenPass@2244','ab.o(bArrDecode, str2.getBytes(charset))'],
      'defpackage/hg3.java':['byte[] b = {66, 97, 115, 101, 90, 104}','bArrDecode[i] ^ bArr[i % 6]'],
      'defpackage/w14.java':['openRawResource(R.raw.tekidoer)'],
      'defpackage/pa.java':['return gj.f(','"DATA"'],
      'com/tekidoer/austrovpn/activities/BaseActivity.java':['w14.k(this)','hg3.c(jSONObject.getString("url_updater"))'],
      'defpackage/hz0.java':['setRequestMethod("GET")'],
      'defpackage/la.java':['hg3.c(jSONObject.getString("username"))','hg3.c(jSONObject.getString("dns_pass"))'],
      'defpackage/ka.java':['jSONObject.put("server_host", gj.c(','jSONObject.put("ws_pass", gj.c('],
      'com/tekidoer/austrovpn/activities/MainActivity.java':['return hg3.c(str);','V(jSONObject.getString("custom_payload"))','hg3.c(jSONObject.getString("custom_v2ray"))']}
    digests={}
    for name,markers in checks.items():
        path=sources/name if (sources/name).exists() else plain/name;text=path.read_text()
        if not all(x in text for x in markers):raise ValueError('STATIC_TRACE_MISMATCH '+name)
        digests[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    with zipfile.ZipFile(folder/'base.apk') as z:data=z.read('res/raw/tekidoer.js')
    (folder/'embedded.bin').write_bytes(data);(folder/'embedded.bin').chmod(0o600)
    clear=codec.decode_catalog(data)
    report={'identity':identity,'resolvedStrings':json.loads(result.stdout),'sourceSha256':digests,
      'embeddedBytes':len(data),'embeddedSha256':hashlib.sha256(data).hexdigest(),
      'embeddedVersion':clear['version'],'embeddedServers':len(clear['Servers']),'embeddedTweaks':len(clear['Tweaks']),
      'updater':clear['url_updater'],'catalogKdfInputSha256':hashlib.sha256(codec.CATALOG_KEY).hexdigest(),
      'xorInputSha256':hashlib.sha256(codec.XOR_KEY).hexdigest(),'apkCodeExecuted':False}
    (folder/'recipe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();inspect(a.private)
