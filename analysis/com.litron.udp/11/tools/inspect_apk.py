#!/usr/bin/env python3
"""Check the exact supplied APK and static catalog call chain, without execution."""
import argparse,hashlib,json,os,re,zipfile
from pathlib import Path
FIELDS=['ChaveKey','DNS','NameServer','Password','Payload','ProxyIP','SNI','ServerHost','Username']
def save(raw,path):
    if path.exists():
        if path.is_symlink() or path.read_bytes()!=raw:raise ValueError('EXISTING_OUTPUT_MISMATCH')
    else:
        with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:f.write(raw)
def inspect(folder):
    folder=Path(folder);apk=folder/'base.apk'
    if hashlib.sha256(apk.read_bytes()).hexdigest()!='83425c38c72a04e0875374cc50706e3eb5ff518104e7edaa1e5f753e675484e1':raise ValueError('APK_MISMATCH')
    root=folder/'jadx/sources/com/skyproject/udp';sources={p: (root/p).read_text() for p in ['util/ConfigUtil.java','util/ConfigUpdate.java','util/AESCrypt.java','MainActivity.java','adapter/ServerDialog.java']}
    assert 'https://godtechprime.github.io/litroproadfix.txt' in sources['util/ConfigUpdate.java']
    assert 'setRequestMethod("GET")' in sources['util/ConfigUpdate.java']
    assert '"godtech25"' in sources['util/ConfigUtil.java'] and 'config/config.json' in sources['util/ConfigUtil.java']
    aes=sources['util/AESCrypt.java']
    for marker in ['SHA-256','AES/CBC/PKCS7Padding','messageDigest.update(bytes, 0, bytes.length)','new IvParameterSpec(bArr)','Base64.decode(str2, 2)']:assert marker in aes
    fields=sorted(set(re.findall(r'AESCrypt\.m3311\(" {8}", jSONObject.getString\("([^"]+)"\)\)',sources['MainActivity.java'])))
    if fields!=FIELDS:raise ValueError('ENCRYPTED_FIELD_CONTRACT_CHANGED')
    with zipfile.ZipFile(apk) as z:
        embedded=z.read('assets/config/config.json');icon=z.read('res/drawable/icon.png')
    save(embedded,folder/'embedded.bin');save(icon,folder/'icon.png')
    result={'package':'com.litron.udp','build':11,'source':'https://godtechprime.github.io/litroproadfix.txt','outerKdf':'SHA256(UTF8(public app format input))','fieldKdf':'SHA256(8 ASCII spaces)','cipher':'AES-256-CBC/PKCS7, IV16 zero bytes','cipherAuthenticated':False,'encryptedServerFields':fields,
        'embeddedBytes':len(embedded),'embeddedSha256':hashlib.sha256(embedded).hexdigest(),'iconBytes':len(icon),'iconSha256':hashlib.sha256(icon).hexdigest(),
        'staticSourceSha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in sources.items()},'apkCodeExecuted':False}
    (folder/'recipe.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();inspect(a.private)
