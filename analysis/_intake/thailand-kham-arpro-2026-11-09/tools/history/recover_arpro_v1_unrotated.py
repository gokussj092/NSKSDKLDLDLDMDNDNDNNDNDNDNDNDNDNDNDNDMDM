# Historical failed XTS hypothesis: missing native byte rotation. Do not use for current recovery.
#!/usr/bin/env python3
"""Static native constants and AES-XTS/GCM oracle for AR PRO build2.

Offsets validated against libovpn3 SHA-256 in the build expediente. No native
vendor code executes. Decoded configs remain in the private directory.
"""
import argparse,base64,hashlib,json,zipfile
from pathlib import Path
from elftools.elf.elffile import ELFFile
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
EXPECTED=''
def recover(directory):
    library=directory/'splits/config.arm64_v8a.apk/lib/arm64-v8a/libovpn3.so'
    with library.open('rb') as f:
        elf=ELFFile(f)
        def raw(address,n):
            s=next(s for s in elf.iter_sections() if s['sh_addr']<=address<s['sh_addr']+s['sh_size'])
            return s.data()[address-s['sh_addr']:address-s['sh_addr']+n]
        def xor(a,b):return bytes(x^y for x,y in zip(a,b))
        standard=xor(raw(0x21d6e0,32),raw(0x1c2b80,16)+raw(0x1c2860,16))
        xts=xor(raw(0x21d8d0,64),raw(0x1c2000,16)+raw(0x1c21c0,16)+raw(0x1c2aa0,16)+raw(0x1c2ab0,16))
    keys={'standard':base64.b64encode(standard).decode(),'mode5':base64.b64encode(xts).decode()}
    (directory/'format-keys.json').write_text(json.dumps(keys))
    with zipfile.ZipFile(directory/'base.apk') as z:wire=z.read('res/raw/noobdev.js')
    blob=base64.b64decode(wire);cipher=Cipher(algorithms.AES(xts),modes.XTS(blob[:16])).decryptor()
    plain=cipher.update(blob[16:])+cipher.finalize();doc=json.loads(plain)
    (directory/'embedded-outer.json').write_text(json.dumps(doc))
    def field(v):
        if not v:return v
        data=base64.b64decode(v);return AESGCM(standard).decrypt(data[:12],data[12:],None).decode()
    metadata={k:field(doc[k]) for k in ('Version','Message','DefUpdateURL','updater') if k in doc}
    (directory/'embedded-metadata.json').write_text(json.dumps(metadata))
    print(json.dumps({'outerSha256':hashlib.sha256(plain).hexdigest(),'librarySha256':hashlib.sha256(library.read_bytes()).hexdigest(),
      'keys':list(doc),'version':metadata.get('Version'),'sourceRecovered':bool(metadata.get('DefUpdateURL'))}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();recover(a.private)
