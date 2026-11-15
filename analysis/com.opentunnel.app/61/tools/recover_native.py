#!/usr/bin/env python3
"""Static getSecret(10) recovery from JNI_OnLoad; never loads/emulates the SO."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'scripts/apk_analysis'))
from elf_inspect import ElfImage
def recover(folder):
    folder=Path(folder);image=ElfImage(folder/'libopentunnel.so')
    if hashlib.sha256(image.data).hexdigest()!='5f5449eb72551bdf6a285d09322c8290554068f49d9f6682bab6609664c40ba1':raise ValueError('NATIVE_MISMATCH')
    # JNI_OnLoad21e08: ADR21e68->15864; XORaa loop64 bytes; key10 at21eb4.
    secret=bytes(x^0xaa for x in image.read(0x15864,64));secret.decode('ascii')
    result={'secret10':secret.decode(),'secretSha256':hashlib.sha256(secret).hexdigest(),'length':len(secret),'source':'JNI_OnLoad0x21e08/XOR loop0x21e8c..21eb0/map key10 at0x21eb4','librarySha256':hashlib.sha256(image.data).hexdigest(),'scope':'public app-wide file/prefs format input, not SSH credentials or cloud authorization','apkCodeExecuted':False}
    p=folder/'native-material.json';p.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='secret10'}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();recover(a.private)
