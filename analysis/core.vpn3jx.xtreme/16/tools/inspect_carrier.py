#!/usr/bin/env python3
"""Compare build16 native seed bindings and owned/static carrier variants privately."""
import argparse,base64,hashlib,json
from pathlib import Path
from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw,Type
from native_recipe import inspect,pointer
from native_inspect import Go32Image
def main():
    p=argparse.ArgumentParser();p.add_argument("elf",type=Path);p.add_argument("catalog",type=Path);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    image=Go32Image(a.elf);primary,recipe=inspect(a.elf)
    seeds={"encrypt":primary,"decrypt":image.read(pointer(image,0xfd2eec,0xfd2ef0),32),
           "do":image.read(pointer(image,0xfd3bf8,0xfd3bfc),32)}
    t=a.catalog.read_text().strip();records=[]
    print(json.dumps({"seedHashes":{k:hashlib.sha256(v).hexdigest() for k,v in seeds.items()},"textBytes":len(t),"lengthMod4":len(t)%4}))
    for name,password in seeds.items():
      for remove in (False,True):
       try:raw=base64.b64decode(t[:3]+t[4:] if remove else t,validate=True)
       except ValueError:continue
       for derive in ("argon2id","direct"):
        key=hash_secret_raw(password,raw[:16],3,8192,1,32,Type.ID) if derive=="argon2id" else password
        for aad in (False,True):
         try:
          offset=16 if derive=="argon2id" else 0
          cipher=AES.new(key,AES.MODE_GCM,nonce=raw[offset:offset+12])
          if aad:cipher.update(raw[:16])
          clear=cipher.decrypt_and_verify(raw[offset+12:-16],raw[-16:])
          obj=json.loads(clear);a.out.write_bytes(clear);a.out.chmod(0o600)
          records.append({"seedBinding":name,"derive":derive,"removeOffset3":remove,"saltAAD":aad,
           "servers":len(obj.get("Servers",[])),"networks":len(obj.get("Networks",[])),
           "rootKeys":list(obj),"authenticated":True})
         except (ValueError,UnicodeError):pass
    print(json.dumps({"authenticatedVariants":records}))
if __name__=="__main__":main()

