#!/usr/bin/env python3
"""Read build16 PC-relative literals and report safe method evidence only."""
from pathlib import Path
import hashlib,json,struct
from native_inspect import Go32Image
PIN="4df067b7c0c6d38730476ff94a950424c561be05cd4d31abf64b6f6a7f73425a"
def pointer(image,load,add):
    from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
    dis=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    ins=list(dis.disasm(image.read(load,4),load))[0]
    nxt=list(dis.disasm(image.read(add,4),add))[0]
    if ins.mnemonic!="ldr" or "[pc, #" not in ins.op_str or nxt.mnemonic!="add":
        raise ValueError("UNEXPECTED_LITERAL_BINDING")
    off=int(ins.op_str.split("#")[1].rstrip("]"),0)
    value=struct.unpack("<i",image.read(load+8+off,4))[0]
    return (add+8+value)&0xffffffff
def inspect(path):
    image=Go32Image(path)
    if hashlib.sha256(image.data).hexdigest()!=PIN:raise ValueError("UNSUPPORTED_NATIVE_BUILD")
    def string(load,add,size):return image.read(pointer(image,load,add),size)
    password=string(0xfd28e8,0xfd28ec,32)
    field_seed=string(0xfd3bf8,0xfd3bfc,32)
    source=string(0xfd7300,0xfd7304,39).decode()
    method=string(0xfd72ec,0xfd72f0,4).decode()
    field=string(0xfd71f8,0xfd71fc,4).decode()
    value=string(0xfd71d8,0xfd71dc,14).decode()
    content_type=string(0xfd7390,0xfd7394,33).decode()
    return password,{"source":source,"method":method,"formField":field,"formValue":value,
        "contentType":content_type,"nativeSha256":PIN,"passwordSha256":hashlib.sha256(password).hexdigest(),
        "passwordLength":len(password),"fieldSeedSha256":hashlib.sha256(field_seed).hexdigest(),"argon2":{"variant":"id","time":3,"memoryKiB":8192,"parallelism":1,"outputBytes":32},
        "format":"salt16 nonce12 AES-GCM ciphertext tag16; salt also AAD; random letter inserted at Base64 offset3"}
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser();p.add_argument("elf",type=Path);p.add_argument("--private-recipe",type=Path);a=p.parse_args()
    key,report=inspect(a.elf)
    if a.private_recipe:
        a.private_recipe.write_text(json.dumps({**report,"passwordHex":key.hex()},indent=2));a.private_recipe.chmod(0o600)
    # POST fields are public client recipe data, never account credentials.
    print(json.dumps(report))

