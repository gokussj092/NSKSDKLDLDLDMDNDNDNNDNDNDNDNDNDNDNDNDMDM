#!/usr/bin/env python3
"""Recover the documented Zstd code frame; inventory public routes/identifiers only.

Uses the host libzstd data parser, never loads APK/native executable code.
Does not recover application authentication keys or execute any request.
"""
import argparse,ctypes,ctypes.util,hashlib,json,re
from pathlib import Path
from inventory import urls
EXPECTED='2563039f827ff936035abfbe7aeb0cb9d4bac8bf42f414bb6c68cf7241081a4d'
OFFSET=0xe89018;SIZE=0x4de074;PLAIN=0x1e00000
TOKENS=('server_list','servers_list','get_servers','list_servers','ServerList','ServersActivity','ServerRepository','ApiService','import_config')
def unpack(private):
    raw=(private/'inputs/libdatajar.so').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=EXPECTED:raise ValueError('BUILD_HASH_MISMATCH')
    encoded=raw[OFFSET:OFFSET+SIZE]
    lib=ctypes.CDLL(ctypes.util.find_library('zstd'))
    lib.ZSTD_decompress.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t]
    lib.ZSTD_decompress.restype=ctypes.c_size_t
    lib.ZSTD_isError.argtypes=[ctypes.c_size_t];lib.ZSTD_isError.restype=ctypes.c_uint
    lib.ZSTD_versionString.restype=ctypes.c_char_p
    output=ctypes.create_string_buffer(PLAIN);source=ctypes.create_string_buffer(encoded)
    size=lib.ZSTD_decompress(output,PLAIN,source,len(encoded))
    if lib.ZSTD_isError(size) or size!=PLAIN:raise ValueError('FRAME_DECOMPRESSION_FAILED')
    frame=output.raw[:size];target=private/'code-frame.bin';target.write_bytes(frame);target.chmod(0o600)
    routes=set();classes=set()
    for m in re.finditer(rb'[A-Za-z0-9_./$-]{5,180}',frame):
        text=m[0].decode()
        if re.fullmatch(r'/?httpinjector/[a-z0-9_/-]{1,80}',text):routes.add(text)
        if re.fullmatch(r'(?:[A-Za-z_$][A-Za-z0-9_$/]*?/)?[A-Za-z_$]*(?:ServerList|ServersActivity|ServerRepository|ApiService)[A-Za-z0-9_$]*',text):classes.add(text)
    result=dict(frameBytes=size,frameSha256=hashlib.sha256(frame).hexdigest(),hostZstdVersion=lib.ZSTD_versionString().decode(),
      tokenCounts={token:frame.count(token.encode()) for token in TOKENS},routeIdentifiers=sorted(routes),classIdentifiers=sorted(classes)[:60],
      sourceCandidates=urls(frame,'documented-zstd-code-frame'),apkCodeExecuted=False,authenticationMaterialCollected=False,
      limitation='Code frame and identifiers do not establish a working remote catalog or a complete executable DEX.')
    target=private/'frame-inventory.json';target.write_text(json.dumps(result,indent=2)+'\n');target.chmod(0o600);print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();unpack(a.private)
