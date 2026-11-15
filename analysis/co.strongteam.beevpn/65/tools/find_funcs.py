import struct
p = '/home/hatch/workspace/catalogs/beevpn/extract/config.arm64_v8a/lib/arm64-v8a/libgojni.so'
data = open(p,'rb').read()
base = 0x13fde40
TEXT = 0x5233f0
u64 = lambda o: struct.unpack_from('<Q', data, o)[0]
nfunc = u64(base+8)
fnOff = u64(base+32)
pcln = u64(base+64)
ft = base + pcln
def cstr(o):
    e = data.index(b'\0', o)
    return data[o:e].decode('utf-8','replace')
funcs = []
for i in range(nfunc):
    e, f = struct.unpack_from('<II', data, ft + i*8)
    fbase = ft + f
    nameoff = struct.unpack_from('<i', data, fbase+4)[0]
    name = cstr(base+fnOff+nameoff)
    funcs.append((TEXT+e, name))
import json
json.dump(funcs, open('/home/hatch/workspace/catalogs/beevpn/work/funcs.json','w'))
for addr, name in funcs:
    if 'AndroidLibXrayLite' in name:
        print(f'{addr:#x} {name}')
