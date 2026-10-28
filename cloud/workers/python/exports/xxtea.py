"""XXTEA encoder matching the audited existing EHI decoder."""
import struct

def encrypt(plain:bytes,key:bytes)->bytes:
    """Inverse of the audited EHI _xxtea_decrypt, length word included."""
    n0=(len(plain)+3)//4
    v=list(struct.unpack("<%dI"%n0,plain.ljust(n0*4,b"\0"))) + [len(plain)]
    n=len(v)
    k=struct.unpack("<4I",key.ljust(16,b"\0")[:16])
    delta=0x9e3779b9; q=6+52//n; su=0;z=v[-1];mask=0xffffffff
    while q:
        q-=1;su=(su+delta)&mask;e=(su>>2)&3
        for p in range(n-1):
            y=v[p+1]
            mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((su^y)+(k[(p&3)^e]^z)))&mask
            v[p]=(v[p]+mx)&mask;z=v[p]
        y=v[0]
        mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((su^y)+(k[((n-1)&3)^e]^z)))&mask
        v[-1]=(v[-1]+mx)&mask;z=v[-1]
    return struct.pack("<%dI"%n,*v)
