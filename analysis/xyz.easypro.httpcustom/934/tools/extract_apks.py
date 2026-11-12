"""Extract the authorized local research libraries and public signer certificate."""
import argparse,hashlib,struct,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]

def length_prefixed(data,pos=0):
    size=struct.unpack_from('<I',data,pos)[0]
    if pos+4+size>len(data):raise ValueError('Truncated signing block')
    return data[pos+4:pos+4+size],pos+4+size

def signer_certificate(data):
    eocd=data.rfind(b'PK\x05\x06')
    cd=struct.unpack_from('<I',data,eocd+16)[0]
    if data[cd-16:cd]!=b'APK Sig Block 42':raise ValueError('Signing block unavailable')
    size=struct.unpack_from('<Q',data,cd-24)[0];pos=cd-size;end=cd-24
    while pos<end:
        size=struct.unpack_from('<Q',data,pos)[0];kind=struct.unpack_from('<I',data,pos+8)[0]
        blob=data[pos+12:pos+8+size];pos+=8+size
        if kind not in (0x7109871a,0xf05368c0):continue
        signers,_=length_prefixed(blob);signer,_=length_prefixed(signers)
        signed,_=length_prefixed(signer);_,offset=length_prefixed(signed)
        certs,_=length_prefixed(signed,offset);certificate,_=length_prefixed(certs)
        return certificate
    raise ValueError('No v2/v3 signer certificate')

def main():
    p=argparse.ArgumentParser();p.add_argument('apks',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.resolve().is_relative_to(ROOT):raise ValueError('Keep third-party binaries outside Git')
    a.output.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(a.apks) as z:
        for name in ('base.apk','split_config.arm64_v8a.apk'):(a.output/name).write_bytes(z.read(name))
    with zipfile.ZipFile(a.output/'split_config.arm64_v8a.apk') as z:
        for name in z.namelist():
            if Path(name).name in ('libf2c.so','libruntime.so','libcodec.so','libpolicy.so'):
                (a.output/Path(name).name).write_bytes(z.read(name))
    certificate=signer_certificate((a.output/'base.apk').read_bytes())
    (a.output/'certificate.der').write_bytes(certificate)
    print('Signer certificate SHA-256:',hashlib.sha256(certificate).hexdigest())
    print('APK signature cryptographic verification: NOT_RUN')

if __name__=='__main__':main()
