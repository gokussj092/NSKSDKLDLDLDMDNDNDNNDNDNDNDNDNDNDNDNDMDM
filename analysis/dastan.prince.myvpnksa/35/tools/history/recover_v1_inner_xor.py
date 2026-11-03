#!/usr/bin/env python3
"""Pin the observed build, confirm recovered source/constants and fetch its updater.

Inputs stay private. No Android code, signature check or account API is executed.
Run shared inspect_apk/decompile/paranoid_strings first (see REPRODUCE.md).
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.request import Request, HTTPRedirectHandler, build_opener

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from scripts.apk_analysis.elf_inspect import ElfImage
from decoders.Python.apps.BD_NET_VPN import codec

SOURCE="https://raw.githubusercontent.com/pipoyrichards/FNFTUNNELBD/refs/heads/main/FEB52025"
AGENT="FNF TUNNEL BD/PrinceBuild35" # broker identifier; original Volley has no custom header
BASE_SHA="8a2d72c7c8005a979e221dffb1b8fba550512e2fa925ed1dbde16c7ff1066e38"

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError("Unexpected updater redirect")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("private",type=Path);p.add_argument("--download",action="store_true")
    a=p.parse_args();d=a.private
    digest=lambda x:hashlib.sha256(x).hexdigest()
    assert digest((d/'apks/dastan.prince.myvpnksa.apk').read_bytes())==BASE_SHA
    sources=d/'resolved'
    updater=(sources/'fnf/vpn/app/activities/OpenVPNClient.java').read_text()
    callback=(sources/'defpackage/Hy.java').read_text()
    outer=(sources/'defpackage/AbstractC0398oi.java').read_text()
    assert SOURCE in updater and 'new Hy(this)' in updater
    assert 'AbstractC0398oi.c(' in callback and '"Version"' in callback and '"/gremlin.json"' in callback
    assert '"...|..."' in outer and '(-1638454863)' in outer
    elf=ElfImage(d/'libputils.so')
    # The function at 0x1466d4 constructs an 8-byte literal plus MOVK suffix,
    # then EORs every byte modulo twelve. Pin its exact disassembly for review.
    asm=list(elf.disassemble(0x1466d4,548))
    assert elf.read(0xc4731,8)+bytes.fromhex('666b505d')==codec.PROFILE_KEY
    (d/'xor-disassembly.txt').write_text('\n'.join(asm)+'\n')
    report={'baseApkSha256':BASE_SHA,'nativeSha256':digest((d/'libputils.so').read_bytes()),
      'source':SOURCE,'deltaMatches':True,'profileKeyMatches':True,
      'xorAddress':'0x1466d4','xorBytes':548,'disassemblySha256':digest(('\n'.join(asm)+'\n').encode())}
    if a.download:
        with build_opener(NoRedirect()).open(Request(SOURCE,headers={
          'User-Agent':AGENT,'Accept-Encoding':'identity'}),timeout=30) as r:
            assert r.status==200 and r.headers.get('Content-Encoding','identity')=='identity'
            data=r.read(codec.MAX_INPUT+1)
            report['http']={'status':r.status,'contentType':r.headers.get('Content-Type'),'bytes':len(data),'sha256':digest(data)}
        assert data and len(data)<=codec.MAX_INPUT and not data.lstrip().startswith(b'<')
        f=d/'remote.enc';f.write_bytes(data);f.chmod(0o600)
        decoded=codec.decode_json_bytes(data)
        f=d/'remote-decoded.json';f.write_bytes(decoded);f.chmod(0o600)
        report['remote']=codec.summary(decoded);report['remote']['provider']='fnf-tunnel-bd'
    (d/'recovery-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
