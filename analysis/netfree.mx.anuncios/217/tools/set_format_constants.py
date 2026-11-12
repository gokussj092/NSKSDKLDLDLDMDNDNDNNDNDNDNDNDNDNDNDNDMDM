#!/usr/bin/env python3
"""Install reviewed APK format constants in the backend; no runtime external key file."""
import argparse,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();recipe=json.loads((a.private/'recipe.json').read_text());password=recipe['remotePassword'].encode();key=recipe['fieldPassword'].encode()[:32].ljust(32,b'\0')
    assert hashlib.sha256(password).hexdigest()=='247419e2e7ce98342a223eab5bd4800517c7d4a66e7673255e79146839b3f7ef';assert hashlib.sha256(key).hexdigest()=='70d914ed726e2de2476506a5b1754414408d0bc09f42d2097c42ad4e845d153e'
    path=ROOT/'decoders/Python/apps/Speicers_Turbo_VPN/codec.py';text=path.read_text()
    for name,value in [('CATALOG_PASSWORD',password),('FIELD_KEY',key)]:text,count=re.subn(r'^'+name+r' = .*$',lambda _:name+' = '+repr(value),text,flags=re.M);assert count==1
    path.write_text(text)
if __name__=='__main__':main()
