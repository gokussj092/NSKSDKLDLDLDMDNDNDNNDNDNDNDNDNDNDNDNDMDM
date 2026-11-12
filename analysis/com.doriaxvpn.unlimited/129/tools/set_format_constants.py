#!/usr/bin/env python3
"""Write the two reviewed static format constants into the backend, not .env."""
import argparse,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);a=p.parse_args()
    recipe=json.loads((a.private/'recipe.json').read_text());password=recipe['password'].encode();key=recipe['field_key'].encode()
    assert hashlib.sha256(password).hexdigest()=='7863407ed8a091eeb5dcc2f7c05a892d088fa7df0eb2650c770a03fc573a045b'
    assert hashlib.sha256(key).hexdigest()=='45ab405fcdd0a0f309b26a10752f88af8a8e616fa0ba31837b323f15c0237f1f'
    f=ROOT/'decoders/Python/apps/HTTP_Conexion/codec.py';s=f.read_text()
    for name,value in [('CATALOG_PASSWORD',password),('FIELD_KEY',key)]:
        s,n=re.subn(r'^'+name+r' = .*$',lambda _:name+' = '+repr(value)+' # pinned APK format constant; not HTTP authentication',s,flags=re.MULTILINE);assert n==1
    f.write_text(s);print('Both reviewed format constants included in backend code.')
if __name__=='__main__':main()
