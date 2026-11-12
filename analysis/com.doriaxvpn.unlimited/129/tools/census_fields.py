#!/usr/bin/env python3
"""Count GCM-compatible fields without printing values; compare strict/Android Base64."""
import argparse,base64,collections,json
from pathlib import Path
from Crypto.Cipher import AES
def census(doc,key,normalize):
    counts={}
    for row in doc['Servers']:
        for name,value in row.items():
            c=counts.setdefault(name,collections.Counter());c[type(value).__name__]+=1
            if not isinstance(value,str) or not value:c['empty_or_nonstring']+=1;continue
            try:
                raw=base64.b64decode(''.join(value.split()) if normalize else value,validate=True)
                if len(raw)<28:raise ValueError('short')
                clear=AES.new(key,AES.MODE_GCM,nonce=raw[:12]).decrypt_and_verify(raw[12:-16],raw[-16:])
                base64.b64decode(b''.join(clear.split()) if normalize else clear,validate=True)
                c['authenticated_gcm']+=1
            except ValueError:c['not_this_gcm']+=1
    return counts
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('private',type=Path);p.add_argument('outer',type=Path);a=p.parse_args()
    key=json.loads((a.private/'recipe.json').read_text())['field_key'].encode();doc=json.loads(a.outer.read_text())
    result={'source':a.outer.name,'strict_base64':census(doc,key,False),'android_whitespace':census(doc,key,True)}
    (a.private/(a.outer.stem+'-census.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
if __name__=='__main__':main()
