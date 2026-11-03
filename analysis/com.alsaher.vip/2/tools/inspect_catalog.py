#!/usr/bin/env python3
"""Census of encrypted field locations; no plaintext values or secrets printed."""
import argparse,json,hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.ZiG_Tunnel.codec import open_outer,decrypt

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('catalog',type=Path);a=p.parse_args()
    data=a.catalog.read_bytes();doc=open_outer(data)
    fields={}
    def walk(value,path='$'):
        if isinstance(value,dict):
            for k,v in value.items():walk(v,path+'.'+k)
        elif isinstance(value,list):
            for v in value:walk(v,path+'[]')
        elif isinstance(value,str) and value:
            try:clear=decrypt(value)
            except ValueError:return
            fields[path]=fields.get(path,0)+1
    walk(doc)
    print(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
       'version':doc.get('Version'),'lists':{k:len(v) for k,v in doc.items() if isinstance(v,list)},
       'decryptable_field_locations':fields,'all_top_keys':list(doc)},indent=2))
if __name__=='__main__':main()
