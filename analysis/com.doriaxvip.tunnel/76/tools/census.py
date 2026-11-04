#!/usr/bin/env python3
"""Preserve the discovery census: every nonempty row string is a CBC field."""
import argparse
import base64
from collections import Counter, defaultdict
import json
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('private',type=Path)
    args=parser.parse_args()
    constants=json.loads((args.private/'constants.json').read_text())
    key=constants['innerPassword'].encode().ljust(32,b'\0')[:32]
    report={}
    for name in ('included','included-users','remote'):
        doc=json.loads((args.private/(name+'.outer.json')).read_text())
        counts=Counter();fields=defaultdict(Counter)
        for section in ('Servers','Usuarios'):
            for row in doc.get(section,[]):
                for field,value in row.items():
                    if not isinstance(value,str):continue
                    try:
                        raw=base64.urlsafe_b64decode(value+'='*((-len(value))%4))
                        unpad(AES.new(key,AES.MODE_CBC,raw[:16]).decrypt(raw[16:]),16).decode()
                        outcome='decrypted'
                    except ValueError:
                        outcome='empty' if value=='' else 'invalid'
                    counts[outcome]+=1;fields[field][outcome]+=1
        assert not counts['invalid']
        report[name]={'counts':dict(counts),'fields':dict(fields)}
    target=args.private/'census.json'
    target.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v['counts'] for k,v in report.items()}))


if __name__=='__main__':main()
