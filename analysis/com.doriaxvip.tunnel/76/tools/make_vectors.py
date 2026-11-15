#!/usr/bin/env python3
"""Create fictional JCA-encrypted fixtures; never copy a real VPN profile."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).parent))
from verify import oracle, line
from decoders.Python.apps.Genis_VPN.codec import CATALOG_PASSWORD, FIELD_KEY

TARGET = Path(__file__).resolve().parent.parent/'tests/fixtures'


def seal(doc):
    value = json.loads(json.dumps(doc))
    fields = [(row,key,val) for section in ('Servers','Usuarios') for row in value.get(section,[])
              for key,val in row.items() if isinstance(val,str)]
    results = oracle([line('G', FIELD_KEY, val.encode()) for _,_,val in fields])
    for (row,key,_), encoded in zip(fields,results):
        row[key]=encoded.decode()
    plain = json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
    sealed, = oracle([line('E', CATALOG_PASSWORD, plain)])
    return sealed


def main():
    TARGET.mkdir(parents=True,exist_ok=True)
    server = {'Version':'76-fixture','ReleaseNotes':'Fictional test only',
              'Meta':{'nested':['kept',False,None,7],'unicode':'Español 🙂'},
              'Servers':[{'serverType':1,'tunnelType':2,'p0PgL3l0d89mnssz7ImPJA==':'Fictional Genis 🇲🇽',
                          'ACqWMY4zuZWzSEs8cZMXIw==':'test.example.org',
                          'Qz8kR1uPmNvT4sXbHc2AwQ==':'opaque value',
                          'futureEncryptedField':'Keep the entire document',
                          'SbDP19AbQur0YtkkyRlVMA==':'','MIgkNbuX29MmGatZNVaFUj==':False}]}
    users = {'Version':'76-fixture','Usuarios':[{'Name':'Fictional User','Username':'fixture-user',
             'Password':'fictional-only','Obfs':'','Auth':'test-auth','ID':'fixture-id','Path':'/fixture'}]}
    for name,doc in [('catalog',server),('users',users)]:
        (TARGET/(name+'.enc')).write_bytes(seal(doc))
        (TARGET/(name+'.json')).write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n')
    print('JCA fictional full-document vectors created.')


if __name__=='__main__':
    main()
