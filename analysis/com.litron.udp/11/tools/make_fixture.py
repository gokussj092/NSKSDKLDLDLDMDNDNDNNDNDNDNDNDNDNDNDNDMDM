#!/usr/bin/env python3
"""Generate fictional .invalid fixtures only, using the independent JCA oracle."""
import argparse,base64,copy,json
from pathlib import Path
from verify import oracle
FIELDS=['ChaveKey','DNS','NameServer','Password','Payload','ProxyIP','SNI','ServerHost','Username']
def make(output):
    expected={'Version':'fixture.11','IsTimer':False,'ReleaseNotes':'Prueba ñ 😀\nsegunda línea','Password':'root plaintext is untouched',
        'Unknown':{'a':[1,None,True,{'keep':'YWJjZA=='}]},'Servers':[
        {'Name':'Fictional full server','TunnelType':'5','ServerPort':'443','Json':'{"nested":[1,true]}','VendorOpaque':'YWJjZA==',**{k:k+'.example.invalid\nñ 😀' for k in FIELDS}},
        {'Name':'Empty inactive fields','TunnelType':'6','ServerHost':'','SNI':'','Json':'{"example":"config.invalid"}'},
        {'Name':'Unknown future protocol','TunnelType':'99','UnknownList':[None,2,False]}]}
    packed=copy.deepcopy(expected);server=packed['Servers'][0]
    for field,raw in zip(FIELDS,oracle([('seal',b' '*8,server[k].encode()) for k in FIELDS])):server[field]=base64.b64encode(raw).decode()
    text=json.dumps(packed,ensure_ascii=False,separators=(',',':'))
    invalid=['[]','{"Version":"x","Servers":[],"Version":"duplicate"}','{"Version":"x","Servers":[],"n":NaN}',
        '{"Version":"x","Servers":[],"n":1e999}','{"Version":"x","Servers":[],"x":"\\ud800"}',
        '{"Version":1,"Servers":[]}','{"Version":"x","Servers":{}}','{"Version":"x","Servers":[{"Name":1}]}',
        '{"Version":"x","Servers":[{"Name":"test","Password":"invalid marker"}]}','{"Version":"x","Servers":[{"Name":"test","ServerHost":null}]}']
    bad_utf8=base64.b64encode(oracle([('seal',b' '*8,b'\xff')])[0]).decode()
    invalid.append(json.dumps({'Version':'x','Servers':[{'Name':'bad utf8','Payload':bad_utf8}]}))
    outputs=oracle([('seal',b'godtech25',x.encode()) for x in [text,*invalid]])
    result={'provenance':'Independent standard JCA synthetic fixtures; no real server data','catalog':base64.b64encode(outputs[0]).decode(),
        'expected':expected,'invalidCatalogs':[base64.b64encode(x).decode() for x in outputs[1:]],'outerJson':packed}
    Path(output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True);make(a.output)
