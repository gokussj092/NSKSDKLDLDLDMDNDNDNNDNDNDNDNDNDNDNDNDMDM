#!/usr/bin/env python3
"""Generate fictional lowercase build15 catalogs using the independent Java oracle."""
import argparse,base64,hashlib,json,sys
from pathlib import Path
from verify import oracle,SERVERS,TWEAKS
def xor(text):
    key=b'BaseZh';return base64.b64encode(bytes(b^key[i%6] for i,b in enumerate(text.encode()))).decode()
def main():
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
    servers={k:'' if i%3==0 else 'fake-'+k+'.example.invalid' for i,k in enumerate(sorted(SERVERS))}
    servers.update(name='Synthetic ñ',flag='xx',server_port='22',ssl_port=443,server_cat='',use_grpc=False,
        v2ray_type='vless',server_info='fixture only',unknown={'flags':[True,None,3],'base64Looking':'YWJjZA=='})
    tweaks={k:'' if i%2==0 else 'fake-'+k+'.example.invalid' for i,k in enumerate(sorted(TWEAKS))}
    tweaks.update(name='Synthetic tweak',flag='xx',tun_mode=1,use_proxy=True,proxy_port='8080')
    expected={'version':'synthetic-15','message':'Owned fixture only','url_updater':'https://example.invalid/catalog',
        'Servers':[servers,dict(servers,name='Second')],'Tweaks':[tweaks,dict(tweaks,name='Second')],
        'unknown':[None,{'number':17,'flag':False}],'force_update':False}
    packed=json.loads(json.dumps(expected));packed['url_updater']=xor(expected['url_updater'])
    for section,fields in [('Servers',SERVERS),('Tweaks',TWEAKS)]:
        for item in packed[section]:
            for key in fields&item.keys():item[key]=xor(item[key])
    invalid=json.loads(json.dumps(packed));invalid['Servers'][0]['username']=False
    invalid_name=json.loads(json.dumps(packed));invalid_name['Tweaks'][0]['name']=None
    enc=oracle([('xxe',json.dumps(x,ensure_ascii=False,separators=(',',':')).encode()) for x in [packed,invalid,invalid_name]])
    fixture={'origin':'OWNED_SYNTHETIC_JAVA_ORACLE','expected':expected,'catalog':base64.b64encode(enc[0]).decode(),
        'invalidField':base64.b64encode(enc[1]).decode(),'invalidName':base64.b64encode(enc[2]).decode()}
    a.output.parent.mkdir(exist_ok=True,parents=True);a.output.write_text(json.dumps(fixture,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'synthetic':True,'sha256':hashlib.sha256(a.output.read_bytes()).hexdigest()}))
if __name__=='__main__':main()
