#!/usr/bin/env python3
"""Independent Java fixture generation. Synthetic values/example.org only."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify import oracle

def main():
    fixture=Path(__file__).resolve().parents[1]/'tests/fixtures'
    text='Prueba 日本語 😀\nGET / HTTP/1.1\r\nHost: example.org\r\n'
    doc={'FileName':'synthetic-alsaher','Version':'synthetic-2','ReleaseNotes':'test',
      'config_url':'https://example.org/catalog','cloud_get_api':'https://example.org/get',
      'cloud_post_api':'https://example.org/post','account_api':'','AppConfPass':'',
      'Servers':[{'Name':'Example','ServerIP':'vpn.example.org','ProxyHost':'proxy.example.org',
                  'Username':'synthetic-user','Password':'synthetic-password','TcpPort':'443',
                  'AutoLogIn':False,'unknown':{'preserve':[True,None,7]}}],
      'HTTPNetworks':[{'Name':'HTTP sample','NetworkPayload':text,'SquidProxy':'proxy.example.org','UseDefProxy':True}],
      'SSLNetworks':[{'Name':'SSL sample','SSLSNI':'example.org','SquidProxy':'','SSLPort':'443'}],
      'JSONsettings':[{'mLocalPort':'1080','mCompression':True,'unknown':'preserve'}],
      'unknownRoot':{'preserve':True}}
    expected=json.loads(json.dumps(doc));entries=[]
    for k in ('config_url','cloud_get_api','cloud_post_api'):entries.append((doc,k))
    for k in ('ServerIP','ProxyHost','Username','Password'):entries.append((doc['Servers'][0],k))
    for k in ('NetworkPayload','SquidProxy'):entries.append((doc['HTTPNetworks'][0],k))
    entries.append((doc['SSLNetworks'][0],'SSLSNI'))
    values=[row[k] for row,k in entries]
    for (row,k),encrypted in zip(entries,oracle('E',values)):row[k]=encrypted
    cipher=oracle('E',[json.dumps(doc,ensure_ascii=False)])[0]
    fixture.mkdir(parents=True,exist_ok=True)
    (fixture/'expected.json').write_text(json.dumps(expected,ensure_ascii=False,indent=2)+'\n')
    (fixture/'outer.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n')
    (fixture/'catalog.enc').write_text(cipher+'\n')
    print('Generated synthetic whole-catalog fixture with Java reference.')
if __name__=='__main__':main()
