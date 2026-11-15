#!/usr/bin/env python3
"""Generate only fictional test catalogs using an independent Java encryptor."""
import base64,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
ORACLE=ROOT/'analysis/com.appxrayservice.namovpn/35/tools/CatalogOracle.java'
def encrypt(doc,key=b'khamvpn270@'):
    raw=json.dumps(doc,ensure_ascii=False,separators=(',',':')).encode()
    line='E\t'+base64.b64encode(key).decode()+'\t'+base64.b64encode(raw).decode()+'\n'
    out=subprocess.run(['java',str(ORACLE)],input=line,text=True,capture_output=True,check=True,timeout=60)
    return base64.b64decode(out.stdout.strip()).decode()
def encoded(s):return base64.b64encode(s.encode()).decode()
if __name__=='__main__':
    d=ROOT/'analysis/com.khamvpn.net/24/tests/fixtures';d.mkdir(parents=True,exist_ok=True)
    plain={'Version':'fictional-1','Message':'Unicode: México 🇲🇽',
      'Servers':[{'ServerName':'YWJj','ServerIP':'ssh.example.invalid','Username':'fictional',
       'Password':'fictitious','SSHPort':'22','ServerFlag':'th','UDPConfig':'','setOpenVPN':''}],
      'Networks':[{'PayloadName':'Fictional network','Sni':'tls.example.invalid','Payload':'CONNECT [host_port] HTTP/1.1\r\n\r\n','SquidPort':'80','SelectedProtocal':'SSH'}],
      'setOpenVPN':'','unknown':{'preserve':['full',None,True,3]}}
    wire=json.loads(json.dumps(plain))
    for group,fields in [('Servers',('ServerIP','Username','Password','UDPConfig','setOpenVPN')),('Networks',('Sni','Payload'))]:
        for row in wire[group]:
            for k in fields:row[k]=encoded(row[k])
    cases={'plain':plain,'wire':encrypt(wire),'outer':wire}
    bad=json.loads(json.dumps(wire));bad['Servers'][0]['ServerIP']='!invalid!';cases['badField']=encrypt(bad)
    bad=json.loads(json.dumps(wire));bad['Networks']=[];cases['emptyNetworks']=encrypt(bad)
    cases['wrongKey']=encrypt(wire,b'fictional-key')
    (d/'vectors.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2)+'\n')
    d=ROOT/'analysis/thailand.vpn.globalvpn/3/tests/fixtures';d.mkdir(parents=True,exist_ok=True)
    plain={'Status':True,'Servers':[{'id':1,'protocol_type':'openvpn','server_name':'Fictional México 🇲🇽',
      'server_type':'free','ip':'vpn.example.invalid','username':None,'password':None,'configuration':'fictional-profile',
      'no_of_minutes':15,'server_status':'active','unknown':{'preserve':True}}],
      'Settings':{'app_settings':{'fictional':True}},'unknown':[None,False,123]}
    (d/'vectors.json').write_text(json.dumps({'plain':plain,'wire':encoded(json.dumps(plain,ensure_ascii=False))},ensure_ascii=False,indent=2)+'\n')
    print('Fictional Java-reference KHAM and Base64 Thailand vectors written')
