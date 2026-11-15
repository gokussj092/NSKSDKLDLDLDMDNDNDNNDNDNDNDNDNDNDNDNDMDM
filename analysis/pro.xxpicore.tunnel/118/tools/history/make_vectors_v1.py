#!/usr/bin/env python3
"""Generate fictional JCA fixtures; never derive fixtures from real profiles."""
import json
from pathlib import Path
from verify import oracle,dispatch
HERE=Path(__file__).resolve().parents[1]/'tests/fixtures'
def seal(doc):
    out=json.loads(json.dumps(doc));entries=dispatch(out)
    values=oracle([(10+m,v) for _,_,m,v in entries])
    for (r,k,_,_),value in zip(entries,values):r[k]=value
    return oracle([(10,json.dumps(out,ensure_ascii=False,separators=(',',':')))])[0]
def main():
    doc={'Version':'fictional-1','Notes':'Synthetic fixture only','Username':'demo-user','Password':'demo-pass',
      'Servers':[{'Name':'Prueba 日本語','Subname':'Fictional','ServerIPHost':'vpn.example.org','OpenVPNTCPPort':'443','OpenVPNSSLPort':'8443',
       'CloudfrontDNS':'edge.example.org','flag':'ZZ','Obfs':'demo','CustomCert':'fictional-certificate','Username':'user','Password':'password',
       'SlowDNS':{'NSNameServer':'ns.example.org','PubKey':'fictional-public-key'},'V2Ray':{'UUID':'00000000-0000-4000-8000-000000000000','PATH':'/demo','V2RayHost':'ws.example.org'},
       'unchanged':{'foo':True}}],
      'Networks':[{'Name':'Demo','Info':'Fictional only','DNSResolver':'1.1.1.1','TLSVersion':'TLSv1.3','SNIHost':'example.org','Payload':'GET /demo HTTP/1.1\r\nHost: example.org\r\n\r\n',
       'ProxySettings':{'Squid':'proxy.example.org','Port':'8080'},'UDPOptions':{'UpMbps':'5','DlMbps':'10','RecvConnectionWindow':'1048576'},
       'V2Ray':{'SNIHost':'example.org','CustomV2RAYConfig':'{"outbounds":[{"protocol":"vless"}]}'},'optional':None}]}
    HERE.mkdir(parents=True,exist_ok=True)
    (HERE/'catalog.enc').write_text(seal(doc));(HERE/'expected.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n')
    invalid={}
    for name,changed in [('missing-networks',{**doc,'Networks':[]}),('bad-inner',{**doc,'Servers':[{'Name':7}]}),('bad-nested',{**doc,'Networks':[{'V2Ray':[]}]}),('not-object',[])]:
        if name=='bad-inner':
            changed={'Version':'x','Servers':[{'Name':7}],'Networks':[{}]}
        encoded=json.dumps(changed,separators=(',',':'));invalid[name]=oracle([(10,encoded)])[0]
    invalid['duplicate-key']=oracle([(10,'{"Version":"a","Version":"b","Servers":[{}],"Networks":[{}]}')])[0]
    invalid['nan']=oracle([(10,'{"Version":NaN,"Servers":[{}],"Networks":[{}]}')])[0]
    (HERE/'invalid.json').write_text(json.dumps(invalid,indent=2)+'\n')
    print(json.dumps({'source':'independent Java/JCA encryption','fictionalCatalogs':1,'negativeEnvelopes':len(invalid)}))
if __name__=='__main__':main()
