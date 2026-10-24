"""Generate synthetic 7NET vectors with the independent JDK reference."""
from pathlib import Path
import base64,json,subprocess

HERE=Path(__file__).resolve().parent

def oracle(cases):
    lines=''.join(str(mode)+'\t'+base64.b64encode(value).decode()+'\n' for mode,value in cases)
    r=subprocess.run(['java',str(HERE/'sevennet_vpn_oracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=90)
    values=[base64.b64decode(line) for line in r.stdout.splitlines()]
    if len(values)!=len(cases):raise ValueError('Incomplete JDK reference output')
    return values


def main():
    # Find an independent boundary fixture whose real CBC ciphertext ends in zero.
    candidates=[('boundary.example.test/'+str(i)).encode() for i in range(1024)]
    special=oracle([(11,c) for c in candidates]);raw=oracle([(3,base64.b64decode(v)) for v in special])
    index=next(i for i,value in enumerate(raw) if len(value.rstrip(b'\0'))%16!=0)
    boundary=candidates[index].decode();boundary_cipher=special[index].decode()
    server0=('Name','Subname','OpenVPNTCPPort','OpenVPNSSLPort','UDPSSLPort','CloudfrontDNS','flag','Obfs','CustomCert')
    network0=('Name','Info','DNSResolver','TLSVersion')
    record={name:'test-'+name for name in server0};record.update({'ServerIPHost':boundary,'Username':'test-user','Password':'test-password',
       'Protocol':2,'ServerHTTP':False,'UdpAuthMode':1,'UseCustomCert':True,'isServerThailand':False,
       'SlowDNS':{'NSNameServer':'ns.example.test','PubKey':'test-public-key','unknown':{'null':None}},
       'V2Ray':{'UUID':'test-id','PATH':'/test path','V2RayHost':'v2.example.test','DNSMode':'plain-preserved'},
       'unknown':[None,True,443,1.5,{'empty':''}]})
    network={name:'test-'+name for name in network0};network.update({'UDPv4Port':'5667','SNIHost':'sni.example.test','Payload':'GET / HTTP/1.1\r\n\r\n',
       'ProxySettings':{'Squid':'proxy.example.test','Port':'8080'},'UDPOptions':{'UpMbps':'100','DlMbps':'100','RecvConnectionWindow':'2048'},
       'V2Ray':{'SNIHost':'v2-sni.example.test','CustomV2RAYConfig':'{"outbounds":[{"full":true}]}','UseCustomV2RAYConfig':True,'allowInsecure':False},
       'TunnelType':2,'DNSServerHost':'plaintext.example.test','EnableWS':True,'PayloadMode':1,'AutoReplace':False})
    expected={'Version':'synthetic-56','Servers':[record,{'Name':record['Name'],'ServerIPHost':'duplicate.example.test','Username':'','Password':None}],
       'Networks':[network],'Username':'global-user','Password':'global-password','Notes':'日本語 🔒','unknownRoot':{'list':[False,None,'']}}
    encrypted=json.loads(json.dumps(expected));items=[]
    def fields(obj,mode,names):
        for name in names:
            if name in obj and obj[name] not in (None,''):items.append((obj,name,mode,obj[name]))
    fields(encrypted,2,('Username','Password'))
    for rec in encrypted['Servers']:
        fields(rec,0,server0);fields(rec,1,('ServerIPHost',));fields(rec,2,('Username','Password'))
        if 'SlowDNS' in rec:fields(rec['SlowDNS'],0,('NSNameServer','PubKey'))
        if 'V2Ray' in rec:fields(rec['V2Ray'],0,('UUID',));fields(rec['V2Ray'],1,('PATH','V2RayHost'))
    for rec in encrypted['Networks']:
        fields(rec,0,network0);fields(rec,1,('SNIHost','Payload','UDPv4Port'))
        fields(rec['ProxySettings'],0,('Squid','Port'));fields(rec['UDPOptions'],0,('UpMbps','DlMbps','RecvConnectionWindow'))
        fields(rec['V2Ray'],1,('SNIHost','CustomV2RAYConfig'))
    opened=oracle([(mode+10,value.encode()) for _,_,mode,value in items])
    for (obj,name,mode,_),value in zip(items,opened):obj[name]=value.decode()
    encrypted['Servers'][0]['ServerIPHost']=boundary_cipher
    plain=json.dumps(encrypted,ensure_ascii=False,separators=(',',':')).encode()
    catalog=oracle([(10,plain)])[0].decode()
    profile={'Server':encrypted['Servers'][0],'Network':encrypted['Networks'][0],'Username':encrypted['Username'],'Password':encrypted['Password'],'Enabled':True,'unknown':{'keep':[None,False]}}
    expected_profile={'Server':expected['Servers'][0],'Network':expected['Networks'][0],'Username':expected['Username'],'Password':expected['Password'],'Enabled':True,'unknown':{'keep':[None,False]}}
    file=oracle([(10,json.dumps(profile,ensure_ascii=False).encode())])[0].decode()
    historical=oracle([(10,b'{"Host":"legacy.example.test","Port":443,"Enabled":false}')])[0].decode()
    invalid=json.loads(json.dumps(encrypted));invalid['Servers'][0]['Username']='invalid-ciphertext'
    invalid=oracle([(10,json.dumps(invalid).encode())])[0].decode()
    output={'provenance':'Independent JDK JCA and separately transcribed native XXTEA/Threefish; synthetic data only',
       'catalog':catalog,'expected':expected,'file':file,'expectedFile':expected_profile,'networkFile':'7netvpn://'+oracle([(10,json.dumps(encrypted['Networks'][0],ensure_ascii=False).encode())])[0].decode(),'expectedNetworkFile':expected['Networks'][0],'historical':historical,
       'boundary':{'plain':boundary,'cipher':boundary_cipher,'nativeByteTrimWouldCutCiphertext':True},'invalidFieldCatalog':invalid,
       'sensitiveSample':encrypted['Username'],'sensitiveExpected':expected['Username']}
    (HERE/'sevennet_vpn_vectors.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print('Independent JDK 7NET synthetic catalog/profile/boundary vectors generated')


if __name__=='__main__':main()
