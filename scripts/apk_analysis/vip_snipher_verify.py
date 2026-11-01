"""Compare complete authorized catalogs with JDK; print only counts and hashes."""
from __future__ import annotations
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.VIP_Snipher_Pro import codec


def oracle(cases):
    lines=''.join(str(mode)+'\t'+base64.b64encode(value).decode()+'\n' for mode,value in cases)
    r=subprocess.run(['java',str(ROOT/'tests/golden/vip_snipher_oracle.java')],input=lines,text=True,capture_output=True,check=True,timeout=120)
    values=[base64.b64decode(line,validate=True) for line in r.stdout.splitlines()]
    if len(values)!=len(cases):raise ValueError('Incomplete JDK output')
    return values


# Independently transcribed field consumers; do not import production schemas.
SERVER={0:('Name','Subname','OpenVPNTCPPort','OpenVPNSSLPort','UDPSSLPort','CloudfrontDNS','flag','Obfs','CustomCert'),1:('ServerIPHost',),2:('Username','Password')}
NETWORK={0:('Name','Info','DNSResolver','TLSVersion'),1:('SNIHost','Payload')}
NESTED={('Servers','SlowDNS'):{0:('NSNameServer','PubKey')},('Servers','V2Ray'):{0:('UUID',),1:('PATH','V2RayHost')},
 ('Networks','ProxySettings'):{0:('Squid','Port')},
 ('Networks','V2Ray'):{1:('SNIHost','CustomV2RAYConfig')}}


def entries(doc):
    result=[]
    def fields(obj,schema):
        for mode,names in schema.items():
            for name in names:
                if name in obj:result.append((obj,name,mode))
    fields(doc,{2:('Username','Password')})
    for section,schema in [('Servers',SERVER),('Networks',NETWORK)]:
        for rec in doc[section]:
            fields(rec,schema)
            for (parent,key),nested in NESTED.items():
                if parent==section and isinstance(rec.get(key),dict):fields(rec[key],nested)
    return result


def verify(path,native=None,runtime=False):
    data=path.read_bytes();expected=json.loads(oracle([(0,data)])[0]);items=entries(expected)
    cases=list(dict.fromkeys((mode,obj[key].encode()) for obj,key,mode in items if obj[key] not in (None,'')))
    reference=dict(zip(cases,oracle(cases)))
    for obj,key,mode in items:
        if obj[key] not in (None,''):obj[key]=reference[(mode,obj[key].encode())].decode('utf-8')
    actual=codec.decode_catalog(data)
    if actual!=expected:raise ValueError('Full catalog differs from JDK')
    zero_cases=[]
    special=[raw for mode,raw in cases if mode==1]
    streams=dict(zip(special,oracle([(3,base64.b64decode(raw)) for raw in special])))
    zero_cases=[raw for raw in special if len(streams[raw].rstrip(b'\0'))%16]
    sensitive=[raw for mode,raw in cases if mode==2 and len(raw)<2048][:2]
    sensitive_tea=dict(zip(sensitive,oracle([(6,base64.b64decode(raw)) for raw in sensitive]))) if native else {}
    count=0
    if native:
        sys.path.insert(0,str(ROOT/'tests/golden'))
        from vip_snipher_native_oracle import NativePrimitives
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        for mode in (0,1,2):
            selected=[raw for m,raw in cases if m==mode and len(raw)<2048][:2]
            if mode==1:selected=list(dict.fromkeys(selected+zero_cases))
            for raw in selected:
                engine=NativePrimitives(native)
                if mode==0:
                    inner=unpad(AES.new(codec.KEY16,AES.MODE_CBC,codec.IV).decrypt(base64.b64decode(raw)),16)
                    value=bytes((v-2)&255 for v in engine.xxtea(inner,codec.KEY16));target=reference[(mode,raw)]
                elif mode==1:value=engine.threefish(base64.b64decode(raw),codec.HKDF32);target=streams[raw]
                else:value=engine.xxtea(base64.b64decode(raw),codec.PBKDF32);target=sensitive_tea[raw]
                if value!=target:raise ValueError('Original ARM64 primitive differs from JDK')
                count+=1
    report={'source':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'version':actual['Version'],
       'servers':len(actual['Servers']),'networks':len(actual['Networks']),'processed':len(items),
       'nonempty':sum(obj[key] not in (None,'') for obj,key,_ in items),
       **{'mode'+str(m):sum(mode==m and obj[key] not in (None,'') for obj,key,mode in items) for m in range(3)},
       'completeJdkEqual':True,'zeroCiphertextFields':sum(mode==1 and obj[key] not in (None,'') and obj[key].encode() in zero_cases for obj,key,mode in entries(codec.open_outer(data))),
       'nativeCasesEqual':count}
    if runtime:
        from cloud.workers.python.engine import decode_provider_catalog
        from decoders.Python.apps.VIP_Snipher_Pro import server_catalog_decoder as catalog
        rendered=catalog.run(data)
        result=decode_provider_catalog('vip-snipher-pro',data)
        if result['structuredJson']!=actual or result['rawText']!=rendered or result['isPartial']:
            raise ValueError('Isolated worker differs from the complete catalog')
        cli=ROOT/'decoders/Python/apps/VIP_Snipher_Pro/server_catalog_decoder.py'
        process=subprocess.run([sys.executable,str(cli),'--stdin'],input=data,cwd='/tmp',capture_output=True,check=True,timeout=120)
        if process.stdout!=(rendered+"\n").encode():raise ValueError('stdin CLI differs from the complete catalog')
        report.update(completeRealWorkerEqual=True,completeStdinCliEqual=True,renderedBytes=len(process.stdout))
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('catalog',type=Path,nargs='+');p.add_argument('--native',type=Path);p.add_argument('--runtime',action='store_true');a=p.parse_args()
    for path in a.catalog:print(json.dumps(verify(path,a.native,a.runtime)))

if __name__=='__main__':main()
