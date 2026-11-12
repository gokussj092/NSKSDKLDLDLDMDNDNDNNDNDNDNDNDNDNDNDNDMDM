#!/usr/bin/env python3
"""Generate fictional catalogs with independent Java, not the Python decoder."""
import base64,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.NAMO_VPN.codec import FORMAT_KEY
sys.path.insert(0,str(Path(__file__).with_name('fields')))
from reference import transform_fields
def transform(mode,values,key=FORMAT_KEY):
    lines=''.join(mode+'\t'+base64.b64encode(key).decode()+'\t'+base64.b64encode(v).decode()+'\n' for v in values)
    done=subprocess.run(['java',str(Path(__file__).with_name('CatalogOracle.java'))],input=lines,
      text=True,capture_output=True,check=True,timeout=45)
    out=[base64.b64decode(x,validate=True) for x in done.stdout.splitlines()]
    if len(out)!=len(values):raise ValueError('Incomplete reference')
    return out
def main():
    doc={'Version':'test35','Message':'Fictional; prueba ñ ไทย 🦊',
      'Servers':[{'ServerName':'Fictional server','ServerIP':'vpn.example.org','Username':'sample-user',
        'Password':'sample-password','TCPPort':'443','setOpenVPN':'client\nremote vpn.example.org 443\n',
        'OvpnCertificate':'client\n','V2Ray':'vless://fictional@example.org:443',
        'Cloudfront':'front.example.org','NameServer':'ns.example.org','PublicKey':'0123456789abcdef',
        'ServerDNS':'dns.example.org','ProxyIP':'proxy.example.org','UDPConfig':'{"server":"example.org"}'}],
      'Networks':[{'PayloadName':'Fictional network','Sni':'front.example.org',
        'Payload':'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n','ServerDNS':'dns.example.org',
        'SquidProxy':'proxy.example.org','Protocal':'SSL','UnusualPlainHex':'deadbeef',
        'FutureBase64':'cHJlc2VydmU=','empty':''}],
      'setOpenVPN':'client\nremote root.example.org 443\n','FutureMetadata':{'nested':[True,None,35]}}
    out=Path(__file__).resolve().parents[1]/'tests/fixtures';out.mkdir(parents=True,exist_ok=True)
    text=json.dumps(doc,ensure_ascii=False,indent=2)+'\n'
    encoded=transform_fields(doc,'E');cipher=transform('E',[json.dumps(encoded,ensure_ascii=False).encode()])[0]
    assert transform_fields(json.loads(transform('D',[cipher])[0]))==doc
    (out/'expected.json').write_text(text);(out/'catalog.txt').write_bytes(cipher)
if __name__=='__main__':main()
