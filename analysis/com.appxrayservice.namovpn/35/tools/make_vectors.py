#!/usr/bin/env python3
"""Generate fictional catalogs with independent Java, not the Python decoder."""
import base64,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.NAMO_VPN.codec import FORMAT_KEY
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
        'Password':'sample-password','TCPPort':'443','setOpenVPN':'','V2Ray':'vless://fictional@example.org:443'}],
      'Networks':[{'PayloadName':'Fictional network','Sni':'front.example.org',
        'Payload':'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n','Protocal':'SSL','UnusualPlainHex':'deadbeef'}],
      'setOpenVPN':'','FutureMetadata':{'nested':[True,None,35]}}
    out=Path(__file__).resolve().parents[1]/'tests/fixtures';out.mkdir(parents=True,exist_ok=True)
    text=json.dumps(doc,ensure_ascii=False,indent=2)+'\n';cipher=transform('E',[text.encode()])[0]
    assert json.loads(transform('D',[cipher])[0])==doc
    (out/'expected.json').write_text(text);(out/'catalog.txt').write_bytes(cipher)
if __name__=='__main__':main()
