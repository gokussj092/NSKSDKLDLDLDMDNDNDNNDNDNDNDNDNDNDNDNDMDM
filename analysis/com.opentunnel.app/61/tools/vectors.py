#!/usr/bin/env python3
"""Generate safe synthetic .tnl vectors with independent Java/JCA, never APK."""
import base64,json,subprocess,tempfile
from pathlib import Path
from xml.sax.saxutils import escape
def generate(properties=None):
    expected=properties or {'CONFIG_MODE':'3','sshServer':'vpn.example.invalid','sshPort':'22','sshUser':'','sshPass':'','sshCredsRedacted':'1','file.protection':'1','checkRoot':'1','HWID':'synthetic-device','file.validate':'0','proxyPayload':'GET /日本 HTTP/1.1\r\nHost: example.invalid\r\n\r\n','v2rayjson':'{"synthetic":true}','unknown':'ñ'}
    xml=('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n<properties><comment>synthetic</comment>'+''.join('<entry key="'+k+'">'+escape(v).replace('\r','&#13;')+'</entry>' for k,v in expected.items())+'</properties>').encode()
    with tempfile.TemporaryDirectory(prefix='open-oracle-') as folder:
        path=Path(folder)/'synthetic.xml';path.write_bytes(xml)
        r=subprocess.run(['java','-XX:-UsePerfData',str(Path(__file__).with_name('OpenOracle.java')),str(path)],capture_output=True,timeout=30)
    if r.returncode:raise ValueError('INDEPENDENT_JCA_FAILED')
    lines=r.stdout.decode().splitlines()
    if len(lines)!=3:raise ValueError('INDEPENDENT_VECTOR_COUNT')
    return {'expected':expected,'xml':xml.decode(),'documents':[{'mode':mode,'base64':line} for mode,line in zip(['dotted-gcm','opl2-gcm','legacy-unauthenticated'],lines)]}
if __name__=='__main__':print(json.dumps(generate(),ensure_ascii=False,indent=2))
