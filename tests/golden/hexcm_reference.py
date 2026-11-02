#!/usr/bin/env python3
"""Rebuild synthetic .hexcm fixtures with JDK JCA, without importing the reader."""
import json
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent

def main():
    cases=[]
    with tempfile.TemporaryDirectory(prefix='hexcm-jca-') as folder:
        temp=Path(folder)
        subprocess.run(['java','com.sun.tools.javac.Main','-d',str(temp),str(HERE/'hexcm_oracle.java')],check=True)
        def oracle(*args):
            subprocess.run(['java','-cp',str(temp),'HexcmOracle',*map(str,args)],check=True)
        profiles = [
            ('open', {'blocked': False}),
            ('locked', {'blocked': True}),
            ('id', {'blocked': True, 'blockId': True,
                    'blockIdValue': '0123456789abcdef0123456789abcdef'}),
            ('carrier', {'blocked': True, 'blockCompany': True}),
            ('id-carrier', {'blocked': True, 'blockId': True, 'blockCompany': True,
                            'blockIdValue': '0123456789abcdef0123456789abcdef'}),
            ('login-id', {'blocked': True, 'loginById': True,
                          'loginByIdValue': '0123456789abcdef0123456789abcdef'}),
        ]
        for label, metadata in profiles:
            unsigned={'version':1,'server':{'name':'Prueba 🔐','serverType':1,'tunnelType':2,
                'serverIp':'vpn.example.invalid','serverPort':22,'user':'synthetic',
                'password':'fixture-only','payload':'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
                'future':{'array':[None,False,1234567890123,1.25],'unicode':'ñ / 漢字\u0000'}},
                'meta':{'blocked':False,'blockRoot':False,'blockCompany':False,'countryIso':'mx',
                'company':'TEST','exportedAt':1700000000000,'expiresAt':0,'blockId':False,
                'loginById':False,'useUuid':False},'unknownRoot':['preserve',True]}
            unsigned['meta'].update(metadata)
            # Android JSONStringer escapes forward slash. Keep its exact lexemes.
            raw=json.dumps(unsigned,ensure_ascii=False,separators=(',',':')).replace('/','\\/').encode()
            src=temp/'unsigned.json';signed=temp/'signed.json';wire=temp/'profile.hexcm'
            src.write_bytes(raw);oracle('sign',src,signed)
            expected=json.loads(signed.read_bytes())
            for variant in ('single','double'):
                oracle('encrypt',variant,signed,wire)
                reference=temp/'roundtrip.json';oracle('decrypt',wire,reference)
                assert reference.read_bytes()==signed.read_bytes()
                cases.append({'name':f'{variant}-{label}','variant':variant,
                    'wire':wire.read_text(),'expected':expected})
            oracle('encrypt','double-bad-tag',signed,wire)
            cases.append({'name':f'inner-tag-{label}','reject':True,'wire':wire.read_text()})
        for name,body in [('signature','{"version":1,"server":{"name":"x"},"meta":{"blocked":false},"signature":"'+'0'*64+'"}'),
                ('duplicate','{"version":1,"server":{"name":"x"},"meta":{"blocked":false,"blocked":true}}'),
                ('nonfinite','{"version":1,"server":{"x":NaN},"meta":{"blocked":false}}'),
                ('version','{"version":2,"server":{"name":"x"},"meta":{"blocked":false}}')]:
            src.write_text(body)
            if name!='signature':oracle('sign',src,signed)
            else:signed.write_text(body)
            oracle('encrypt','single',signed,wire)
            cases.append({'name':name,'reject':True,'wire':wire.read_text()})
    (HERE/'hexcm_vectors.json').write_text(json.dumps({'producer':'JDK 17 JCA PBKDF2/AES-GCM/ChaCha20-Poly1305/SHA-256',
        'realUserFilesIncluded':False,'documents':cases},ensure_ascii=False,indent=2)+'\n')
    print(f'{len(cases)} independent fixtures generated')

if __name__=='__main__':main()
