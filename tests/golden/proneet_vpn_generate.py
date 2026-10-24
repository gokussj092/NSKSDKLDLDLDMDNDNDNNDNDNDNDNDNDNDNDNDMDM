"""Generate synthetic ProNeet fixtures with JDK, without importing the decoder."""
import base64
import json
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parent
FIELDS=('ServerUser','ServerPass','ServerIP','ServerPort','ProxyIP','ProxyPort','SSLPort',
    'Payload','SNI','Slowchave','Nameserver','Slowdns','udpserver','udpauth','udpobfs',
    'udpbuffer','udpdown','udpup','v2rayJson','serverktun','portktun','userktun','passktun')


def oracle(commands):
    data=''.join(k+'\t'+base64.b64encode(v.encode()).decode()+'\n' for k,v in commands)
    p=subprocess.run(['java',str(ROOT/'proneet_vpn_oracle.java')],input=data,text=True,capture_output=True,check=True,timeout=30)
    out=[base64.b64decode(s).decode() for s in p.stdout.splitlines()];assert len(out)==len(commands);return out


def main():
    server={'Name':'Synthetic Perú 日本 🧪','FLAG':'EC','sInfo':'First\r\nSecond',
        **{k:'synthetic-'+k+'.example.invalid' for k in FIELDS},
        'Payload':'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
        'v2rayJson':'{"protocol":"vless","unknown":[null,true,3]}',
        'isSSL':True,'isCustomServer':False,'future':[None,False,2.5,''],'AuthToken':''}
    usuario={'Version':'synthetic-user-1','ReleaseNotes':'Unknown metadata retained','Servers':[
        server,{'Name':'Empty optional','SNI':''},{'Name':'Empty optional','SNI':''}],'future':{'keep':True}}
    token={'Version':'synthetic-token-2','Servers':[dict(server,Name='Token mode')],'future':False}
    copies=json.loads(json.dumps([usuario,token]));positions=[];commands=[]
    for di,doc in enumerate(copies):
        for i,item in enumerate(doc['Servers']):
            for key in FIELDS:
                if key in item:positions.append((di,i,key));commands.append(('field-encrypt',item[key]))
    for (di,i,key),value in zip(positions,oracle(commands)):copies[di]['Servers'][i][key]=value
    invalid=['{"Version":"x","Servers":[{"Name":"x"}],"a":1,"a":2}',
        '{"Version":"x","Servers":[{"Name":"x","SNI":"6"}]}',
        '{"Version":"x","Servers":[{"Name":"x","ServerIP":3}]}',
        '{"Version":"x","Servers":[]}','{"Version":"x","Servers":[1]}',
        '{"Version":"x","Servers":[{"Name":"x"}],"a":NaN}']
    ciphertext=oracle([('outer-encrypt',json.dumps(x,ensure_ascii=False)) for x in copies]+[('outer-encrypt',v) for v in invalid])
    values=['Latin AZaz','ñΩ中𐐀🧪','x'*15,'x'*16,'x'*17,'']
    fields=oracle([('field-encrypt',v) for v in values])
    result={'source':'Independent synthetic JDK ProNeet AESCrypt custom Base64/AES-CBC, no real accounts',
        'usuario':ciphertext[0],'token':ciphertext[1],'expectedUsuario':usuario,'expectedToken':token,
        'fields':[{'data':d,'expected':v} for d,v in zip(fields,values)],'invalid':ciphertext[2:]}
    (ROOT/'proneet_vpn_vectors.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')

if __name__=='__main__':main()
