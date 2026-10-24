"""Regenerate synthetic OnSpace fixtures through JDK only; no reader imports."""
import base64
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parent
SERVER_FIELDS=('ServerIP','ProxyIP','ServerUser','ServerPass','Payload','SNI','Slowchave',
    'Nameserver','Slowdns','V2rayConfig','UdpServer','UdpObfs','UdpAuth','UdpDown','UdpUp','UdpBuffer')
USER_FIELDS=('Username','Password','Obfs','Auth','ID','Path')


def oracle(commands):
    data=''.join(command+'\t'+base64.b64encode(value.encode()).decode()+'\n' for command,value in commands)
    p=subprocess.run(['java',str(ROOT/'onspace_vpn_oracle.java')],input=data,text=True,capture_output=True,check=True,timeout=30)
    values=[base64.b64decode(v).decode() for v in p.stdout.splitlines()]
    assert len(values)==len(commands)
    return values


def main():
    servers={'Version':'synthetic-servers-25','Servers':[
        {'Name':'Prueba Perú 日本 🧪','ServerPort':'22','ProxyPort':'80','OtrasConfig':True,
         **{k:'synthetic-'+k+'.example.invalid' for k in SERVER_FIELDS},
         'Payload':'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
         'V2rayConfig':'{"outbounds":[{"protocol":"vless","future":true}]}',
         'unknown':'dGVzdA==','future':[None,False,2.5,'']},
        {'Name':'Empty optional','SNI':'','ServerIP':'example.invalid'},
        {'Name':'Sparse duplicate','SNI':''},{'Name':'Sparse duplicate','SNI':''}],
        'ReleaseNotes':'First\r\nSecond','future':{'keep':True}}
    users={'Version':'synthetic-users-9','Usuarios':[
        {'Name':'Synthetic user','**unknown**':False,**{k:'fixture-only-'+k for k in USER_FIELDS}},
        {'Name':'Empty values',**{k:'' for k in USER_FIELDS}}],'future':[None,True]}
    encrypted=[]
    for doc,section,fields in [(servers,'Servers',SERVER_FIELDS),(users,'Usuarios',USER_FIELDS)]:
        copy=json.loads(json.dumps(doc))
        for item in copy[section]:
            for key in fields:
                if key in item:item[key]=oracle([('field-encrypt',item[key])])[0]
        encrypted.append(oracle([('outer-encrypt',json.dumps(copy,ensure_ascii=False))])[0])
    invalid=['{"Version":"x","Servers":[],"a":1,"a":2}',
        '{"Version":"x","Servers":[{"Name":"x","ServerIP":"bad-cipher"}]}',
        '{"Version":"x","Servers":[1]}','{"Version":"x","Servers":[]}',
        '{"Version":"x","Servers":[{"Name":"x"}],"bad":NaN}',
        '{"Version":"x","Usuarios":[{"Name":"x","Password":3}]}']
    fields=[]
    for value in ('Latin AZ az 019 !','ñΩ中A𐐀🧪','GET /\r\n\r\n','a'*33):
        cipher,expected=oracle([('field-seal',value),('rotate',value)])
        fields.append({'data':cipher,'expected':expected})
    result={'source':'Synthetic independent JDK OnSpace APK AESCrypt/Trululu/Choco; no real catalog data',
        'servers':encrypted[0],'users':encrypted[1],'expectedServers':servers,'expectedUsers':users,
        'fields':fields,'invalid':oracle([('outer-encrypt',v) for v in invalid])}
    (ROOT/'onspace_vpn_vectors.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')

if __name__=='__main__':main()
