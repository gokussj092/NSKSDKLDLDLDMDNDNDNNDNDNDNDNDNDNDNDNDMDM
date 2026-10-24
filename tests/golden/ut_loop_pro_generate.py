"""Generate public synthetic fixtures using the independent JDK reference only."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent

def main():
    with tempfile.TemporaryDirectory() as tmp:
        def oracle(mode,data,*args):
            r=subprocess.run(['java',str(HERE/'ut_loop_pro_oracle.java'),mode,*args],input=base64.b64encode(data).decode()+'\n',text=True,capture_output=True,check=True)
            return r.stdout.splitlines()
        expected={'Version':'synthetic-1','Message':'Prueba 日本語 🔒','Servers':[
            {'Name':'all types','SSHHost':'ssh.example.test','SSHPort':'22','DropBear':'443','SSLPort':443,
             'PublicKey':'synthetic-key','NameServer':'dns.example.test','OpenVPNHost':'vpn.example.test',
             'UDPPort':'7300','UDPCertificate':'test certificate','Flag':'default','ProxyPort':'8080',
             'HUDPHost':'udp.example.test','HUDPPort':'9000','ServerEntry':'full entry','V2Ray':'vmess://test',
             'Trojan':'trojan://test','Vless':'vless://test','HostKey':'test-host-key','DNSHostKey':'dns-key',
             'Premium':True,'Stub':True,'unknown':{'list':[None,False,1,1.5,'']}},
            {'Name':'all types','SSHHost':'duplicate.example.test','empty':''}],
            'Tweaks':[{'Name':'all modes','Direct':False,'SSL':True,'Websocket':True,'Bug':'sni.example.test',
             'DNS':True,'DNSAddress':'dns.example.test','DNSMode':'doh','DoHUrl':'https://dns.example.test/dns-query',
             'DNSEngine':'vaydns','DNSWorkers':2,'UDP':True,'FastDNS':True,'HUDP':True,'HUDP2':True,
             'WG':True,'Vmess':True,'Trojan':True,'Vless':True,'Payload':'GET / HTTP/1.1\r\n\r\n',
             'CustomProxy':True,'ProxyHost':'proxy.example.test','ProxyPort':8080,'Port':'443','Flag':'default'}],
            'MinVersion':65,'PremiumRev':'separate','unknownRoot':[0,None,False,{'untouched':''}]}
        plain=json.dumps(expected,ensure_ascii=False,separators=(',',':')).encode()
        encrypted=oracle('seal',plain)[0]
        assert base64.b64decode(oracle('open',base64.b64decode(encrypted))[0])==plain
        def sign(blob):
            pub,sig=oracle('sign',blob.encode());return pub,{'data':blob,'sig':sig,'unknownEnvelope':{'keep':'signature covers data'}}
        pub,envelope=sign(encrypted)
        corrupt=bytearray(base64.b64decode(encrypted));corrupt[-1]^=1
        _,bad_tag=sign(base64.b64encode(corrupt).decode())
        bad_doc=oracle('seal',b'{"Version":"1","Servers":"invalid"}')[0]
        _,bad_schema=sign(bad_doc)
        banner='SYNTHETIC banner 日本語\r\nall text preserved'
        banners=[]
        for slot in ('0','1'):
            raw=oracle('banner-seal',banner.encode(),slot)[0]
            assert base64.b64decode(oracle('banner-open',base64.b64decode(raw),slot)[0]).decode()==banner
            banners.append('<div title="'+raw+'">x</div>')
        legacy=oracle('legacy-seal',banner.encode())[0]
        assert base64.b64decode(oracle('legacy-open',base64.b64decode(legacy))[0]).decode()==banner
        fixtures={'provenance':'Independent JDK JCA and APK custom-delta XXTEA reference; synthetic signer rejected by production',
                  'expected':expected,'cached':encrypted,'signed':envelope,'testPublicKey':pub,
                  'badTagSigned':bad_tag,'badSchemaSigned':bad_schema,'bannerExpected':banner,
                  'banners':banners,'legacyBanner':'<div title="'+legacy+'">legacy</div>'}
        (HERE/'ut_loop_pro_vectors.json').write_text(json.dumps(fixtures,ensure_ascii=False,indent=2)+'\n')
        print('Independent JDK synthetic vectors generated')

if __name__=='__main__':main()
