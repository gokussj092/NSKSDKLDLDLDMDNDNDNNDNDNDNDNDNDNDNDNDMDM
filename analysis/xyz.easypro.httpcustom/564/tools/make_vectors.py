"""Create sanitized revision-57 fixtures using trusted libsodium, not the port.

The optional original ARM64 JNI oracle independently freezes build-564 local
XOR/Base64 primitives. No app binary or private profile enters generated data.
"""
import argparse,base64,ctypes,ctypes.util,gzip,hashlib,importlib.util,json,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT))
from decoders.Python.HTTPCUSTOM import HCConstants as C

KEY564=bytes.fromhex('edecebeae9e8e7e6e5e4050403020100fffefdfc')
KEY565=bytes.fromhex('edecebeae9e8e7e6e5e4d5d4d3d2d1d0cfcecdcc')
NONCE=bytes([219])*8

class Sodium:
    def __init__(self):
        self.library=ctypes.CDLL(ctypes.util.find_library('sodium'))
        self.library.sodium_version_string.restype=ctypes.c_char_p
        self.version=self.library.sodium_version_string().decode()
        self.function=self.library.crypto_aead_chacha20poly1305_encrypt
        self.function.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulonglong),ctypes.c_char_p,
            ctypes.c_ulonglong,ctypes.c_void_p,ctypes.c_ulonglong,ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p]
    def seal(self,plain,key,nonce):
        output=ctypes.create_string_buffer(len(plain)+16);length=ctypes.c_ulonglong()
        assert self.function(output,ctypes.byref(length),plain,len(plain),None,0,None,nonce,key)==0
        return output.raw[:length.value]

def encoded(text,build):
    raw=text.encode('utf-8')
    if build==565:raw=base64.b64encode(raw)
    key=KEY565 if build==565 else KEY564
    return base64.b64encode(bytes(v^key[i%20]for i,v in enumerate(raw)))

def make(sodium,*,build=565,hwid=True,area='',tamper=None,unresolved=False,empty_strings=False):
    host='AABBCCDDEEFF00112233445566778899AA'if hwid else ''
    material=host+host if host and not area else host+area
    nonce=bytearray(NONCE);raw=material.encode()[:8];nonce[:len(raw)]=raw
    cfg={'verApp':build,'isLoginHwid':False,'a':False,'b':host,'f':area,
         's':True,'t':False,'u':True,'future':{'empty':'','items':[0,None,False]}}
    tokens=['']*32
    tokens[0]='GET /fixture HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
    tokens[1]='proxy.example.invalid:8080'
    for index in (2,3,5,8,9,13,15,16,19,21,23,25,28):tokens[index]='false'
    tokens[4]='lifeTime';tokens[6]='Synthetic notes 日本語';tokens[18]='Synthetic fixture'
    tokens[7]='ssh.example.invalid:443@synthetic:password'
    tokens[10]='client\nremote ovpn.example.invalid 443\n# synthetic\n'
    tokens[11]='synthetic:password';tokens[12]='sni.example.invalid'
    tokens[14]='reserved-field-14';tokens[17]='{"syntheticPsiphon":true,"regions":[]}'
    tokens[20]='1';tokens[22]='reserved-field-22';tokens[24]='[splitPsiphon][splitPsiphon]'
    tokens[25]='true';tokens[27]=str(build)
    tokens[29]='dns.example.invalid';tokens[30]='synthetic-public-material';tokens[31]='1.1.1.1'
    tokens[26]=json.dumps({'inbounds':[{'protocol':'socks','port':1080}],
        'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'example.invalid',
        'port':443,'users':[{'id':'00000000-0000-0000-0000-000000000000'}]}]}}],
        'policy':{'levels':{'0':{'handshake':4}}},'unknown':[None,False,'é']},ensure_ascii=False)
    if empty_strings:
        for index in (0,7,10,11,12,17,29,30,31):tokens[index]=''
        tokens[6]='0123456789abcdef0123456789abcdef' # Plain note, not ciphertext.
    expected=dict(zip((C.TOKEN_MAP[i]for i in range(32)),tokens));wire=tokens.copy()
    for index in (0,7,10,11,12,17,26,29,30,31):
        value=tokens[index]
        body=encoded(value,build)if value else b''
        if tamper=='json'and index==26:body=encoded('not-json',build)
        if tamper=='utf8'and index==0:body=b'\xff'
        key=C.CHACHA_KEYS[3 if index>=29 else 2]
        sealed=sodium.seal(body,key,bytes(nonce))
        if tamper=='field'and index==26:sealed=sealed[:-1]+bytes([sealed[-1]^1])
        if index==17 and unresolved:sealed=bytes(range(16));expected[C.TOKEN_MAP[17]]=sealed.hex()
        wire[index]=sealed.hex()
    inner=sodium.seal('[splitConfig]'.join(wire).encode(),C.CHACHA_KEYS[1],NONCE)
    if tamper=='content':inner=inner[:-1]+bytes([inner[-1]^1])
    cfg['content']=inner.hex();outer={'cfg':cfg,'verCfg':57,'futureEnvelope':['kept',0]}
    if tamper=='schema':outer['verCfg']=58
    if tamper=='build':cfg['verApp']=999
    outer_plain=json.dumps(outer,separators=(',',':'),ensure_ascii=False).encode()
    seal=sodium.seal(outer_plain,C.CHACHA_KEYS[5],NONCE)
    if tamper=='metadata-tag':
        pos=outer_plain.index(b'"verApp":565')+len(b'"verApp":');altered=bytearray(seal)
        for i in range(3):altered[pos+i]^=outer_plain[pos+i]^ord('9')
        seal=bytes(altered)
    if tamper=='outer':seal=seal[:-1]+bytes([seal[-1]^1])
    xor=bytes.fromhex('e382e4b8adc386f09f9293');data=seal.hex().encode();data=bytes(v^xor[i%len(xor)]for i,v in enumerate(data))
    prot={}
    if host:prot['hwid']=host
    if area:prot['area']=area
    result={'Config':expected,'Protections':prot,
            'Metadata':{'config':{k:v for k,v in cfg.items()if k!='content'},'envelope':{'verCfg':57,'futureEnvelope':['kept',0]}},
            'UnresolvedFields':[{'index':17,'field':'psiphon','status':'encrypted_unresolved'}]if unresolved else []}
    return {'data':base64.b64encode(data).decode(),'expected':result,'tamper':tamper}

def main():
    p=argparse.ArgumentParser();p.add_argument('--native-library',type=Path);a=p.parse_args()
    sodium=Sodium();cases={}
    for build in (564,565):
        for hwid in (False,True):cases[f'build{build}-hwid{int(hwid)}']=make(sodium,build=build,hwid=hwid)
    cases['area']=make(sodium,area='synthetic-region')
    cases['unresolved']=make(sodium,unresolved=True)
    cases['empty-and-hex-notes']=make(sodium,empty_strings=True)
    for layer in ('outer','content','field','json','utf8','schema','build','metadata-tag'):cases['bad-'+layer]=make(sodium,tamper=layer)
    out=ROOT/'tests/golden/hc_legacy57.json'
    raw=json.dumps({'generator':'libsodium original 64-bit-nonce AEAD','sodium_version':sodium.version,'cases':cases},ensure_ascii=False,separators=(',',':')).encode()
    out.write_text(json.dumps({'encoding':'gzip+base64','sha256_uncompressed':hashlib.sha256(raw).hexdigest(),
        'payload':base64.b64encode(gzip.compress(raw,mtime=0)).decode()},indent=2)+'\n')
    print('fixture_cases',len(cases),'bytes',out.stat().st_size,'sha256',hashlib.sha256(out.read_bytes()).hexdigest())
    if a.native_library:
        spec=importlib.util.spec_from_file_location('hc564_native',Path(__file__).with_name('native_oracle.py'))
        oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
        vectors=[]
        for algorithm in (2,3,4):
            value=b'Native synthetic {"a":[1,null,true]}'
            result=oracle.Oracle(a.native_library).run(0xfe6c,value,0,algorithm)
            recovered=oracle.Oracle(a.native_library).run(0xfe6c,result,1,algorithm)
            assert recovered==value
            vectors.append({'algorithm':algorithm,'plaintext':value.decode(),'encoded':result.decode()})
        target=Path(__file__).parents[1]/'generated/native_codec_vectors.json'
        target.write_text(json.dumps({'source_sha256':hashlib.sha256(a.native_library.read_bytes()).hexdigest(),'jni_entry':'0xfe6c','vectors':vectors},indent=2)+'\n')
        print('original_jni_roundtrips',len(vectors))

if __name__=='__main__':main()
