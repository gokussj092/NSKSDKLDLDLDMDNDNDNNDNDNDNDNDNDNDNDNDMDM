"""Native-only NPV differential signed v1/v5/v6, legacy and text fixtures."""
from __future__ import annotations
import base64
import copy
import json
import struct
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from decoders.Python import npvs, npvs_v1, NPVTUNNEL, npvs_identity
from tests.test_npvs_v1_legacy import make_v1
from tests.golden.npvs_protected_generate import make
from decoders.Python.apps.NPV_Tunnel import text_decoder

def call(exe,raw,pw="",identity=""):
    parts=(pw.encode(),identity.encode(),raw)
    framed=b"".join(struct.pack(">I",len(v))+v for v in parts)
    return subprocess.run([exe],input=framed,capture_output=True)

def compare(exe,raw,expected,pw="",identity=""):
    result=call(exe,raw,pw,identity)
    if result.returncode:
        raise AssertionError(("decoder failed",result.stderr.decode(errors="replace")[:300]))
    actual=json.loads(result.stdout)
    assert actual==expected,("parity mismatch",actual,expected)

def negative(exe,raw,pw="",identity=""):
    r=call(exe,raw,pw,identity)
    assert r.returncode!=0,"Unauthenticated NPV input accepted"

def main(exe):
    count=0
    for protected in (False,True):
        inp,cred,plain=make_v1(passphrase=protected,embedded=True)
        pw=(cred or {}).get("password","")
        expected=npvs_v1.decode_npvs_v1_complete(inp,password=pw or None)
        compare(exe,inp,expected,pw)
        count+=1
        negative(exe,inp[:-1]+bytes([inp[-1]^1]),pw);count+=1
        if protected:
            negative(exe,inp,"bad-password");count+=1
            negative(exe,inp);count+=1
    identity=npvs_identity.generate()
    for version in (5,6):
        for recipient in (False,True):
            if version==6 and not recipient:continue
            fixture=make(recipient=recipient,version=version,identity=identity if recipient else None)
            pw="" if recipient else fixture["password"]
            ident=json.dumps(identity) if recipient else ""
            expected=npvs.decode_npvs_complete(fixture["data"],
                **({"recipient_key":identity} if recipient else {"password":pw}))
            compare(exe,fixture["data"],expected,pw,ident);count+=1
            negative(exe,fixture["data"][:-1]+bytes([fixture["data"][-1]^1]),pw,ident);count+=1
            if recipient:
                negative(exe,fixture["data"],pw,"");count+=1
                other=npvs_identity.generate()
                negative(exe,fixture["data"],pw,json.dumps(other));count+=1
            else:
                negative(exe,fixture["data"],"bad-password");count+=1
                negative(exe,fixture["data"]);count+=1
    # Authentic v5 app-key mode 2, built with the same NPF field body but a
    # separately signed app-key envelope. Confirms the 749,569-byte whitebox
    # native evaluator (the recipient-only v6 path does not exercise this KDF).
    from Crypto.Cipher import ChaCha20_Poly1305
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Signature import DSS
    import hashlib
    def seal(key, nonce, plain, aad):
        c=ChaCha20_Poly1305.new(key=key,nonce=nonce)
        c.update(aad)
        out,tag=c.encrypt_and_digest(plain)
        return out+tag
    base=make()
    raw=base["data"]
    oldh=int.from_bytes(raw[5:9],"big")
    oldhead=raw[9:9+oldh]
    nonce=raw[9+oldh:9+oldh+12]
    body=raw[9+oldh+16:-64]
    prefix=bytearray(oldhead[:53])
    prefix[50]=2
    cid=bytes(prefix[1:17])
    salt=bytes(range(16,32))
    kdk=hashlib.sha256(b"npvtunnel/appkey/v2 "+npvs._whitebox_block(salt)+cid).digest()
    wrapnonce=bytes(range(48,60))
    prefix.extend(b"\x00\x02"+salt+wrapnonce+seal(kdk,wrapnonce,base["dek"],salt))
    mkey=HKDF(base["dek"],32,nonce,SHA256,context=b"NPVS-v5/metadata")
    meta=seal(mkey,nonce,npvs._canonical(base["expectedRaw"]["metadata"]),bytes(prefix))
    header=bytes(prefix)+struct.pack(">I",len(meta))+meta
    unsigned=b"NPVS\x05"+struct.pack(">I",len(header))+header+nonce+struct.pack(">I",len(body))+body
    signed=unsigned+DSS.new(base["creator"],"deterministic-rfc6979",encoding="binary").sign(SHA256.new(unsigned))
    assert npvs.decode_npvs_complete(signed)==npvs.decode_npvs_complete(raw,password=base["password"])
    compare(exe,signed,npvs.decode_npvs_complete(signed));count+=1
    negative(exe,signed[:-1]+bytes([signed[-1]^1]));count+=1
    negative(exe,signed,"incorrect");count+=1
    # A signed NPV blob transported through any supported NPV URI must use
    # the same authenticated native codec, not a plaintext Base64 shortcut.
    envelope=b"npvt://"+base64.urlsafe_b64encode(signed).rstrip(b"=")
    compare(exe,envelope,npvs.decode_npvs_complete(signed));count+=1
    # Recipient mode also accepts an explicit file-bound, captured agreement.
    original=make(recipient=True,identity=identity)
    first=npvs.inspect_npvs(original["data"])["recipients"][0]
    from Crypto.PublicKey import ECC
    private=ECC.import_key(npvs_identity.binary(identity["privateKey"]))
    ephemeral=ECC.import_key(first[32:65],curve_name="P-256")
    shared=int((ephemeral.pointQ*private.d).x).to_bytes(32,"big")
    captured={
       "schema":"spdecode.npvs.recipient.v1",
       "kind":"agreement","source":"captured","curve":"P-256",
       "fingerprint":identity["fingerprint"],
       "fileSha256":hashlib.sha256(original["data"]).hexdigest(),
       "peer":npvs_identity.encode(first[32:65]),
       "sharedSecret":npvs_identity.encode(shared),
    }
    assert npvs.decode_npvs_complete(original["data"],recipient_key=captured)==npvs.decode_npvs_complete(original["data"],recipient_key=identity)
    compare(exe,original["data"],npvs.decode_npvs_complete(original["data"],recipient_key=identity),identity=json.dumps(captured))
    count+=1
    negative(exe,original["data"],identity=json.dumps(captured|{"fileSha256":"0"*64}))
    count+=1
    # Authenticated fields use a fixed mock nonce and inventory MAC; no partial
    # success when altering any tag or layout.
    obj={"configs":[{"host":"example.invalid","port":443,"nested":
        ["npvs1:"+base64.urlsafe_b64encode("日本語".encode()).decode().rstrip("="),False,None]}]}
    payload=json.dumps(obj,ensure_ascii=False,separators=(",",":")).encode()
    wrapped=b"npvt-ssh://"+base64.urlsafe_b64encode(payload).rstrip(b"=")
    compare(exe,wrapped,text_decoder.decode(wrapped.decode()));count+=1
    # Every server URI alias, case, alphabet and padding combination must
    # preserve full JSON and recursively decode explicit npvs1 layers.
    for prefix in text_decoder.PREFIXES:
        for encoder in (base64.b64encode,base64.urlsafe_b64encode):
            for padded in (False,True):
                for scheme in (prefix,prefix.upper()):
                    token=encoder(payload)
                    if not padded:token=token.rstrip(b"=")
                    link=b" \n"+scheme.encode()+token+b"\r\n"
                    compare(exe,link,text_decoder.decode(link.decode()));count+=1
    from decoders.Python import npvt_links
    for prefix in ("dns://","DNS://"):
        link=prefix.encode()+base64.urlsafe_b64encode(payload).rstrip(b"=")
        compare(exe,link,json.loads(npvt_links.decode_text(link.decode())));count+=1
    for source in (json.dumps(obj,ensure_ascii=False),"example.invalid"):
        link=b"npvs1:"+base64.urlsafe_b64encode(source.encode()).rstrip(b"=")
        decoded=npvt_links.decode_text(link.decode())
        expected=json.loads(decoded) if source.startswith("{") else {"decodedText":decoded}
        compare(exe,link,expected);count+=1
    # A failure inside an explicit encoded JSON object must not be swallowed
    # by a prose fallback, leaving an apparently successful partial result.
    bad_inner="npvs1:"+base64.b64encode(b'{"bad":"npvs1:!"}').decode()
    for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":"\xff"}',
                json.dumps({"x":bad_inner}).encode(),
                json.dumps({"x":"npvs1:/w=="}).encode()):
        link=b"npvt-ssh://"+base64.b64encode(raw)
        negative(exe,link);count+=1
    for link in (b"npvt://AAAA==",b"npvt://AB",b"npvs1:!",b"dns://!"):
        negative(exe,link);count+=1
    expected=[obj,obj,{"extra":"preserved"}]
    raw=json.dumps(expected,ensure_ascii=False).encode()
    link=b"npvt://"+base64.b64encode(raw)
    compare(exe,link,text_decoder.decode(link.decode()));count+=1
    negative(exe,b"npvt://!");count+=1
    for source in (b"NPVS",b"NPVT1,wrong,invalid",b"NOT-NPV"):
        negative(exe,source);count+=1
    # Historical whitebox CTR, deliberately synthetic and complete arrays.
    tables=NPVTUNNEL.load_whitebox_state()
    iv=bytes(range(16))
    plain=json.dumps([{"alpha":"example.org","x":None},{"beta":2}]).encode()
    stream=b"";counter=bytearray(iv)
    for i in range(0,len(plain),16):
        stream+=NPVTUNNEL.whitebox_encrypt_block(counter,*tables)
        for k in range(15,-1,-1):
            counter[k]=(counter[k]+1)&255
            if counter[k]:break
    payload=iv+bytes(a^b for a,b in zip(plain,stream))
    for prefix in (b"NPVT1",b"NPVTSUB1"):
        encrypted=prefix+b"meta,"+base64.urlsafe_b64encode(payload).rstrip(b"=")
        compare(exe,encrypted,json.loads(plain));count+=1
    print(f"PASS: NPV signed v1/v5/v6, ECDH, legacy and URI native parity: {count} cases")

if __name__=="__main__":main(sys.argv[1])
