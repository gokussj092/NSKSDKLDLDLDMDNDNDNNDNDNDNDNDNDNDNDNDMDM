#!/usr/bin/env python3
"""Source-derived Phase G text schemes, deterministic ciphertext and golden JSON.

Shared file engines never replace distinct text-specific source handlers.
Unconfigured HAPP private RSA keys are a documented gated route, not success.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python import (
    renz, xor_family, text_legacy_protocols as legacy,
    text_structured_protocols as structured, falcon_links,npvt_links,
    wyrlite,wyrvpn,intvpn,juanscript,eut,slipnet,izph
)
from scripts.android_e_special_fixtures import encrypt_sources
from scripts.android_f_independent_fixtures import flex_fixture,izph_fixture
from tests.test_renz_family import profile_fixture

B=lambda b:base64.b64encode(b).decode()
DOC={"Server":"example.invalid","Port":443,"Enabled":False,"Notes":"Prueba 日本語"}
def js(x):return json.dumps(x,ensure_ascii=False,separators=(",",":")).encode()
def zero(data):return data+bytes(-len(data)%16)
def expect_obj(raw,source):
    result=source(raw)
    if not isinstance(result,str) or not result.strip():
        raise ValueError("Source failed: "+str(raw)[:90])
    try: return json.loads(result)
    except json.JSONDecodeError: return {"decodedText":result}

def build():
    vectors=[]
    def add(name,group,link,decoder,expected=None):
        if expected is None:expected=expect_obj(link,decoder)
        assert isinstance(expected,(dict,list)) and link
        vectors.append({"scheme":name,"group":group,"input":link,"expected":expected})
    for prefix,profile in renz.RENZ_TEXT_PROTOCOLS.items():
        clear=profile_fixture(profile,DOC).decode("ascii")
        add(prefix,"renz",prefix+clear,renz.decode_text)
    # XOR 10 prefixes: the original cipher is the same, including recursive
    # field values, regardless of suffix spelling.
    xor_key=xor_family.XORDecoder.XOR_KEY
    nested=bytes(v^xor_key[i%len(xor_key)] for i,v in enumerate(b"inner.example")).hex()
    for prefix in xor_family.SCHEMES:
        # BD NET's version-specific decoder intentionally opens only known
        # encrypted profile fields; other XOR-family engines decode any hex
        # string. Use a field that BD NET actually decrypts to compare genuine
        # Python/Android parity without loosening its unknown-field policy.
        nested_field="host" if prefix=="bdnet://" else "SNIHost"
        content=js({**DOC,nested_field:nested})
        token=bytes(v^xor_key[i%len(xor_key)] for i,v in enumerate(content)).hex()
        add(prefix,"xor",prefix+token,xor_family.decode_text)
    # Source-structured protocols; Base64, JSON and URL-decoding are NOT
    # encryption and are deliberately identified as plain text conversions.
    add("falcontunnel://import/","batch","falcontunnel://import/"+B(js(DOC)),
        falcon_links.decode_text)
    add("npvt-ssh://","batch","npvt-ssh://"+B(js({"details":
        "npvs1:"+B(b"CONNECT example.invalid")})),npvt_links.decode_text)
    add("dns://","batch","dns://"+B(js({"server":DOC["Server"]})),
        npvt_links.decode_text)
    add("npvs1:","batch","npvs1:"+B(js(DOC)),npvt_links.decode_text)
    add("slipnet://","structured","slipnet://"+B(js(DOC)),
        structured.decode_slipnet_plain)
    add("slipnet://plain","structured","slipnet://"+B(b"SSH example.invalid"),
        structured.decode_slipnet_plain)
    add("flex://","structured","flex://"+B(flex_fixture(1)),structured.decode_flex)
    add("flexnet://","structured","flexnet://"+B(flex_fixture(4,30)),
        structured.decode_flex)
    add("izph://","batch","izph://"+izph_fixture(3).decode(),izph.run
        if False else lambda s:izph.run(s.encode()))
    add("izphvpnpro://","batch","izphvpnpro://"+izph_fixture(3).decode(),
        lambda s:izph.run(s.encode()))
    # V2Box export, not the different locked= URL share.
    samples=encrypt_sources()
    add("v2box://","structured","v2box://"+samples["v2box_export.py"].decode(),
        structured.decode_v2box)
    add("wyrlite://","batch","wyrlite://"+samples["wyrlite.py"].decode(),
        lambda s:wyrlite.run(s.encode()))
    add("wyrvpnlite://","batch","wyrvpnlite://"+samples["wyrlite.py"].decode(),
        lambda s:wyrlite.run(s.encode()))
    add("wyrl://","batch","wyrl://"+samples["wyrlite.py"].decode(),
        lambda s:wyrlite.run(s.encode()))
    add("wyrvpn://","batch",samples["wyrvpn.py"].decode(),
        lambda s:wyrvpn.run(s.encode()))
    add("intvpn://","batch",samples["intvpn.py"].decode(),
        lambda s:intvpn.run(s.encode()))
    add("slipnet-enc://","batch",samples["slipnet.py"].decode(),
        lambda s:slipnet.run(s.encode()))
    for prefix in ("juanscript://","mobi://"):
        add(prefix,"batch",prefix+samples["juanscript.py"].decode(),
            lambda s:juanscript.run(s.encode()))
    add("eut-settings://","batch",samples["eut.py"].decode(),
        lambda s:eut.run(s.encode()))
    # Creeb retains entire source bundle and all links in profile/prefs.
    creeb={"type":"creeb_profile_bundle","version":3,"message":"hello",
        "security":{"locked":False},"profiles":[{
            "name":"demo","hostPort":"example.invalid:443","tunnelType":"v2ray",
            "prefs":{"server":"vless://test@host.invalid:443?type=ws",
                     "duplicate":"vless://test@host.invalid:443?type=ws"}}]}
    add("__creeb__","structured",js(creeb).decode(),structured.decode_creeb)
    # Alternative static NetMod key from newer text_legacy_protocols.py.
    for key_index,key in enumerate(legacy._NM_KEYS):
        cipher=AES.new(key,AES.MODE_ECB).encrypt(pad(js(DOC),16))
        add(f"nm-ss://key{key_index}","legacy","nm-ss://"+B(cipher),
            legacy.decode_netmod)
    # Extra scheme missing from initial Android text port.
    howdy={"username":"user","password":"pass","server":"node.example",
           "sni":"sni.example","port":443,"type":"ssh","extra":"preserve"}
    for field in ("server","sni"):
        howdy[field]=B(AES.new(legacy._HOWDY_KEY,AES.MODE_CBC,legacy._HOWDY_IV)
            .encrypt(zero(howdy[field].encode())))
    add("mark://","legacy","mark://"+B(js(howdy)),legacy.decode_howdy)
    clear=B(js(DOC)).encode()
    pb=AES.new(legacy._PB_KEY,AES.MODE_CBC,legacy._PB_IV).encrypt(zero(clear))
    add("pb-vmess://","legacy","pb-vmess://"+B(pb),legacy.decode_pb)
    return {"schemaVersion":1,"referenceSources":[
        "decoders/Python/renz.py","decoders/Python/xor_family.py",
        "decoders/Python/text_structured_protocols.py",
        "decoders/Python/text_legacy_protocols.py",
        "spdecode/handlers/config_batch_texts.py"],
        "renzCount":len(renz.RENZ_TEXT_PROTOCOLS),
        "xorCount":len(xor_family.SCHEMES),
        "vectorCount":len(vectors),
        "unavailableWithoutPrivateKeys":["happ://crypt/","happ://crypt2/",
            "happ://crypt3/","happ://crypt4/"],
        "vectors":vectors}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--fixtures",required=True,type=Path)
    a=p.parse_args()
    doc=build()
    a.fixtures.parent.mkdir(parents=True,exist_ok=True)
    a.fixtures.write_text(json.dumps(doc,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"[G] {doc['vectorCount']} original Python source text protocol vectors")
if __name__=="__main__":main()
