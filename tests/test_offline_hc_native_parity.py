"""Differential validation of native C++ HCX4 against independent Python goldens."""
from __future__ import annotations
import json
import struct
import subprocess
import sys
from pathlib import Path
import importlib.util
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
spec = importlib.util.spec_from_file_location("native_hc_fixture", root / "tests/golden/http_custom_899.py")
assert spec is not None and spec.loader is not None
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
make_file, PASSWORD, HWID = fixture.make_file, fixture.PASSWORD, fixture.HWID
from decoders.Python.apps.HTTP_Custom.codec import decrypt

def call(exe, data: bytes, password="", hwid=""):
    fields=(password.encode(),hwid.encode(),data)
    frames=b"".join(struct.pack(">I",len(x))+x for x in fields)
    return subprocess.run([exe], input=frames,capture_output=True,check=False)

def check(condition, message):
    if not condition: raise AssertionError(message)


def legacy_http_custom_old_file(*, nested=False):
    """Synthetic old-style HC: legacy ChaCha8, JKL, Braille SSH and z3a."""
    import base64
    from Crypto.Cipher import ChaCha20
    from decoders.Python.HTTPCUSTOM import HCConstants

    def encrypt_hex(text, key, nonce=HCConstants.STATIC_NONCE):
        cipher=ChaCha20.new(key=key,nonce=nonce)
        cipher.seek(64)
        return (cipher.encrypt(text.encode("utf-8"))+bytes(16)).hex()

    def jkl_old(clear: str) -> str:
        internal=base64.b64encode(clear.encode("utf-8"))
        keyed=bytes(b ^ HCConstants.JKL_KEY_OLD[i%20] for i,b in enumerate(internal))
        return base64.b64encode(keyed).decode("ascii")

    alphabet=HCConstants.BRAILLE_ALPHABET
    def to_braille(clear: str) -> str:
        return "".join(alphabet[b//16]+alphabet[b%16] for b in clear.encode("utf-8"))

    def z3a(clear: str) -> str:
        count=len(clear)
        return ",".join(f"{ord(letter)+count}.{count}" for letter in clear)

    tokens=[""]*(32 if nested else 12)
    # Original historical field encryption chain:
    # ChaCha8(field key 7, static nonce) -> JKL(legacy) -> text.
    tokens[0]=encrypt_hex(jkl_old("GET / HTTP/1.1"),HCConstants.CHACHA_KEYS[7])
    tokens[1]="example.org"
    if nested:
        # A valid Boolean can be accidentally Base64-decoded to non-UTF8 by
        # the old standalone port; Python leaves it as "true".
        tokens[2]="true"
        tokens[5]="true"
        tokens[13]="true"
    tokens[7]=to_braille("vpn.example:443@"+z3a("user")+":"+z3a("pass"))
    tokens[11]=z3a("open")+":"+z3a("vpn")
    sep=("a1b2c3d4e5f6"*8) if nested else "[splitConfig]"
    clear=sep.join(tokens)
    old=({"a":{"xy":encrypt_hex(clear,HCConstants.CHACHA_KEYS[1]),
                "uv":sep,"yz":"synthetic-metadata"},
          "b":"synthetic-profile"} if nested else
         {"a":{},"xy":encrypt_hex(clear,HCConstants.CHACHA_KEYS[1]),"uv":sep})
    encoded=encrypt_hex(json.dumps(old,separators=(",",":")),HCConstants.CHACHA_KEYS[5]).encode()
    key=bytes.fromhex("e382e4b8adc386f09f9293")
    source=bytes(b ^ key[i%len(key)] for i,b in enumerate(encoded))
    return source.decode("latin-1").encode("utf-8")



def legacy_http_custom_field_file(style: str) -> bytes:
    """Independent full historic exporter for separated hex or Latin1 field."""
    import base64
    from Crypto.Cipher import AES,ChaCha20
    from Crypto.Util.Padding import pad
    from decoders.Python.HTTPCUSTOM import HCConstants
    assert style in ("separated_hex","latin1","utf8_ignored")
    inner=base64.b64encode(b"GET / HTTP/1.1")
    xored=bytes(value ^ HCConstants.JKL_KEY_OLD[i%20] for i,value in enumerate(inner))
    token=base64.b64encode(xored)
    cha=ChaCha20.new(key=HCConstants.CHACHA_KEYS[7],nonce=HCConstants.STATIC_NONCE)
    cha.seek(64)
    # Historical Python deliberately ignores malformed UTF-8 after ChaCha.
    # The old C++ heuristic accepted these random bytes then failed JSON dump.
    plaintext=b"\xffGET / HTTP/1.1\xc0\xaf" if style=="utf8_ignored" else token
    encrypted=cha.encrypt(plaintext)+bytes(16)
    if style=="separated_hex":
        raw=encrypted.hex()
        field=":".join(raw[i:i+10] for i in range(0,len(raw),10))
    elif style=="latin1":
        field=encrypted.decode("latin-1")
    else:
        field=encrypted.hex()
    plain="[splitConfig]".join((field,"example.org","false")).encode("utf8")
    aes=AES.new(HCConstants.RST_KEYS[0],AES.MODE_ECB)
    crypt=base64.b64encode(aes.encrypt(pad(plain,16)))
    content=bytes(v ^ HCConstants.RST_XOR_KEY[i%20] for i,v in enumerate(crypt)).decode("ascii")
    outer=json.dumps({"cfg":{"content":content}},separators=(",",":")).encode()
    cipher=ChaCha20.new(key=HCConstants.CHACHA_KEYS[5],nonce=HCConstants.STATIC_NONCE)
    cipher.seek(64)
    outer_hex=(cipher.encrypt(outer)+bytes(16)).hex().encode("ascii")
    key=bytes.fromhex("e382e4b8adc386f09f9293")
    masked=bytes(x ^ key[i%len(key)] for i,x in enumerate(outer_hex))
    return masked.decode("latin-1").encode("utf8")

def hccfg_early_hwid_file(schema: int, password: str | None = None):
    """Build historical HCCFG n2 with authenticated HWID slots independently."""
    import hashlib
    from Crypto.Cipher import ChaCha20_Poly1305
    from decoders.Python import _hc_hccfg as hc
    from tests.golden.hc_sip_new_variants import SYNTHETIC_HWID
    from argon2.low_level import Type,hash_secret_raw

    def sealed(key,nonce,aad,plaintext):
        cipher=ChaCha20_Poly1305.new(key=key,nonce=nonce)
        cipher.update(aad)
        ciphertext,tag=cipher.encrypt_and_digest(plaintext)
        return ciphertext+tag
    seed=bytes(range(32))
    nonce_outer=bytes(range(48,72))
    nonce_slot=bytes(range(72,96))
    nonce_main=bytes(range(24))
    env={"a":"HCCFG","b":schema,
         "c":"XCHACHA20P1305" if schema==1 else "s1",
         "d":"NATIVE-HKDF-SHA256" if schema==1 else "h1",
         "e":"n2","f":["ssh","profiles"],"g":seed.hex(),
         "h":int(password is not None),"n":760}
    if password is not None:env.update({"k":"ARGON2ID13","l":2,"m":8*1024*1024})
    hw=SYNTHETIC_HWID.encode()
    transcript=(b"HCCFG\0"+hc.PKG+b"\0"+b"1\0ssh,profiles\0"+b"760\0"+
                b"hwid\0"+hw+b"\0"+seed)
    ikm=hashlib.sha256(hc.C0_PREFIX+transcript).digest()
    protection=b"|0"
    if password is not None:
        ikm+=hash_secret_raw(password.encode(),seed[:16],time_cost=2,
             memory_cost=8192,parallelism=1,hash_len=32,type=Type.ID,version=19)
        protection=b"|1|ARGON2ID13|2|8388608"
    info=b"app-config|n2|"+hc.PKG+b"|1|ssh,profiles|760|hwid|"+hw
    wrapped=hc._hkdf(ikm,seed,info)
    aad=(b"HCCFG|"+str(schema).encode()+b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|n2|"+
         hc.PKG+b"|1|ssh,profiles"+protection+b"|760")
    section_key=bytes(reversed(range(32)))
    env["o"]=[{"a":nonce_slot.hex(),"b":sealed(wrapped,nonce_slot,aad+b"\0w",section_key).hex()}]
    env["i"]={"a":"m0","b":nonce_main.hex(),
              "c":sealed(section_key,nonce_main,aad+b"\0m0",b'{"g":{"a":"free"}}').hex()}
    # A single authenticated historical HPC1, no untrusted decrypted data.
    from tests.golden.hc_sip_new_variants import hpc1,NONCE_PROFILE
    env["j"]=[{"a":"s0","b":NONCE_PROFILE.hex(),
              "c":sealed(section_key,NONCE_PROFILE,aad+b"\0s0",hpc1()).hex()}]
    assert hc._derive(env,password,SYNTHETIC_HWID)==(section_key,aad)
    return nonce_outer+sealed(hc._outer_key(),nonce_outer,hc.OUTER_AAD,
        json.dumps(env,separators=(",",":")).encode("utf-8"))

def main(exe):
    from decoders.Python.HTTPCUSTOM import HCDecryptor
    passed=0
    for locked in (False,True):
        for protected in (False,True):
            password=PASSWORD if protected else ""
            hwid=HWID if locked else ""
            for carrier in (0,1,2):
                source=make_file(locked=locked,protected=protected,carrier=carrier)
                expected=decrypt(source,password=password or None,hwid=hwid or None)
                result=call(exe,source,password,hwid)
                check(result.returncode==0,(locked,protected,carrier,result.stderr.decode()[:200]))
                actual=json.loads(result.stdout)
                check(actual==expected,(locked,protected,carrier,actual,expected))
                passed+=1
            # Correct keys must reject altered tags in every authenticated layer.
            for where in ("outer","slot","main","profile","hpr","sidecar"):
                if where=="slot" and not locked:continue
                bad=call(exe,make_file(locked=locked,protected=protected,tamper=where),password,hwid)
                check(bad.returncode!=0,(locked,protected,where,"tampered ciphertext accepted"))
                passed+=1
            if protected:
                bad=call(exe,make_file(locked=locked,protected=protected),"incorrect password",hwid)
                check(bad.returncode!=0,"wrong password accepted")
                passed+=1
                missing=call(exe,make_file(locked=locked,protected=protected),"",hwid)
                check(missing.returncode!=0,"missing password accepted")
                passed+=1
            if locked:
                bad=call(exe,make_file(locked=locked,protected=protected),password,"B"*32)
                check(bad.returncode!=0,"wrong HWID accepted")
                passed+=1
                missing=call(exe,make_file(locked=locked,protected=protected),password,"")
                check(missing.returncode!=0,"missing HWID accepted")
                passed+=1
    # Historical HCCFG n1/n7 and v3 n8 HWID/dual-credential envelopes.
    # These are independent of the build-899 HCX4 nonce/prestate KDF.
    from tests.golden.hc_sip_new_variants import (
        hccfg_file, hccfg_hwid_file, SYNTHETIC_HWID, S4_SYNTHETIC_PASSWORD)
    from decoders.Python import _hc_hccfg as historical
    for schema,schedule in ((1,"n1"),(2,"n1"),(5,"n1"),(7,"n7")):
        for protected in (False,True):
            pw=S4_SYNTHETIC_PASSWORD if protected else ""
            source=hccfg_file(schema=schema,schedule=schedule,password=pw or None)
            ref=historical.decrypt(source,password=pw or None)
            result=call(exe,source,pw,"")
            check(result.returncode==0,(schema,schedule,protected,result.stderr.decode(errors="replace")[:300]))
            check(json.loads(result.stdout)==ref,(schema,schedule,protected,"historical mismatch"))
            passed+=1
    for protected in (False,True):
        pw=S4_SYNTHETIC_PASSWORD if protected else ""
        source=hccfg_hwid_file(password=pw or None)
        expected=historical.decrypt(source,password=pw or None,hwid=SYNTHETIC_HWID)
        result=call(exe,source,pw,SYNTHETIC_HWID)
        check(result.returncode==0,(protected,result.stderr.decode(errors="replace")[:300]))
        check(json.loads(result.stdout)==expected,(protected,"HWID/dual mismatch"))
        passed+=1
        for layer in ("slot","main","profile","hpr1","sidecar"):
            invalid=call(exe,hccfg_hwid_file(password=pw or None,tamper_layer=layer),pw,SYNTHETIC_HWID)
            check(invalid.returncode!=0,("historical tamper accepted",layer))
            passed+=1
        for wrongpw,wronghwid in ((pw,"B"*32),("bad" if pw else pw,SYNTHETIC_HWID)):
            if wrongpw==pw and wronghwid==SYNTHETIC_HWID:continue
            invalid=call(exe,source,wrongpw,wronghwid)
            check(invalid.returncode!=0,("historical wrong credential accepted"))
            passed+=1
    # Historical n2 HWID handling for schema 1,2,5,7 was missing from
    # the previous matrix; compare each against the actual server Python.
    for schema in (1,2,5,7):
        for protected in (False,True):
            pw=S4_SYNTHETIC_PASSWORD if protected else ""
            sample=hccfg_early_hwid_file(schema,pw or None)
            expected=historical.decrypt(sample,password=pw or None,hwid=SYNTHETIC_HWID)
            native=call(exe,sample,pw,SYNTHETIC_HWID)
            check(native.returncode==0,(schema,"n2",native.stderr.decode(errors="replace")[:250]))
            check(json.loads(native.stdout)==expected,(schema,"n2","mismatch"))
            check(call(exe,sample,pw,"B"*32).returncode!=0,(schema,"incorrect HWID accepted"))
            check(call(exe,sample,pw,"").returncode!=0,(schema,"missing HWID accepted"))
            passed+=3
    # Real-world bug signature without embedding any user sample:
    # nested a.xy/a.uv, 31 separators, old true flags. The historical
    # Python reader rejects invalid UTF-8 intermediate JKL bytes instead
    # of corrupting the entire JSON result.
    nested=legacy_http_custom_old_file(nested=True)
    nested_reference=HCDecryptor.execute(nested)
    check(nested_reference is not None and "lockAllConfig" in nested_reference,
          "nested old-format Python reference should decode")
    nested_result=call(exe,nested)
    check(nested_result.returncode==0,
          ("nested old format failed",nested_result.stderr.decode(errors="replace")[:250]))
    nested_json=json.loads(nested_result.stdout)
    check(nested_json["Config"]["lockAllConfig"]=="true",
          "old boolean flag was corrupted during JKL UTF-8 decoding")
    check(nested_json["Config"]["noteEnabled"]=="true",
          "old note flag was corrupted during JKL UTF-8 decoding")
    check(nested_json["Config"]["payload"]=="GET / HTTP/1.1",
          "old protected payload regression")
    passed+=1
    # The Python legacy decoder has an additional historical Braille SSH
    # credential stage, which previously was absent from the standalone APK.
    old=legacy_http_custom_old_file()
    legacy_ref=HCDecryptor.execute(old)
    check(legacy_ref is not None and "vpn.example:443@user:pass" in legacy_ref,
          "legacy reference must decode Braille and numeric SSH fields")
    native=call(exe,old)
    check(native.returncode==0,native.stderr.decode(errors="replace")[:250])
    legacy=json.loads(native.stdout)
    check(legacy["Config"]["payload"]=="GET / HTTP/1.1","old JKL payload chain mismatch")
    check(legacy["Config"]["sshField"]=="vpn.example:443@user:pass",
          "old Braille SSH credentials mismatch")
    check(legacy["Config"]["ovpnUserAndPass"]=="open:vpn",
          "old numeric OVPN credentials mismatch")
    passed+=1
    for style in ("separated_hex","latin1","utf8_ignored"):
        sample=legacy_http_custom_field_file(style)
        reference=HCDecryptor.execute(sample)
        check(reference is not None and "GET / HTTP/1.1" in reference,
              ("historic Python field candidate failed",style))
        result=call(exe,sample)
        check(result.returncode==0,(style,result.stderr.decode(errors="replace")[:250]))
        actual=json.loads(result.stdout)
        check(actual["Config"]["payload"]=="GET / HTTP/1.1",
              ("historic field variant not decoded",style,actual["Config"].get("payload")))
        passed+=1
    # Reuse the existing, independently validated A.2.3 XOR + ChaCha8 +
    # RST AES golden instead of trusting newly invented exporter bytes.
    from tests.golden.a23_generators import httpcustom_bytes
    from decoders.Python.HTTPCUSTOM import HCDecryptor
    original=httpcustom_bytes()
    reference=HCDecryptor.execute(original)
    check(reference is not None and "example.org" in reference,
          "The known Python historical HC golden must decode")
    native=call(exe,original)
    check(native.returncode==0,native.stderr.decode(errors="replace")[:200])
    result=json.loads(native.stdout)
    check(result["Config"]["payload"]=="GET","Legacy HC payload mismatch")
    check(result["Config"]["proxy"]=="example.org","Legacy HC proxy mismatch")
    passed+=1
    for invalid in (b"",b"invalid","".encode()+b"\xff"*45):
        check(call(exe,invalid).returncode!=0,"invalid input accepted")
        passed+=1
    from tests.test_hc_legacy57 import native_parity
    passed+=native_parity(exe)
    print(f"PASS: native HCX4 and legacy Python parity / tamper checks: {passed} cases")

if __name__=="__main__":
    main(sys.argv[1])
