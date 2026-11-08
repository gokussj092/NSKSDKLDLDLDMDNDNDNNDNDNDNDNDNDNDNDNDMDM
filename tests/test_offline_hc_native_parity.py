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

def main(exe):
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
    # Independent historical XOR + original ChaCha20 (64-bit nonce) vectors.
    # Unlike HCX4 these exporters have no authenticated tag, so test structural
    # parsing and exact clear fields rather than claiming AEAD security.
    from Crypto.Cipher import ChaCha20
    from decoders.Python.HTTPCUSTOM import HCConstants, HCDecryptor
    def wrap_cha(clear, key):
        stream=ChaCha20.new(key=key,nonce=bytes([0xdb])*8)
        stream.seek(64)
        return (stream.encrypt(clear.encode("utf-8"))+bytes(16)).hex()
    for new in (False,True):
        tokens="GET / HTTP/1.1[splitConfig]proxy.example:1080"
        inner=wrap_cha(tokens,HCConstants.CHACHA_KEYS[1])
        doc={"cfg":{"content":inner}} if new else {"xy":inner,"uv":"[splitConfig]"}
        outside=wrap_cha(json.dumps(doc,separators=(",",":")),HCConstants.CHACHA_KEYS[5])
        clear=outside.encode("ascii")
        xor=bytes.fromhex("e382e4b8adc386f09f9293")
        logical=bytes(c^xor[i%len(xor)] for i,c in enumerate(clear))
        original=logical.decode("latin1").encode("utf-8")
        reference=HCDecryptor.execute(original)
        check(reference is not None and "proxy.example:1080" in reference,
              "Python reference rejected historical synthetic vector")
        native=call(exe,original)
        check(native.returncode==0,(new,native.stderr.decode(errors="replace")[:200]))
        result=json.loads(native.stdout)
        check(result["Config"]["payload"]=="GET / HTTP/1.1","legacy payload differs")
        check(result["Config"]["proxy"]=="proxy.example:1080","legacy proxy differs")
        passed+=1
    for invalid in (b"",b"invalid","".encode()+b"\xff"*45):
        check(call(exe,invalid).returncode!=0,"invalid input accepted")
        passed+=1
    print(f"PASS: native HCX4 and legacy Python parity / tamper checks: {passed} cases")

if __name__=="__main__":
    main(sys.argv[1])
