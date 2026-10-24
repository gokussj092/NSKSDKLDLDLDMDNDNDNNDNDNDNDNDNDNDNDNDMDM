"""Independent libsodium Argon2id + JDK AES-GCM reference and synthetic fixtures.

No production decoder imports. Verification output never prints private values.
"""
from __future__ import annotations
import base64
import ctypes
from ctypes.util import find_library
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EXPORT_PASSWORD = b"iOi/hqT/TocUv0UbDImfWPGR1mfSdzzX"
FIELD_PASSWORD = b"NewDecryptLibPassword"


def kdf(password, salt):
    lib = ctypes.CDLL(find_library("sodium"))
    lib.sodium_init()
    fn = lib.crypto_pwhash
    fn.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_char_p,
                   ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_ulonglong,
                   ctypes.c_size_t, ctypes.c_int]
    fn.restype = ctypes.c_int
    output = ctypes.create_string_buffer(32)
    if len(salt) != 16 or fn(output, 32, password, len(password), salt, 3, 16*1024*1024, 2):
        raise ValueError("Independent Argon2id failed")
    return output.raw


def aes_batch(lines):
    r = subprocess.run(["java", "-XX:-UsePerfData", str(ROOT/"tests/golden/mm_tunnel_aes.java")],
                       input="\n".join(lines)+"\n", text=True, capture_output=True, timeout=60)
    if r.returncode:
        raise ValueError("Independent JDK GCM failed")
    output = [base64.b64decode(s, validate=True) for s in r.stdout.splitlines()]
    if len(output) != len(lines):
        raise ValueError("Incomplete JDK output")
    return output


def seal(text, exported=False, counter=0):
    salt=bytes((i+counter)%256 for i in range(16))
    nonce=bytes((i+counter+91)%256 for i in range(12))
    key=kdf(EXPORT_PASSWORD if exported else FIELD_PASSWORD,salt)
    line="\t".join(["E",key.hex(),salt.hex(),nonce.hex(),base64.b64encode(text.encode()).decode()])
    encoded=base64.b64encode(salt+nonce+aes_batch([line])[0]).decode()
    return encoded[:3]+"Q"+encoded[3:] if exported else encoded


def open_many(values):
    """Each value is (ciphertext, exported); decrypt complete texts in one JDK call."""
    lines=[]
    for text, exported in values:
        if exported:
            text=text[:3]+text[4:]
        raw=base64.b64decode(text.replace("\r","").replace("\n",""),validate=True)
        key=kdf(EXPORT_PASSWORD if exported else FIELD_PASSWORD,raw[:16])
        lines.append("\t".join(["D",key.hex(),raw[:16].hex(),raw[16:28].hex(),base64.b64encode(raw[28:]).decode()]))
    return [b.decode() for b in aes_batch(lines)]


def generate():
    inner=seal("GET /日本 HTTP/1.1\r\nHost: example.invalid\r\n\r\n",counter=3)
    address=seal("vpn.example.invalid",counter=4)
    profile={"Name":"Prueba 日本語","TunnelType":"SSH","Payload":inner,
             "SNI":"plain.example.invalid","URI":None,"ProxyPort":"8080","Enabled":False,
             "future":{"list":[0,False,None,"keep"],"passwordHash":"synthetic metadata"}}
    expected=dict(profile,Payload="GET /日本 HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
    catalog={"Version":"test.45","Servers":[{"Name":"synthetic","ServerIPHost":address,"SSH_Port":"22"}],
             "Networks":[profile],"ReleaseNotes":"Prueba","DefOVPNPass":seal("",counter=8)}
    expected_catalog=dict(catalog,Servers=[dict(catalog['Servers'][0],ServerIPHost="vpn.example.invalid")],
                          Networks=[expected],DefOVPNPass="")
    docs=[]
    for kind,outer,expect in [("file",profile,expected),("catalog",catalog,expected_catalog)]:
        plain=json.dumps(outer,ensure_ascii=False,separators=(",",":"))
        for mode in ("export","eo","plain"):
            wire=plain if mode=="plain" else seal(plain,mode=="export",counter=len(docs)+10)
            docs.append({"kind":kind,"mode":mode,"wire":wire,"outer":outer,"expected":expect})
    return {"documents":docs,"kdf":{"password":"synthetic test key","saltHex":bytes(range(16)).hex(),
                                   "keyHex":kdf(b"synthetic test key",bytes(range(16))).hex()}}


if __name__ == "__main__":
    print(json.dumps(generate(),ensure_ascii=False,indent=2))
