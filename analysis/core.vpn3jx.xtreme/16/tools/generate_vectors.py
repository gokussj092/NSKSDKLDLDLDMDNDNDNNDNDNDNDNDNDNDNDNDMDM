#!/usr/bin/env python3
"""Generate owned deterministic fixtures with the independent Go oracle."""
import argparse,base64,copy,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.Wolf_Custom_VPN import codec_v16 as c
def main():
    p=argparse.ArgumentParser();p.add_argument("--oracle",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    fields={"DefOVPNUser":"owned-user","ServerIPHost":"owned.example.invalid","UUID":"owned-uuid",
        "Payload":"GET /owned HTTP/1.1\r\nHost: owned.example.invalid\r\n","SNI":"owned.example.invalid","V2rayConfig":"owned synthetic configuration"}
    seed=lambda b:base64.b64encode(b).decode()
    jobs=[{"Operation":"seal","Seed":seed(c.FIELD_SEED),"Value":seed(v.encode()),
        "Salt":seed(bytes(range(16))),"Nonce":seed(bytes(range(12))),"Transport":False} for v in fields.values()]
    def call(jobs):
        r=subprocess.run([str(a.oracle)],input="\n".join(json.dumps(j) for j in jobs)+"\n",text=True,capture_output=True,timeout=60)
        if r.returncode:raise ValueError("ORACLE_FAILED")
        out=[json.loads(s) for s in r.stdout.splitlines()]
        if len(out)!=len(jobs) or not all(r["OK"] for r in out):raise ValueError("ORACLE_FAILED")
        return [r["Value"] for r in out]
    cipher=dict(zip(fields,call(jobs)))
    expected={"Version":"owned-build16","DefOVPNUser":fields["DefOVPNUser"],
        "Servers":[{"Name":"Owned server","ServerIPHost":fields["ServerIPHost"],"SSH_Port":"22",
                    "V2ray":{"UUID":fields["UUID"],"port":443}}],
        "Networks":[{"Name":"Owned network","TunnelType":"V2RAY","Payload":fields["Payload"],
                     "SNI":fields["SNI"],"V2rayConfig":fields["V2rayConfig"],"URI":False,
                     "unknown":{"SNI":"preserve-unrecognized-position","array":[True,None,7]}}],
        "unknown":{"full":[False,None,"ñ"]}}
    packed=copy.deepcopy(expected);packed["DefOVPNUser"]=cipher["DefOVPNUser"]
    packed["Servers"][0]["ServerIPHost"]=cipher["ServerIPHost"];packed["Servers"][0]["V2ray"]["UUID"]=cipher["UUID"]
    for k in ("Payload","SNI","V2rayConfig"):packed["Networks"][0][k]=cipher[k]
    profile=copy.deepcopy(expected["Networks"][0]);packed_profile=copy.deepcopy(packed["Networks"][0])
    def outer(value,transport):
        return {"Operation":"seal","Seed":seed(c.CATALOG_SEED if transport else c.FIELD_SEED),
            "Value":seed(json.dumps(value,ensure_ascii=False).encode()),"Salt":seed(bytes(range(16))),
            "Nonce":seed(bytes(range(12))),"Transport":transport}
    bad=outer({},True);bad["Value"]=seed(bytes([255,128,0]))
    transport,embedded,profile_carrier,invalid_utf8=call([outer(packed,True),outer(packed,False),outer(packed_profile,True),bad])
    value={"origin":"OWNED_SYNTHETIC_GO_ORACLE","fieldPlain":fields,"fieldCipher":cipher,
        "catalogTransport":transport,"catalogEmbedded":embedded,"profileTransport":profile_carrier,
        "invalidUtf8Transport":invalid_utf8,"expected":expected,"expectedProfile":profile}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"syntheticFixture":True,"vectors":len(fields)+4}))
if __name__=="__main__":main()

