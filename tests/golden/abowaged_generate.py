#!/usr/bin/env python3
"""Regenerate ONLY synthetic AboWaged fixtures with the independent JDK oracle."""
from __future__ import annotations
import base64
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
# Independently transcribed from the APK's export/read sites, never production imports.
ROOT_FIELDS = "Version Message DefUpdateURL updater updatemsg Banner_ID AppOpenAd Interstitial_ID RewardAd_ID RewardInter_ID cardMessage cardLink".split()
SERVER_FIELDS = "SSHHost Category SSHPort SSLPort DropBear ProxyPort Username Password UDPServer Obfs Auth CFServer CFUser CFPass vuid vhost vpath wgConf vprotocol NameServer PublicKey DNSUsername DNSPassword WebServer WebUser WebPass".split()
TWEAK_FIELDS = "DNSHost Payload Sni ProxyHost ProxyPort v2Sni vport v2rayjson Bug".split()
FILE_FIELDS = "Payload WSPayload SNIHost BUGHost DNSHost ProxySet UDPhost UDPobfs UDPauth V2Ejson v2Esni EwgConf".split()


def oracle(operations):
    data="".join(op+"\t"+base64.b64encode(value).decode()+"\n" for op,value in operations)
    proc=subprocess.run(["java","-XX:-UsePerfData",str(HERE/"abowaged_oracle.java")],
                        input=data,text=True,capture_output=True,check=True,timeout=60)
    lines=proc.stdout.splitlines()
    if len(lines)!=len(operations):raise ValueError("Incomplete JDK oracle output")
    return [base64.b64decode(line,validate=True) for line in lines]


def encode_fields(obj,names,op):
    result=dict(obj);keys=[k for k in names if isinstance(obj.get(k),str)]
    values=oracle([(op,obj[k].encode()) for k in keys])
    for key,value in zip(keys,values):result[key]=value.decode()
    return result


def json_bytes(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()


def main():
    root={k:f"synthetic {k} 日本語 😀" for k in ROOT_FIELDS}
    root.update(Version="1.2.3",MyBool=True,unlimited=False,versioncode=1,addTime=0,
                unknown={"Payload":"ordinary Base64: YWJjZA==","list":[None,False,3.5,""]})
    server={k:f"synthetic {k} é\n" for k in SERVER_FIELDS}
    server.update(Name="Synthetic server",Flag="zz",Info="plain text",NoobLevel=0,vgrpc=False,
                  unknown={"Password":"untouched"},CFPass="",WebPass=None)
    tweak={k:f"synthetic {k} [host]\r\n" for k in TWEAK_FIELDS}
    tweak.update(Name="Synthetic tweak",Flag="zz",Info="plain",Mode=1,unknown=[1,None,""])
    catalog={**root,"Servers":[server],"Tweaks":[tweak]}
    wire=encode_fields(root,ROOT_FIELDS,"Jenc")
    wire.update(Servers=[encode_fields(server,SERVER_FIELDS,"Jenc")],
                Tweaks=[encode_fields(tweak,TWEAK_FIELDS,"Jenc")])
    catalog_cipher=oracle([("XXenc",json_bytes(wire))])[0].decode()
    files=[]
    for locked in (False,True):
        profile={k:("" if k=="UDPobfs" else f"synthetic {k} 🌎\r\n") for k in FILE_FIELDS}
        profile.update(NoobDev=1,TunnelType=8,isPassON=locked,MyPass="synthetic-lock" if locked else "",
                       PSInstall=False,DeviceID="",RootBlock=False,MobileData=False,ExpireDate=0,
                       isMsg=True,CFGMessage="plain",isUri=True,isEreverse=False,isWSProxy=False,isWS=True,
                       Server=json_bytes(server).decode(),unknown=[{"Password":"unmodified","n":None}])
        encrypted=encode_fields(profile,FILE_FIELDS,"Fenc")
        encrypted["Server"]=json_bytes(encode_fields(server,SERVER_FIELDS,"Jenc")).decode()
        cipher=oracle([("Penc",json_bytes(encrypted))])[0].decode()
        files.append({"name":"locked" if locked else "normal","cipher":cipher,"expected":profile})
    udp=[{"UDPserver":"udp.example.invalid:443","obfs":"synthetic-obfs","auth":"é😀", "unknown":[None,False,0]}]
    wire_udp=[dict(udp[0])]
    for key in ("obfs","auth"):
        units=udp[0][key].encode("utf-16-le")
        wire_udp[0][key]=",".join(str(int.from_bytes(units[i:i+2],"little")) for i in range(0,len(units),2))
    primitives=[]
    for text in ("","a","a"*15,"a"*16,"a"*17,"é😀\r\n","\u0000tail"):
        for op in ("Jenc","Fenc"):
            primitives.append({"method":op[0],"plain":text})
    cipher=oracle([(v["method"]+"enc",v["plain"].encode()) for v in primitives])
    for v,c in zip(primitives,cipher):v["cipher"]=c.decode()
    fixture={"provenance":"Independent JDK 17; synthetic only", "catalog":{"cipher":catalog_cipher,"expected":catalog},
             "files":files,"udp":{"cipher":json_bytes(wire_udp).decode(),"expected":udp},"primitives":primitives}
    path=HERE/"abowaged_vectors.json";path.write_text(json.dumps(fixture,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"syntheticProfiles":len(files),"catalogs":2,"primitives":len(primitives)}))


if __name__=="__main__":main()
