#!/usr/bin/env python3
"""Compare full AboWaged documents with independent JDK; print counts only."""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from decoders.Python.apps.AboWaged_VPN import codec, server_catalog_decoder as catalog
spec=importlib.util.spec_from_file_location("abowaged_reference",ROOT/"tests/golden/abowaged_generate.py")
ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)


def fields(obj,names,op):
    keys=[k for k in names if isinstance(obj.get(k),str) and obj[k]]
    values=ref.oracle([(op,obj[k].encode()) for k in keys])
    result=dict(obj)
    for key,value in zip(keys,values):result[key]=value.decode("utf-8")
    return result


def reference_catalog(data):
    outer=ref.oracle([("XXdec",data)])[0]
    doc=json.loads(outer)
    result=fields(doc,ref.ROOT_FIELDS,"Jdec")
    for section,names in (("Servers",ref.SERVER_FIELDS),("Tweaks",ref.TWEAK_FIELDS)):
        # One Java batch for all records, with an independently transcribed map.
        result[section]=[dict(v) for v in doc[section]]
        locations=[(i,k) for i,v in enumerate(doc[section]) for k in names if isinstance(v.get(k),str) and v[k]]
        outputs=ref.oracle([("Jdec",doc[section][i][k].encode()) for i,k in locations])
        for (i,k),plain in zip(locations,outputs):result[section][i][k]=plain.decode()
    return result


def reference_file(data):
    doc=json.loads(ref.oracle([("Pdec",data)])[0])
    result=fields(doc,ref.FILE_FIELDS,"Fdec")
    if doc.get("Server"):
        server=fields(json.loads(doc["Server"]),ref.SERVER_FIELDS,"Jdec")
        result["Server"]=json.dumps(server,ensure_ascii=False,separators=(",",":"))
    return result


def reference_udp(data):
    doc=json.loads(data)
    result=[dict(v) for v in doc]
    outputs=ref.oracle([("Ddec",v[k].encode()) for v in doc for k in ("obfs","auth")])
    for i,v in enumerate(result):
        for j,k in enumerate(("obfs","auth")):v[k]=outputs[i*2+j].decode()
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalog",type=Path,action="append",default=[])
    p.add_argument("--udp",type=Path)
    p.add_argument("--file",type=Path,action="append",default=[])
    p.add_argument("--worker",action="store_true")
    p.add_argument("--native",type=Path)
    a=p.parse_args();report={"catalogs":[],"profiles":0,"udpServers":0,"workerEqual":False}
    fixture=json.loads((ROOT/"tests/golden/abowaged_vectors.json").read_text())
    for v in fixture["files"]:
        data=v["cipher"].encode();assert codec.decode_file(data)==reference_file(data)==v["expected"]
        report["profiles"]+=1
    for path in a.file:
        data=path.read_bytes();assert codec.decode_file(data)==reference_file(data)
        report["profiles"]+=1
    for path in a.catalog:
        data=path.read_bytes();actual=codec.decode_catalog(data);assert actual==reference_catalog(data)
        report["catalogs"].append({"servers":len(actual["Servers"]),"tweaks":len(actual["Tweaks"]),"version":actual["Version"]})
    if a.udp:
        data=a.udp.read_bytes();actual=codec.decode_udp(data);assert actual==reference_udp(data)
        report["udpServers"]=len(actual)
    if a.worker:
        from cloud.workers.python.engine import decode_file,decode_provider_catalog
        for v in fixture["files"]:
            assert decode_file("awg",v["cipher"].encode())["structuredJson"]==v["expected"]
        if a.catalog and a.udp:
            bundle=catalog.pack_catalogs(a.catalog[-1].read_bytes(),a.udp.read_bytes())
        else:
            bundle=catalog.pack_catalogs(fixture["catalog"]["cipher"].encode(),fixture["udp"]["cipher"].encode())
        expected=json.loads(catalog.run(bundle))
        result=decode_provider_catalog("abowaged-vpn",bundle)
        assert result["structuredJson"]==expected==json.loads(result["rawText"])
        assert result["isPartial"] is False and result["warnings"]==[]
        report["workerEqual"]=True
    if a.native:
        from abowaged_native_oracle import NativeWrappers
        report.update(NativeWrappers(a.native).verify())
    print(json.dumps(report))


if __name__=="__main__":main()
