"""MKK Hyper multi-source worker aggregation, retaining each decoded document.

The web broker is the only network client. This worker only receives fixed
source labels and Base64 bytes from that trusted broker; it never follows
arbitrary subscription links or fetches user-supplied URLs.
"""
from __future__ import annotations
import base64
import binascii
import json
from decoders.Python.apps.MKK_Hyper_VPN import MKK_Hyper_VPN as codec

SOURCES=("servers","static","subscriptions","legacy-subscriptions")
KIND="spdecode-mkk-sources-v1"
MAX_SOURCE=8*1024*1024

def decode(payload: bytes) -> str:
    manifest=json.loads(payload)
    if not isinstance(manifest,dict) or set(manifest)!={"kind","sources"} or manifest["kind"]!=KIND:
        raise ValueError("INVALID_BUNDLE")
    sources=manifest["sources"]
    if not isinstance(sources,list) or len(sources)!=len(SOURCES) or [x.get("name") for x in sources if isinstance(x,dict)]!=list(SOURCES):
        raise ValueError("INVALID_SOURCES")
    output=[]
    for item in sources:
        if not isinstance(item,dict) or item.get("status") not in ("ok","error"):
            raise ValueError("INVALID_SOURCE")
        name=item["name"]
        if item["status"]=="error":
            if set(item)!={"name","status","error"} or not isinstance(item["error"],str) or item["error"] not in (
                "REMOTE_PROVIDER_UNAVAILABLE","REMOTE_NETWORK_DENIED",
                "REMOTE_RESPONSE_INVALID","REMOTE_TOO_LARGE","REMOTE_NOT_CONFIGURED"):
                raise ValueError("INVALID_SOURCE_FAILURE")
            output.append({"name":name,"status":"error","error":item["error"]})
            continue
        if set(item)!={"name","status","dataBase64"} or not isinstance(item["dataBase64"],str) or len(item["dataBase64"])>MAX_SOURCE*4//3+8:
            raise ValueError("INVALID_SOURCE_BYTES")
        try:
            raw=base64.b64decode(item["dataBase64"],validate=True)
        except (ValueError,binascii.Error):
            raise ValueError("INVALID_SOURCE_BYTES") from None
        if not raw or len(raw)>MAX_SOURCE:
            raise ValueError("INVALID_SOURCE_BYTES")
        try:
            data=codec.decode(raw)
        except (codec.DecodeError,ValueError,UnicodeError,RecursionError):
            output.append({"name":name,"status":"error","error":"DECODE_FAILED"})
            continue
        if isinstance(data,list):
            count=len(data)
        elif isinstance(data,dict):
            count=sum(len(v) for k,v in data.items() if k in ("servers","static_users","subscriptions") and isinstance(v,list))
            if not count:count=len(data)
        else:
            raise ValueError("INVALID_SOURCE_RESULT")
        output.append({"name":name,"status":"ok","records":count,"data":data})
    successful=sum(item["status"]=="ok" for item in output)
    if not successful:
        raise ValueError("ALL_SOURCES_FAILED")
    document={
        "provider":"mkk-hyper",
        "complete":successful==len(SOURCES),
        "sourceCount":len(SOURCES),
        "successfulSources":successful,
        "sources":output,
    }
    return json.dumps(document,ensure_ascii=False,indent=2,allow_nan=False)+"\n"
