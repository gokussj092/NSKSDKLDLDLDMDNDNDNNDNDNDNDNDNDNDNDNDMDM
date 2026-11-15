"""Bounded evidence from *actual* DEX class_data and method code_items.

No code execution, decompilation, literal strings, passwords, or raw bytecode
are returned. The 16-bit Dalvik code units are integrity hashed; a method name
or cryptographic API alone is not proof of a functional decoder.
"""
from __future__ import annotations
import hashlib
import re
import struct

MAX_CLASSES=120_000
MAX_METHODS=250_000
MAX_ENCODED_ITEMS=350_000
MAX_CODE_BYTES=1024*1024
MAX_EVIDENCE=40

CANDIDATE=re.compile(r"(?i)(decrypt|encrypt|decipher|cipher|decode|unpack|config|payload|serialize|deserializ|derivekey|pbkdf|hkdf|aes|chacha|base64|hmac)")
FRAMEWORK_PREFIXES=(
    "Landroid/","Ljava/","Ljavax/","Lkotlin/","Lkotlinx/","Landroidx/",
    "Lcom/google/","Lcom/android/","Lorg/jetbrains/","Lorg/apache/",
    "Lokhttp3/","Lokio/","Lretrofit2/","Lcom/squareup/","Lio/reactivex/",
)
def _uint32(data,at):
    if at<0 or at+4>len(data):raise ValueError("DEX_BOUND")
    return struct.unpack_from("<I",data,at)[0]

def _uleb(data,at):
    result=0
    for j in range(5):
        if at>=len(data):raise ValueError("DEX_ULEB_BOUND")
        octet=data[at];at+=1
        result|=(octet&127)<<(j*7)
        if not octet&128:
            if result>0xffffffff:raise ValueError("DEX_ULEB_OVERFLOW")
            return result,at
    raise ValueError("DEX_ULEB_INVALID")

def _code_digest(data,at):
    if not at:return {"status":"NO_CODE_ITEM"}
    if at<112 or at+16>len(data):return {"status":"CODE_ITEM_BOUNDS"}
    regs,ins,outs,tries,debug,size=struct.unpack_from("<HHHHII",data,at)
    byte_count=size*2
    if size==0 or byte_count>MAX_CODE_BYTES or at+16+byte_count>len(data):
        return {"status":"CODE_ITEM_BOUNDS"}
    region=memoryview(data)[at+16:at+16+byte_count]
    return {
        "status":"CODE_ITEM_HASHED",
        "dalvikCodeUnits":size,
        "registers":regs,
        "inputRegisters":ins,
        "outputRegisters":outs,
        "hasExceptionHandlers":bool(tries),
        "bytecodeSha256":hashlib.sha256(region).hexdigest(),
    }

def observe_method_code(data,*,classes:int,classes_off:int,methods:int,
                        methods_off:int,string_name,class_name)->dict:
    """Read method_idx_diff/class_data/code_off per DEX v035 structure."""
    out={"methodCodeStatus":"NOT_PRESENT","classDataSections":0,
         "candidateCodeItems":0,"methodCodeEvidence":[],"parseWarnings":0}
    if classes<0 or classes>MAX_CLASSES or methods<0 or methods>MAX_METHODS:
        return {**out,"methodCodeStatus":"LIMIT_EXCEEDED"}
    if classes_off<112 or classes_off+32*classes>len(data) or methods_off+8*methods>len(data):
        return {**out,"methodCodeStatus":"INVALID_TABLES"}
    if methods and methods_off<112:return {**out,"methodCodeStatus":"INVALID_TABLES"}
    # Method metadata is an index; only the owning class's encoded method
    # with a nonzero code_off counts as observable implementation evidence.
    candidates={}
    for i in range(methods):
        try:
            cls=struct.unpack_from("<H",data,methods_off+i*8)[0]
            nameidx=_uint32(data,methods_off+i*8+4)
            desc=class_name(cls)
            if desc.startswith(FRAMEWORK_PREFIXES):continue
            method=string_name(nameidx)
            if CANDIDATE.search(method):
                candidates[i]=(desc[:160],method[:96])
        except (IndexError,UnicodeError,ValueError,struct.error):
            out["parseWarnings"]+=1
    scanned=0
    for idx in range(classes):
        class_data_off=_uint32(data,classes_off+idx*32+24)
        if not class_data_off:continue
        try:
            if class_data_off<112 or class_data_off>=len(data):
                raise ValueError("DEX_CLASS_DATA_OFFSET")
            at=class_data_off
            counts=[]
            for _ in range(4):
                count,at=_uleb(data,at)
                counts.append(count)
            static_fields,instance_fields,direct_methods,virtual_methods=counts
            length=static_fields+instance_fields+direct_methods+virtual_methods
            if length>MAX_ENCODED_ITEMS or scanned+length>MAX_ENCODED_ITEMS:
                out["methodCodeStatus"]="LIMIT_EXCEEDED"
                return out
            scanned+=length
            for _ in range(static_fields+instance_fields):
                _,at=_uleb(data,at)
                _,at=_uleb(data,at)
            for count in (direct_methods,virtual_methods):
                method_index=0
                for _ in range(count):
                    diff,at=_uleb(data,at)
                    method_index+=diff
                    _,at=_uleb(data,at)
                    code_off,at=_uleb(data,at)
                    if method_index>=methods:raise ValueError("METHOD_INDEX")
                    desc=candidates.get(method_index)
                    if not desc:continue
                    out["candidateCodeItems"]+=bool(code_off)
                    if len(out["methodCodeEvidence"])<MAX_EVIDENCE:
                        out["methodCodeEvidence"].append({
                            "class":desc[0],"method":desc[1],
                            "evidence":"DEX_CLASS_DATA_AND_CODE_ITEM",
                            **_code_digest(data,code_off),
                        })
            out["classDataSections"]+=1
        except (ValueError,IndexError,struct.error):
            out["parseWarnings"]+=1
            continue
    out["methodCodeStatus"]="PARSED" if out["classDataSections"] else "NO_CLASS_DATA"
    return out
