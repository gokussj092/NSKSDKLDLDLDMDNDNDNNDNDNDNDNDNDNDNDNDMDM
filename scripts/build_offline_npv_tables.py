#!/usr/bin/env python3
"""Convert the exact source-controlled NPV tables into a native C++ header.

This is a BUILD-TIME tool. It runs on GitHub's CI host, never inside Android.
It does not decrypt files, access a network, or need cryptographic packages.
Source files are read as AST constants only; the legacy gzip/pickle data is
inspected for forbidden pickle opcodes and decoded with a no-globals unpickler.
"""
from __future__ import annotations
import argparse
import ast
import base64
import gzip
import hashlib
import io
from pathlib import Path
import pickle
import pickletools
import zlib

ROOT=Path(__file__).resolve().parents[1]
SOURCES=ROOT/"decoders"/"Python"
MODERN_SHA="35717e8267a115fbf474e3cd622066783feea21305457c840cabd57a73086f7d"
FORBIDDEN={
    "GLOBAL","STACK_GLOBAL","REDUCE","BUILD","OBJ","INST","NEWOBJ",
    "NEWOBJ_EX","EXT1","EXT2","EXT4","PERSID","BINPERSID",
}
def constant(path,name):
    tree=ast.parse(path.read_text(encoding="utf-8"),filename=str(path))
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name:
            return ast.literal_eval(node.value)
    raise ValueError(f"Missing constant {name} in {path.name}")
def b85_decode(raw):
    # Python stdlib base85, not the Adobe Ascii85 alphabet.
    return base64.b85decode(raw)
def check_bytes(raw,n,label):
    if len(raw)!=n:raise ValueError(f"Wrong {label}: {len(raw)} bytes != {n}")
    return raw
class SafeOnly(pickle.Unpickler):
    def find_class(self,module,name):raise pickle.UnpicklingError("unsafe class")
    def persistent_load(self,value):raise pickle.UnpicklingError("unsafe persistent opcode")
def legacy_tables():
    text=constant(SOURCES/"NPVTUNNEL.py","_WHITEBOX_BLOB")
    zipped=base64.b64decode(text,validate=True)
    data=gzip.decompress(zipped)
    if len(data)>8*1024*1024:raise ValueError("Legacy whitebox exceeds size cap")
    for op,arg,offset in pickletools.genops(data):
        if op.name in FORBIDDEN:raise ValueError(f"Forbidden legacy pickle opcode {op.name}")
    stream=io.BytesIO(data)
    state=SafeOnly(stream).load()
    if stream.read() or not isinstance(state,tuple) or len(state)!=4:
        raise ValueError("Legacy pickle has unexpected structure")
    p2,p3,p4,p5=state
    # Only r=0 is used by the Python white-box evaluator (2 rounds,
    # with the second round only permuting the state).
    def matrix(items):
        if len(items)!=96:raise ValueError(f"Unexpected xor table count {len(items)}")
        out=bytearray()
        for mat in items:
            if len(mat)!=16:raise ValueError("Unexpected xor rows")
            for row in mat:
                if len(row)!=16:raise ValueError("Unexpected xor columns")
                out.extend(row)
        return bytes(out)
    def words(items):
        if len(items)!=16:raise ValueError("Unexpected word table count")
        out=bytearray()
        for tab in items:
            if len(tab)!=256:raise ValueError("Unexpected word table length")
            for val in tab:out.extend(int(val).to_bytes(4,"big"))
        return bytes(out)
    def final(items):
        if len(items)!=16:raise ValueError("Unexpected final table count")
        out=b"".join(bytes(table) for table in items)
        return check_bytes(out,4096,"legacy final")
    return {
       "LegacyP2":check_bytes(matrix(p2[0]),24576,"legacy xor"),
       "LegacyP3":check_bytes(words(p3[0]),16384,"legacy first words"),
       "LegacyP4":final(p4),
       "LegacyP5":check_bytes(words(p5[0]),16384,"legacy second words")
    }
def modern_tables():
    data=constant(SOURCES/"npvs.py","_TABLE_DATA")
    if not isinstance(data,bytes):raise ValueError("Modern whitebox is not bytes")
    zipped=b85_decode(data)
    raw=zlib.decompress(zipped)
    check_bytes(raw,749569,"modern whitebox")
    if hashlib.sha256(raw).hexdigest()!=MODERN_SHA:
        raise ValueError("Modern embedded tables hash does not match source")
    return {"ModernZlib":zipped}
def old_signed_tables():
    encoded=constant(SOURCES/"npvs_v1.py","_NPVS_ASSET_B64")
    sizes={"tyboxes.bin":16384,"mbl.bin":16384,"xor.bin":24576,
           "tboxes_last.bin":4096,"tboxes_last_v2.bin":4096}
    names={"tyboxes.bin":"V1Ty","mbl.bin":"V1Mbl","xor.bin":"V1Xor",
           "tboxes_last.bin":"V1Final","tboxes_last_v2.bin":"V1FinalV2"}
    return {names[k]:check_bytes(base64.b64decode(encoded[k],validate=True),size,k)
            for k,size in sizes.items()}
def emit(output:Path):
    tables={**modern_tables(),**old_signed_tables(),**legacy_tables()}
    output.parent.mkdir(parents=True,exist_ok=True)
    lines=[
        "#pragma once",
        "// Auto-generated from pinned repo source by scripts/build_offline_npv_tables.py",
        "// Source table hash (uncompressed SHA-256): "+MODERN_SHA,
        "#include <cstddef>",
        "#include <cstdint>",
        "namespace spdecode::offline::tables {",
    ]
    for name,data in tables.items():
        lines.append(f"inline constexpr unsigned char k{name}[]={{")
        for offset in range(0,len(data),24):
            lines.append("  "+",".join(str(v) for v in data[offset:offset+24])+",")
        lines.append("};")
        lines.append(f"inline constexpr size_t k{name}Size=sizeof(k{name});")
    lines.append("} // namespace")
    output.write_text("\n".join(lines)+"\n",encoding="ascii")
    print("NPV_TABLES_OK: "+" ".join(f"{k}={len(v)}" for k,v in tables.items()))
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True)
    emit(p.parse_args().output)
if __name__=="__main__":main()
