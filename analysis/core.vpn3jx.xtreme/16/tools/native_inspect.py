#!/usr/bin/env python3
"""Read Go 1.20+ ARM32 pclntab and disassemble selected functions; never execute ELF.

ARM32 adaptation of scripts/apk_analysis/go_inspect.py. The shared ARM64 reader
is unchanged. Raw strings/keys are not included in the default metadata output.
"""
import argparse,hashlib,io,json,re,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN

class Go32Image:
    def __init__(self,path):
        self.data=Path(path).read_bytes();self.elf=ELFFile(io.BytesIO(self.data))
        if self.elf.elfclass!=32 or self.elf["e_machine"]!="EM_ARM" or not self.elf.little_endian:
            raise ValueError("UNSUPPORTED_ARM32_ELF")
        signature=b"\xf1\xff\xff\xff\0\0\x04\x04"
        section=self.elf.get_section_by_name(".data.rel.ro")
        if section is None:raise ValueError("MISSING_GO_TABLE")
        blob=section.data();offset=blob.find(signature)
        if offset<0 or blob.find(signature,offset+1)>=0:raise ValueError("AMBIGUOUS_GO_TABLE")
        table=blob[offset:]
        count,_,start,names,_,_,_,pcln=struct.unpack_from("<8I",table,8)
        if not start or not 0<count<1000000 or pcln+(count+1)*8>len(table):
            raise ValueError("INVALID_GO_HEADER")
        self.functions={};self.labels={}
        for i in range(count):
            entry,record=struct.unpack_from("<2I",table,pcln+i*8)
            end=struct.unpack_from("<I",table,pcln+(i+1)*8)[0]
            if end<entry or pcln+record+8>len(table):raise ValueError("INVALID_FUNCTION_RECORD")
            name_offset=struct.unpack_from("<i",table,pcln+record+4)[0]
            at=names+name_offset
            if not 0<=at<len(table):raise ValueError("INVALID_FUNCTION_NAME")
            stop=table.find(b"\0",at,min(at+4096,len(table)))
            if stop<0:raise ValueError("UNTERMINATED_FUNCTION_NAME")
            name=table[at:stop].decode()
            address=start+entry;size=end-entry
            self.read(address,min(size,4))
            self.functions[name]=(address,size);self.labels[address]=name
    def read(self,address,size):
        if size<0:raise ValueError("INVALID_READ")
        for segment in self.elf.iter_segments():
            start=segment["p_vaddr"]
            if start<=address and address+size<=start+segment["p_filesz"]:
                at=segment["p_offset"]+address-start
                return self.data[at:at+size]
        raise ValueError("ADDRESS_NOT_FILE_BACKED")
    def disassemble(self,name):
        address,size=self.functions[name]
        if size>65536:raise ValueError("FUNCTION_TOO_LARGE")
        for ins in Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN).disasm(self.read(address,size),address):
            label=""
            if ins.mnemonic in ("bl","b") and ins.op_str.startswith("#"):
                label=self.labels.get(int(ins.op_str[1:],0),"")
            yield f"{ins.address:#x} {ins.mnemonic} {ins.op_str} {label}".rstrip()

def main():
    p=argparse.ArgumentParser();p.add_argument("elf",type=Path)
    p.add_argument("--filter",default=r"AndroidLibXrayLite.*(?:[.]CU$|[.]DO$|[.]decrypt$|[.]Encrypt$|[.]EO$)|main.Decrypt")
    p.add_argument("--disassemble");args=p.parse_args();image=Go32Image(args.elf)
    if args.disassemble:print("\n".join(image.disassemble(args.disassemble)))
    else:
        pattern=re.compile(args.filter)
        print(json.dumps({"elfSha256":hashlib.sha256(image.data).hexdigest(),"architecture":"ARM32",
            "functions":{k:{"address":hex(a),"size":s} for k,(a,s) in image.functions.items() if pattern.search(k)}}))
if __name__=="__main__":main()

