"""Bounded, offline APK/APKS deep *static* metadata inspection.

Reads every validated APKS split, parses DEX tables and ELF dynamic metadata.
Never executes uploaded Dalvik, ELF, scripts or downloaded tools. Every crypto
marker is a reference, NOT a recovered cipher, key or verified vendor method.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import mmap
from pathlib import Path
import re
import struct
import tempfile
import zipfile

from .input_gate import DEX, GateError
from .qa_dex_bytecode import FRAMEWORK_PREFIXES, observe_method_code

MAX_DISPLAY = 32
MAX_NATIVE_DISPLAY = 48
MAX_INDICATORS = 24
MAX_SAMPLE_CLASSES = 16
MAX_SAMPLE_METHODS = 16
MAX_DEX_STRINGS = 200_000
MAX_BINARY_BYTES = 100 * 1000 * 1000

# Names below are allowed, public crypto API references, not arbitrary
# customer strings or credentials.
MARKERS = (
    "AES/GCM/NoPadding", "AES/CBC/PKCS5Padding", "ChaCha20-Poly1305",
    "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA1", "HmacSHA256",
    "SecretKeySpec", "Cipher.getInstance", "javax/crypto/Cipher",
    "javax/crypto/Mac", "java/security/MessageDigest", "BouncyCastle",
    "sodium_crypto", "EVP_EncryptInit", "EVP_DecryptInit", "AES_set_encrypt_key",
    "crypto_secretbox", "SSL_CTX_new", "JNI_OnLoad", "RegisterNatives",
)
RELEVANT_METHOD = re.compile(r"(?i)(decrypt|encrypt|decode|encode|cipher|aes|rsa|chacha|hmac|pbkdf|hkdf|keyderive)")
CLASS = re.compile(r"^L[A-Za-z0-9_/$]{1,140};$")


def _u16(buf, off:int, endian="<") -> int:
    if off < 0 or off+2 > len(buf): raise ValueError("BOUNDS")
    return struct.unpack_from(endian+"H",buf,off)[0]


def _u32(buf, off:int, endian="<") -> int:
    if off < 0 or off+4 > len(buf): raise ValueError("BOUNDS")
    return struct.unpack_from(endian+"I",buf,off)[0]


def _u64(buf, off:int, endian="<") -> int:
    if off < 0 or off+8 > len(buf): raise ValueError("BOUNDS")
    return struct.unpack_from(endian+"Q",buf,off)[0]


@contextmanager
def _spool(archive:zipfile.ZipFile, info:zipfile.ZipInfo, workdir:Path):
    """One seekable temporary file with bounded memory and automatic unlink."""
    if info.file_size < 0 or info.file_size > MAX_BINARY_BYTES:
        raise ValueError("BINARY_SIZE")
    with tempfile.TemporaryFile(mode="w+b", dir=workdir) as tmp:
        received = 0
        digest = hashlib.sha256()
        with archive.open(info) as inp:
            while chunk := inp.read(256 * 1024):
                received += len(chunk)
                if received > info.file_size or received > MAX_BINARY_BYTES:
                    raise ValueError("BINARY_SIZE")
                digest.update(chunk)
                tmp.write(chunk)
        if received != info.file_size:
            raise ValueError("BINARY_TRUNCATED")
        tmp.flush()
        tmp.seek(0)
        yield tmp, digest.hexdigest()


def _dex_string(buf, index:int, count:int, table:int) -> str:
    if index >= count or index < 0: raise ValueError("DEX_STRING_ID")
    off=_u32(buf,table+index*4)
    if off >= len(buf): raise ValueError("DEX_STRING_OFFSET")
    # Dalvik uses a uleb128 UTF-16 length followed by MUTF-8 data.
    for _ in range(5):
        b=buf[off];off+=1
        if b & 128 == 0:break
    else:raise ValueError("DEX_ULEB128")
    end=min(len(buf),off+256)
    zero=buf.find(b"\0",off,end)
    if zero<0: raise ValueError("DEX_STRING_LENGTH")
    return bytes(buf[off:zero]).decode("utf-8",errors="replace")


def _dex_info(file, size:int, apk:str, name:str, digest:str) -> dict:
    data={"apk":apk,"name":name,"bytes":size,"sha256":digest}
    if size < 112:
        return {**data,"status":"DEX_HEADER_INVALID"}
    with mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as mm:
        if mm[:4]!=b"dex\n" or mm[7]!=0 or _u32(mm,0x20)!=size:
            return {**data,"status":"DEX_HEADER_INVALID"}
        strings,strings_off=_u32(mm,0x38),_u32(mm,0x3c)
        types,types_off=_u32(mm,0x40),_u32(mm,0x44)
        methods,methods_off=_u32(mm,0x58),_u32(mm,0x5c)
        classes,classes_off=_u32(mm,0x60),_u32(mm,0x64)
        data.update(status="HEADER_READ",version=mm[4:7].decode("ascii","replace"),
                    strings=strings,methods=methods,classes=classes,
                    sampledClasses=[],candidateMethods=[],cryptoReferences=[])
        # Synthetic and corrupted DEX tables must not be presented as parsed.
        if (strings>MAX_DEX_STRINGS or types>MAX_DEX_STRINGS or
            methods>MAX_DEX_STRINGS or classes>MAX_DEX_STRINGS or
            strings_off+strings*4>size or types_off+types*4>size or
            methods_off+methods*8>size or classes_off+classes*32>size or
            any(n and off<112 for n,off in
                ((strings,strings_off),(types,types_off),
                 (methods,methods_off),(classes,classes_off))) or
            (classes and not types) or (methods and not strings)):

            data["tableStatus"]="UNAVAILABLE_OR_BOUNDED"
            return data
        found=set()
        for i in range(strings):
            try: value=_dex_string(mm,i,strings,strings_off)
            except (ValueError,IndexError):continue
            for marker in MARKERS:
                if marker.lower() in value.lower():found.add(marker)
        data["cryptoReferences"]=sorted(found)[:MAX_INDICATORS]
        def typename(type_index:int) -> str:
            if type_index >= types:raise ValueError("TYPE_INDEX")
            return _dex_string(mm,_u32(mm,types_off+type_index*4),
                               strings,strings_off)
        short=0
        for i in range(classes):
            try:
                desc=typename(_u32(mm,classes_off+i*32))
                if not CLASS.fullmatch(desc):continue
                simple=desc.rsplit("/",1)[-1].rstrip(";")
                if len(simple)<=2:short+=1
                if len(data["sampledClasses"])<MAX_SAMPLE_CLASSES:
                    data["sampledClasses"].append(desc)
            except (ValueError,IndexError):continue
        for i in range(methods):
            try:
                cls=_u16(mm,methods_off+i*8)
                key=_u32(mm,methods_off+i*8+4)
                method=_dex_string(mm,key,strings,strings_off)
                if not RELEVANT_METHOD.search(method):continue
                descriptor=typename(cls)
                if descriptor.startswith(FRAMEWORK_PREFIXES):continue
                if len(data["candidateMethods"])<MAX_SAMPLE_METHODS:
                    data["candidateMethods"].append({
                        "class":descriptor[:144],"name":method[:80],
                        "evidence":"METHOD_NAME_ONLY"})
            except (ValueError,IndexError):continue
        data.update(observe_method_code(
            mm,classes=classes,classes_off=classes_off,
            methods=methods,methods_off=methods_off,
            string_name=lambda idx:_dex_string(mm,idx,strings,strings_off),
            class_name=typename))
        data["tableStatus"]="PARSED"
        data["shortClassNames"]=short
        data["classNameHeuristic"]="POSSIBLE_OBFUSCATION_NOT_PROVEN" if classes>=12 and short*2>classes else "NOT_ESTABLISHED"
        return data


def _cstr(buf, start:int, max_length=192) -> str:
    if start < 0 or start>=len(buf):return ""
    stop=buf.find(b"\0",start,min(start+max_length,len(buf)))
    if stop<0:return ""
    value=bytes(buf[start:stop]).decode("utf-8","replace")
    return value if all(32<=ord(x)<127 for x in value) else ""


def _elf_info(file,size:int,apk:str,name:str,digest:str) -> dict:
    data={"apk":apk,"file":name,"bytes":size,"sha256":digest}
    if size < 52:return {**data,"status":"ELF_HEADER_INVALID"}
    with mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as mm:
        if mm[:4]!=b"\x7fELF" or mm[4] not in (1,2) or mm[5] not in (1,2):
            return {**data,"status":"ELF_HEADER_INVALID"}
        endian="<" if mm[5]==1 else ">"
        is64=mm[4]==2
        machine=_u16(mm,18,endian)
        data.update(status="HEADER_READ",elfClass=64 if is64 else 32,
            endian="LE" if endian=="<" else "BE",
            architecture={183:"AARCH64",40:"ARM",3:"X86",62:"X86_64"}.get(machine,"OTHER"),
            neededLibraries=[],importedSymbols=[],cryptoReferences=[])
        offset=_u64(mm,40,endian) if is64 else _u32(mm,32,endian)
        entry=_u16(mm,58 if is64 else 46,endian)
        count=_u16(mm,60 if is64 else 48,endian)
        minimal=64 if is64 else 40
        if count==0 or offset==0 or count>4096 or entry<minimal or offset+count*entry>size:
            data["sectionStatus"]="UNAVAILABLE_OR_BOUNDED"
            return data
        sections=[]
        for i in range(count):
            at=offset+i*entry
            sections.append({
                "type":_u32(mm,at+4,endian),
                "offset":_u64(mm,at+24,endian) if is64 else _u32(mm,at+16,endian),
                "size":_u64(mm,at+32,endian) if is64 else _u32(mm,at+20,endian),
                "link":_u32(mm,at+40 if is64 else at+24,endian),
                "entry":_u64(mm,at+56,endian) if is64 else _u32(mm,at+36,endian),
            })
        def strtab(section):
            if section["link"]>=len(sections):return None
            tab=sections[section["link"]]
            if tab["type"]!=3 or tab["offset"]+tab["size"]>size:return None
            return tab
        relevant=set()
        for section in sections:
            table=strtab(section)
            if not table or section["offset"]+section["size"]>size:continue
            if section["type"]==6: # SHT_DYNAMIC -> DT_NEEDED
                step=16 if is64 else 8
                for i in range(min(section["size"]//step,4096)):
                    at=section["offset"]+i*step
                    tag=_u64(mm,at,endian) if is64 else _u32(mm,at,endian)
                    value=_u64(mm,at+8,endian) if is64 else _u32(mm,at+4,endian)
                    if tag==1 and value<table["size"]:
                        lib=_cstr(mm,table["offset"]+value)
                        if lib and len(data["neededLibraries"])<32:data["neededLibraries"].append(lib)
            if section["type"]==11: # SHT_DYNSYM, no native execution
                step=24 if is64 else 16
                for i in range(min(section["size"]//step,65536)):
                    at=section["offset"]+i*step
                    sym=_u32(mm,at,endian)
                    shndx=_u16(mm,at+6 if is64 else at+14,endian)
                    if sym>=table["size"]:continue
                    name=_cstr(mm,table["offset"]+sym)
                    if not name:continue
                    for marker in MARKERS:
                        if marker.lower() in name.lower():relevant.add(marker)
                    if shndx==0 and len(data["importedSymbols"])<32 and (
                            name.startswith(("Java_","JNI_","EVP_","AES_","crypto_","mbedtls_"))):
                        data["importedSymbols"].append(name[:128])
        data["cryptoReferences"]=sorted(relevant)[:MAX_INDICATORS]
        data["sectionStatus"]="PARSED"
        return data


def inspect_parts(path:Path, kind:str, on_stage=None) -> dict:
    """Analyze every APKS member with temporary seekable files on job volume."""
    dex=[];native=[];assets=0;resources=0;uncompressed=0;split_names=[]
    dex_seen=0;native_seen=0;indicators=set();skipped=0;split_errors=[]
    stages_reported=set()
    def stage_once(code):
        if on_stage and code not in stages_reported:
            stages_reported.add(code)
            on_stage(code)
    def visit(z:zipfile.ZipFile, apkname:str):
        nonlocal assets,resources,uncompressed,dex_seen,native_seen,skipped
        for info in z.infolist():
            if info.is_dir():continue
            uncompressed+=info.file_size
            name=info.filename
            if DEX.fullmatch(name):
                stage_once("DEX_BYTECODE_INSPECTION")
                dex_seen+=1
                if len(dex)>=MAX_DISPLAY:skipped+=1;continue
                try:
                    with _spool(z,info,path.parent) as (tmp,digest):
                        entry=_dex_info(tmp,info.file_size,apkname,name,digest)
                    dex.append(entry)
                    indicators.update(entry.get("cryptoReferences",[]))
                except (ValueError,OSError,RuntimeError,zipfile.BadZipFile):
                    dex.append({"apk":apkname,"name":name,"status":"DEX_READ_FAILED"})
            elif name.startswith("lib/") and name.endswith(".so"):
                stage_once("NATIVE_LIBRARY_INSPECTION")
                native_seen+=1
                if len(native)>=MAX_NATIVE_DISPLAY:skipped+=1;continue
                abi=name.split("/")[1] if len(name.split("/"))>2 else "unknown"
                try:
                    with _spool(z,info,path.parent) as (tmp,digest):
                        entry=_elf_info(tmp,info.file_size,apkname,name,digest)
                    entry["abi"]=abi
                    native.append(entry)
                    indicators.update(entry.get("cryptoReferences",[]))
                except (ValueError,OSError,RuntimeError,zipfile.BadZipFile):
                    native.append({"apk":apkname,"file":name,"abi":abi,"status":"ELF_READ_FAILED"})
            elif name.startswith("assets/"):assets+=1
            elif name.startswith("res/"):resources+=1
    with zipfile.ZipFile(path) as outer:
        if kind=="APK":
            visit(outer,path.name)
        else:
            members=sorted((x for x in outer.infolist() if
                x.filename.lower().endswith(".apk") and "/" not in x.filename),
                key=lambda x:x.filename)
            for info in members:
                split_names.append(info.filename)
                try:
                    with _spool(outer,info,path.parent) as (tmp,_):
                        with zipfile.ZipFile(tmp) as nested:
                            visit(nested,info.filename)
                except (ValueError,OSError,RuntimeError,zipfile.BadZipFile):
                    # Structural gate already validated the source. Exceeding
                    # the deeper scanner's per-split disk budget is an honest
                    # per-split partial result, not a successful empty APK.
                    if len(split_errors)<64:
                        split_errors.append({"apk":info.filename,
                                             "status":"DEEP_SPLIT_SCAN_INCOMPLETE"})
    return {
        "dexHeaders":dex,"nativeLibraries":native,"dexParsed":sum(x.get("tableStatus")=="PARSED" for x in dex),
        "elfParsed":sum(x.get("sectionStatus")=="PARSED" for x in native),
        "dexFilesObserved":dex_seen,"nativeFilesObserved":native_seen,
        "assetFiles":assets,"resourceFiles":resources,
        "splitFiles":split_names[:64],"uncompressedBytesSeen":uncompressed,
        "displayEntriesSkipped":skipped,
        "splitScanErrors":split_errors,
        "cryptoIndicators":{"status":"REFERENCES_ONLY_NOT_VALIDATED",
            "candidates":sorted(indicators)[:MAX_INDICATORS],
            "methodValidated":False},
    }
