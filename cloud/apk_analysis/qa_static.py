"""F7 APK QA: actual static ZIP/DEX/ELF inventory, no APK code execution.

This is an intentionally bounded FIRST-PASS inspector, not JADX, crypto recovery,
live vendor checks or unattended use of the 63 unreviewed research tools.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
import zipfile

from .input_gate import GateError, inspect_input

MAX_DISPLAY_ITEMS=64


def _dex_header(z:zipfile.ZipFile, name:str) -> dict:
    try:
        with z.open(name) as fd:
            data=fd.read(112)
        if len(data)<112 or not data.startswith(b"dex\n") or data[7]!=0:
            return {"name":name,"status":"UNRECOGNIZED_DEX_HEADER"}
        file_size=struct.unpack_from("<I",data,0x20)[0]
        if file_size!=z.getinfo(name).file_size:
            return {"name":name,"status":"INCONSISTENT_DEX_LENGTH"}
        return {"name":name,"status":"HEADER_READ","classes":struct.unpack_from("<I",data,0x60)[0],
                "methods":struct.unpack_from("<I",data,0x58)[0],
                "strings":struct.unpack_from("<I",data,0x38)[0],
                "bytes":file_size}
    except (OSError,zipfile.BadZipFile,RuntimeError):
        return {"name":name,"status":"DEX_UNREADABLE"}


def inspect_static(path:Path) -> dict:
    checked=inspect_input(path)
    # APKS members are already individually bounded/validated by input_gate.
    # The first pass inventories the outer bundle and base APK, without
    # extracting executable artifacts or visiting arbitrary paths.
    dex=[];native=[];assets=0;resources=0;total_uncompressed=0
    packages=checked["apk_count"]
    paths=[]
    with zipfile.ZipFile(path) as z:
        if checked["format"]=="APK":
            items=[z]
        else:
            # For APKS, do not allocate the complete split in RAM; nested
            # ZIP member iteration is deferred to the separate A5 scanner.
            items=[]
            paths=sorted(x.filename for x in z.infolist()
                         if x.filename.lower().endswith(".apk") and "/" not in x.filename)
        for archive in items:
            for info in archive.infolist():
                if info.is_dir():continue
                total_uncompressed+=info.file_size
                name=info.filename
                if name.endswith(".dex") and "/" not in name:
                    if len(dex)<MAX_DISPLAY_ITEMS:dex.append(_dex_header(archive,name))
                elif name.startswith("lib/") and name.endswith(".so"):
                    if len(native)<MAX_DISPLAY_ITEMS:
                        parts=name.split("/")
                        native.append({"abi":parts[1] if len(parts)>2 else "unknown",
                                       "file":parts[-1][:128],"bytes":info.file_size})
                elif name.startswith("assets/"):assets+=1
                elif name.startswith("res/"):resources+=1
    return {
        "schemaVersion":1, "reportKind":"APK_STATIC_QA_FIRST_PASS",
        "status":"COMPLETED_PRELIMINARY",
        "evidence":"OBSERVED_LOCAL_APK_BYTES",
        "input":{"format":checked["format"],"sha256":checked["input_sha256"],
                 "bytes":checked["input_bytes"],"apkCount":packages},
        "inventory":{"zipEntries":checked["members"],"dexCount":checked["dex_count"],
                     "dexHeaders":dex,"nativeLibraries":native,"assetFiles":assets,
                     "resourceFiles":resources,"splitFiles":paths[:MAX_DISPLAY_ITEMS],
                     "uncompressedBytesSeen":total_uncompressed},
        "analysis":{"codeExecuted":False,"jadxExecuted":False,"vendorMethodValidated":False,
                    "credentialsExtracted":False,"networkUsed":False,
                    "stage":"STATIC_INVENTORY",
                    "nextStages":["DEX_DECOMPILATION_PENDING","ELF_REVIEW_PENDING",
                                  "METHOD_EVIDENCE_PENDING"]},
        "limitations":["FIRST_PASS_ONLY","NO_VPN_DECRYPTION_OR_METHOD_RECONSTRUCTION",
                       "NO_EXTERNAL_NETWORK_OR_DYNAMIC_EXECUTION"],
    }
