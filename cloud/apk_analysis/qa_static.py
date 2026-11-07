"""F7-A5 deep static APK/APKS inspection; no uploaded executable is run.

The input is verified in full first. Then every split, DEX header/table and
ELF dynamic section is examined under size limits. No JADX/Ghidra claim is
made without a separate isolated tool execution and real evidence.
"""
from pathlib import Path
from .input_gate import inspect_input
from .qa_deep import inspect_parts


def inspect_static(path:Path, on_stage=None)->dict:
    checked=inspect_input(path)
    if on_stage:
        on_stage("PACKAGE_VALIDATED")
        on_stage("COMPONENT_INSPECTION")
    inventory=inspect_parts(path,checked["format"])
    if on_stage:
        on_stage("COMPONENTS_INSPECTED")
    return {
        "schemaVersion":2,
        "reportKind":"APK_STATIC_QA_DEEP_V2",
        "status":"COMPLETED_PARTIAL",
        "evidence":"OBSERVED_LOCAL_APK_BYTES",
        "input":{"format":checked["format"],"sha256":checked["input_sha256"],
                 "bytes":checked["input_bytes"],"apkCount":checked["apk_count"]},
        "inventory":{"zipEntries":checked["members"],"dexCount":checked["dex_count"],
                     **inventory},
        "analysis":{
            "stage":"DEEP_STATIC_METADATA",
            "codeExecuted":False,"jadxExecuted":False,"ghidraExecuted":False,
            "vendorMethodValidated":False,"credentialsExtracted":False,"networkUsed":False,
            "dexTablesParsed":inventory["dexParsed"],
            "elfFilesParsed":inventory["elfParsed"],
            "nextStages":["JADX_DECOMPILATION_PENDING","GHIDRA_HEADLESS_PENDING",
                          "METHOD_EVIDENCE_PENDING"],
        },
        "limitations":[
            "STATIC_METADATA_NOT_SOURCE_DECOMPILATION",
            "CRYPTO_SIGNATURES_ARE_REFERENCES_NOT_PROOF",
            "NO_VPN_DECRYPTION_OR_METHOD_RECONSTRUCTION",
            "NO_EXTERNAL_NETWORK_OR_DYNAMIC_EXECUTION",
            "JADX_AND_GHIDRA_NOT_EXECUTED",
        ],
    }
