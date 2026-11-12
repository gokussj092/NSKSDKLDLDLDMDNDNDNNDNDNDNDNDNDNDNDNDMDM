#!/usr/bin/env python3
"""Validate live Android/Cloud metadata, rather than historical release snapshots.

No decoder execution, network traffic, version-specific UI hashes or fixed JNI counts.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


class ContractError(ValueError):
    pass


def release_metadata(gradle: str) -> tuple[str, int]:
    versions = re.findall(r'(?m)^\s*versionName\s*=\s*"([^"]+)"\s*$', gradle)
    codes = re.findall(r"(?m)^\s*versionCode\s*=\s*(\d+)\s*$", gradle)
    if len(versions) != 1 or len(codes) != 1 or not re.fullmatch(r"\d+\.\d+\.\d+", versions[0]):
        raise ContractError("Exactly one valid Android versionName/versionCode is required")
    code = int(codes[0])
    if code <= 0:
        raise ContractError("Android versionCode must be positive")
    return versions[0], code


def jni_registry(cpp: str, kotlin: str) -> tuple[str, ...]:
    cpp_names = re.findall(r'const_cast<char\*>\("((?:native[A-Za-z]+|postNativeEncrypted))"\)', cpp)
    kotlin_names = re.findall(
        r'@JvmStatic\s+private\s+external\s+fun\s+((?:native[A-Za-z]+|postNativeEncrypted))\s*\(',
        kotlin,
    )
    if not cpp_names or not kotlin_names:
        raise ContractError("JNI registration or Kotlin declarations missing")
    if Counter(cpp_names) != Counter(kotlin_names):
        raise ContractError("JNI methods in C++ and Kotlin differ: "
                            + str({"unregistered": sorted(set(kotlin_names)-set(cpp_names)),
                                   "undeclared": sorted(set(cpp_names)-set(kotlin_names))}))
    if len(cpp_names) != len(set(cpp_names)):
        raise ContractError("Duplicate JNI registration")
    if "RegisterNatives(bridge,methods," not in cpp:
        raise ContractError("RegisterNatives binding missing")
    return tuple(cpp_names)


def current_ui_sources(src: Path) -> int:
    """Verify declared launcher sources and security; tolerate new/deleted screens."""
    manifest = src / "AndroidManifest.xml"
    if not manifest.is_file():
        raise ContractError("Android manifest is missing")
    try:
        xml = ET.parse(manifest).getroot()
    except ET.ParseError as exc:
        raise ContractError("Malformed manifest") from exc
    ns = "{http://schemas.android.com/apk/res/android}"
    app = xml.find("application")
    if app is None:
        raise ContractError("Android application entry missing")
    if app.get(ns+"usesCleartextTraffic") != "false" or app.get(ns+"allowBackup") != "false":
        raise ContractError("Cleartext traffic or OS backup must stay disabled")
    kotlin = tuple((src/"java").rglob("*.kt"))
    if not kotlin:
        raise ContractError("Android Kotlin sources missing")
    launchers = 0
    for activity in app.findall("activity"):
        if not any(
            any(a.get(ns+"name")=="android.intent.action.MAIN" for a in intent.findall("action")) and
            any(c.get(ns+"name")=="android.intent.category.LAUNCHER" for c in intent.findall("category"))
            for intent in activity.findall("intent-filter")
        ):
            continue
        name = activity.get(ns+"name", "")
        if not name.startswith(".") or not any(p.name==name.rsplit(".",1)[-1]+".kt" for p in kotlin):
            raise ContractError("Launcher class not backed by a Kotlin source")
        launchers += 1
    if launchers == 0:
        raise ContractError("No launcher activity")
    return len(kotlin)




_JNI_TYPE = {
    "Boolean": "boolean", "Int": "int", "Long": "long",
    "String": "String", "ByteArray": "byte[]",
    "Array<String>": "String[]", "Context": "android.content.Context",
}


def host_native_declarations(kotlin: str) -> str:
    """Reproduce JNI signatures from current Kotlin, for the JVM host harness.

    Unrecognized types fail closed rather than silently generating an incorrect
    host stub. The real C++ and Android Kotlin sources remain untouched.
    """
    matches = re.findall(
        r'@JvmStatic\s+private\s+external\s+fun\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?::\s*(Array<String>|ByteArray|String|Boolean|Long|Int))?',
        kotlin,
        flags=re.S,
    )
    if not matches:
        raise ContractError("No Kotlin JNI methods available for host stub")
    decls = []
    for name, params, return_type in matches:
        signature = []
        for index, param in enumerate(params.split(",")):
            param = param.strip()
            if not param:
                continue
            if ":" not in param:
                raise ContractError("Malformed Kotlin native parameter: " + name)
            _, type_name = param.split(":", 1)
            kind = type_name.strip().replace("?", "")
            if kind not in _JNI_TYPE:
                raise ContractError("Unsupported native parameter type: " + kind)
            signature.append(_JNI_TYPE[kind] + " arg" + str(index))
        output_type = _JNI_TYPE.get(return_type or "", "void")
        if return_type and return_type not in _JNI_TYPE:
            raise ContractError("Unsupported native return type: " + return_type)
        throws = " throws java.io.IOException" if name == "postNativeEncrypted" else ""
        decls.append("    private static native " + output_type + " " + name +
                     "(" + ", ".join(signature) + ")" + throws + ";")
    if len(decls) != len(set(name for name,_,_ in matches)):
        raise ContractError("Duplicate native host declaration")
    return "\n".join(decls)


def generate_host_fixture(root: Path, destination: Path) -> Path:
    kotlin=(root/"android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNativeTransport.kt").read_text("utf-8")
    harness=(root/"tests/native/v2_transport_jni/CloudNativeTransport.java").read_text("utf-8")
    marker="    // CI_HOST_JNI_DECLARATIONS"
    if harness.count(marker)!=1:
        raise ContractError("Exactly one host JNI declaration anchor required")
    generated=harness.replace(marker,host_native_declarations(kotlin))
    destination.mkdir(parents=True,exist_ok=True)
    output=destination/"CloudNativeTransport.java"
    output.write_text(generated,encoding="utf-8")
    return output

def check(root: Path=ROOT) -> dict:
    app=root/"android/app"
    version,code=release_metadata((app/"build.gradle.kts").read_text("utf-8"))
    cpp=(app/"src/main/cpp/spdecode_transport.cpp").read_text("utf-8")
    kt=(app/"src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNativeTransport.kt").read_text("utf-8")
    methods=jni_registry(cpp,kt)
    ui_count=current_ui_sources(app/"src/main")
    return {"version_name":version,"version_code":code,
            "jni_methods":len(methods),"kotlin_sources":ui_count}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    parser.add_argument("--github-env",type=Path)
    parser.add_argument("--generate-host-java",type=Path,metavar="DIRECTORY")
    args=parser.parse_args()
    try:
        result=check()
    except (ContractError,OSError) as exc:
        parser.exit(1,"Android contract: "+str(exc)+"\n")
    if args.generate_host_java:
        try:
            generated=generate_host_fixture(ROOT,args.generate_host_java)
        except (ContractError,OSError) as exc:
            parser.exit(1,"Host JNI fixture: "+str(exc)+"\n")
        print("Generated host JNI declarations: "+str(generated))
    if args.github_env:
        with args.github_env.open("a",encoding="utf-8") as output:
            output.write("SPDECODE_VERSION_NAME="+result["version_name"]+"\n")
            output.write("SPDECODE_VERSION_CODE="+str(result["version_code"])+"\n")
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
