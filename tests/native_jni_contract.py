#!/usr/bin/env python3
"""Fail early if Kotlin external method signatures diverge from RegisterNatives."""
import re
from pathlib import Path

root=Path(__file__).resolve().parents[1]
k=(root/"android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNativeTransport.kt").read_text()
cpp=(root/"android/app/src/main/cpp/spdecode_transport.cpp").read_text()

def descriptor(type_name):
    types={
        "Int":"I","Long":"J","Boolean":"Z","String":"Ljava/lang/String;",
        "ByteArray":"[B","Array<String>":"[Ljava/lang/String;",
        "Context":"Landroid/content/Context;",
        "PrivateKey":"Ljava/security/PrivateKey;","Unit":"V",
    }
    normalized=type_name.replace("?","").strip()
    if normalized not in types:
        raise AssertionError(f"Unrecognized JNI Kotlin type: {type_name}")
    return types[normalized]

declared={}
pattern=r"@JvmStatic\s+private\s+external\s+fun\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*(Array<String>|ByteArray|PrivateKey|Context|String|Long|Boolean|Int|Unit))?"
for m in re.finditer(pattern,k,re.S):
    name,parameters,return_type=m.group(1),m.group(2),m.group(3) or "Unit"
    params=re.findall(r"\w+\s*:\s*([A-Za-z<>?]+)",parameters)
    assert len(params)==len([s for s in parameters.split(",") if s.strip()]),name
    declared[name]="("+ "".join(map(descriptor,params))+")"+descriptor(return_type)
registered=dict(re.findall(
    r'\{const_cast<char\*>\("(\w+)"\),\s*const_cast<char\*>\("([^"]+)"\)',cpp,re.S))
assert declared and registered,(declared,registered)
assert declared==registered, {
    name:(declared.get(name),registered.get(name))
    for name in set(declared)|set(registered)
    if declared.get(name)!=registered.get(name)
}
count=re.search(r"RegisterNatives\(bridge,methods,(\d+)\)",cpp)
if count:
    assert int(count.group(1))==len(registered),(count,len(registered))
else:
    assert "RegisterNatives(bridge,methods,static_cast<jint>(sizeof(methods)/sizeof(methods[0])))" in cpp
assert len(registered)>=23,len(registered)
platform=(root/"android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudKeystorePlatform.kt").read_text()
required=("aliases","contains","delete","publicKey","privateKey","chain","generate")
for method in required:
    assert re.search(r"@JvmStatic\s+fun\s+"+method+r"\s*\(",platform),method
assert "privateKey.encoded" not in platform
catalog=(root/"android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CatalogEnvelope.kt").read_text()
assert "KeyPairGenerator" not in catalog and "PKCS8EncodedKeySpec" not in catalog
assert "beginCatalog()" in catalog and "openCatalogHandle" in catalog
print(f"PASS {len(registered)} native Kotlin JNI descriptors and Keystore platform bridge")
