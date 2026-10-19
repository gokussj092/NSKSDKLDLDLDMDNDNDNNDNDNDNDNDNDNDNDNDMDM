#!/usr/bin/env python3
"""C5 scan of physically compiled Android Cloud APK, no secret bytes printed."""
import re
import sys
import zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if len(sys.argv)!=2:raise SystemExit("Usage: python tests/cloud_c5_apk_audit.py cloud.apk")
with zipfile.ZipFile(sys.argv[1]) as z:
    names=z.namelist()
    native=[p for p in names if re.fullmatch(r"lib/[^/]+/libspdecode\.so",p)]
    assert native,"libspdecode.so not present"
    assets=[p for p in names if p.startswith("assets/")]
    # Release builds can add Android Gradle Plugin's generated ART/dexopt
    # baseline profiles. They contain optimization data, not decoder secrets.
    # Reject every other unknown asset, including vault/legacy material.
    permitted={
        "assets/decoder_catalog.json",
        "assets/dexopt/baseline.prof",
        "assets/dexopt/baseline.profm",
    }
    assert "assets/decoder_catalog.json" in assets,"Missing public decoder catalog"
    assert set(assets) <= permitted,"Unexpected bundled assets: "+str(sorted(set(assets)-permitted))
    assert not any(p.endswith(".spv") for p in names),"Vaulted decoder material bundled"
    dex=[p for p in names if re.fullmatch(r"classes[0-9]*\.dex",p)]
    assert dex,"No dex"
    content=b"".join(z.read(p) for p in dex)
    for token in (b"parity/EhiPort;",b"parity/HcPort;",b"parity/LegacyPortPrimitives;",
                  b"parity/SecureAssetVault;",b"TextPhaseGPort;",b"VaultBuildKey;"):
        assert token not in content,"Original local engine class still packaged: "+repr(token)
    original=(ROOT/"android/app/src/main/java/com/ghostdeveloper/spdecode/HttpInjectorCloudPort.kt").read_text()
    for name in ("SIGN_KEY","RESPONSE_KEY"):
        m=re.search(r'private const val '+name+r' = "([^"]+)"',original)
        assert m,"Original provider secret inventory mismatch"
        assert m.group(1).encode() not in content,"Provider secret still bundled: "+name
print("C5 Cloud APK verified: native HTTPS included, local decoders and secrets absent")
