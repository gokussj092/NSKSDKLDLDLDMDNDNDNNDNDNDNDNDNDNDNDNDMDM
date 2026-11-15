#!/usr/bin/env python3
"""C5 scan of physically compiled Android Cloud APK, no secret bytes printed."""
import re
import sys
import zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if len(sys.argv) not in (2,3) or (len(sys.argv)==3 and sys.argv[2]!="--unity-ads"):
    raise SystemExit("Usage: python tests/cloud_c5_apk_audit.py cloud.apk [--unity-ads]")
unity_ads_qa = len(sys.argv)==3
with zipfile.ZipFile(sys.argv[1]) as z:
    names=z.namelist()
    native=[p for p in names if re.fullmatch(r"lib/[^/]+/libv7q3\.so",p)]
    assert native,"libv7q3.so not present"
    assets=[p for p in names if p.startswith("assets/")]
    # Release builds can add Android Gradle Plugin's generated ART/dexopt
    # baseline profiles. They contain optimization data, not decoder secrets.
    # Reject every other unknown asset, including vault/legacy material.
    permitted={
        "assets/decoder_catalog.json",
        "assets/dexopt/baseline.prof",
        "assets/dexopt/baseline.profm",
    }
    # Unity LevelPlay and Google Ads ship OMID / ad-viewer assets with the SDK.
    # Only allow these known public SDK resources in the explicit Unity QA build.
    if unity_ads_qa:
        ads_assets={
            "assets/ad-viewer/omid-session-client-v1.js",
            "assets/ad-viewer/omsdk-v1.js",
            "assets/iads/controllerVersion",
            "assets/iads/index.css",
            "assets/iads/index.html",
            "assets/iads/index.js",
            "assets/iads/mobileController.html",
            "assets/iads/mobileController.min.css",
            "assets/iads/sdk_controller.min.gz.js",
        }
        assert ads_assets <= set(assets), "Missing required Unity ad SDK resources"
        permitted |= ads_assets
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
