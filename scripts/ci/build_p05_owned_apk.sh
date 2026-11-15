#!/usr/bin/env bash
# Build a first-party disposable signed Android APK. Never use external samples.
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "usage: build_p05_owned_apk.sh OUTPUT_DIRECTORY" >&2; exit 2; fi
OUTPUT="$(mkdir -p "$1" && cd "$1" && pwd -P)"
SDK="$(printenv ANDROID_HOME || printenv ANDROID_SDK_ROOT || true)"
if [[ -z "$SDK" || ! -d "$SDK/build-tools" || ! -d "$SDK/platforms" ]]; then
  echo "P05: Android SDK is unavailable" >&2; exit 2
fi
TOOLS="$(find "$SDK/build-tools" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)"
ANDROID_JAR="$(find "$SDK/platforms" -mindepth 1 -maxdepth 2 -name android.jar | sort -V | tail -1)"
for tool in aapt2 d8 zipalign apksigner; do
  if [[ ! -x "$TOOLS/$tool" ]]; then echo "P05: build tool missing" >&2; exit 2; fi
done
if [[ ! -f "$ANDROID_JAR" ]]; then echo "P05: android.jar unavailable" >&2; exit 2; fi
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src/org/spdecode/p05fixture" "$WORK/classes" "$WORK/dex"
cat > "$WORK/AndroidManifest.xml" <<'MANIFEST'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.spdecode.p05fixture"
    android:versionCode="1" android:versionName="1.0">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28" />
    <application android:label="SP-DECODE P05 Owned Lab" android:hasCode="true" />
</manifest>
MANIFEST
cat > "$WORK/src/org/spdecode/p05fixture/Lab.java" <<'JAVA'
package org.spdecode.p05fixture;
public final class Lab {
    public static int answer() { return 42; }
    private Lab() {}
}
JAVA
javac --release 8 -d "$WORK/classes" "$WORK/src/org/spdecode/p05fixture/Lab.java"
"$TOOLS/d8" --min-api 23 --output "$WORK/dex" "$WORK/classes/org/spdecode/p05fixture/Lab.class"
[[ -s "$WORK/dex/classes.dex" ]] || { echo "P05: DEX missing" >&2; exit 1; }
"$TOOLS/aapt2" link --manifest "$WORK/AndroidManifest.xml" -I "$ANDROID_JAR" \
    --min-sdk-version 23 --target-sdk-version 28 -o "$WORK/unsigned.apk"
(cd "$WORK/dex" && zip -q "$WORK/unsigned.apk" classes.dex)
"$TOOLS/zipalign" -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
# Ephemeral test keystore. The key and password are never committed/uploaded.
export P05_TEST_PASS
P05_TEST_PASS="$(openssl rand -hex 16)"
keytool -genkeypair -noprompt -alias p05 -keyalg RSA -keysize 2048 \
    -validity 2 -keystore "$WORK/p05.jks" -storepass "$P05_TEST_PASS" \
    -keypass "$P05_TEST_PASS" -dname "CN=SP-DECODE P05 Synthetic QA"
"$TOOLS/apksigner" sign --ks "$WORK/p05.jks" --ks-key-alias p05 \
    --ks-pass env:P05_TEST_PASS --key-pass env:P05_TEST_PASS \
    --out "$OUTPUT/owned-signed.apk" "$WORK/aligned.apk"
"$TOOLS/apksigner" verify "$OUTPUT/owned-signed.apk"
# APKS-shaped wrapper, NOT an installable bundletool split-set.
cp "$OUTPUT/owned-signed.apk" "$WORK/base.apk"
printf "P05 synthetic APKS outer wrapper\n" > "$WORK/toc.pb"
(cd "$WORK" && zip -q -0 "$OUTPUT/owned-container.apks" base.apk toc.pb)
python3 - "$OUTPUT" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(root / "negative-ratio.apk", "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00\x08\x00\x00\x00")
    z.writestr("assets/oversized-compression", b"\x00" * (1 << 20))
PY
echo "P05: owned signed APK, APKS-shaped wrapper and negative fixture created"
