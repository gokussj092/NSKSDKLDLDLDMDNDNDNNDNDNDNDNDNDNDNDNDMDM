#!/usr/bin/env bash
set -euo pipefail
# Production C++/JNI with synthetic Android framework inputs. No signing secrets.
work="${RUNNER_TEMP:-/tmp}/spdecode-release-signer-jni"
mkdir -p "$work/mbedtls" "$work/classes"
archive="$work/mbedtls-3.6.7.tar.bz2"
expected=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
if ! printf '%s  %s\n' "$expected" "$archive" | sha256sum -c - >/dev/null 2>&1; then
  curl -fsSL --retry 3 -o "$archive" https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
fi
printf '%s  %s\n' "$expected" "$archive" | sha256sum -c -
tar --no-same-owner -xf "$archive" -C "$work/mbedtls" --strip-components=1
make -C "$work/mbedtls/library" -j2 libmbedcrypto.a CFLAGS='-O2 -fPIC' > "$work/mbedtls-build.log" 2>&1
cat > "$work/cloud_origin.h" <<'CPP'
#include <string>
namespace {
std::string cloudOrigin(){return "https://api.spdecode.example";}
std::string cloudTransportPath(){return "/api/v2/transport";}
}
CPP
java_root="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
cpp=android/app/src/main/cpp
g++ -std=c++17 -DNDEBUG -O2 -fPIC -shared -Wall -Wextra -Werror \
  -I "$java_root/include" -I "$java_root/include/linux" -I "$work/mbedtls/include" -I "$work" \
  "$cpp/spdecode_transport.cpp" "$cpp/spdecode_hpke.cpp" "$cpp/spdecode_security.cpp" \
  "$cpp/spdecode_session.cpp" "$cpp/spdecode_keystore.cpp" "$cpp/spdecode_keystore_policy.cpp" \
  "$cpp/spdecode_catalog.cpp" "$cpp/spdecode_runtime_guard.cpp" "$cpp/spdecode_code_integrity.cpp" \
  "$work/mbedtls/library/libmbedcrypto.a" -lpthread -ldl -o "$work/libv7q3.so"
python3 scripts/ci/current_android_contracts.py --generate-host-java "$work/generated"
javac -d "$work/classes" \
  tests/native/v2_transport_jni/android/content/Context.java \
  tests/native/v2_transport_jni/android/content/pm/*.java \
  tests/native/v2_transport_jni/android/os/Build.java \
  tests/native/v2_transport_jni/ReleaseSignerContract.java \
  "$work/generated/CloudNativeTransport.java"
java -Xcheck:jni -Dspdecode.native="$work/libv7q3.so" -cp "$work/classes" \
  com.ghostdeveloper.spdecode.cloud.CloudNativeTransport
