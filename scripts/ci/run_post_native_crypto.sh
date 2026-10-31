#!/usr/bin/env bash
set -euo pipefail
# Host validation only. No app signer, VPS configuration or production keys.
work="${RUNNER_TEMP:-/tmp}/spdecode-crypto-qa"
mkdir -p "$work/mbedtls"
curl -fsSL --retry 3 -o "$work/mbedtls.tar.bz2" https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
printf '%s  %s\n' a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6 "$work/mbedtls.tar.bz2" | sha256sum -c -
tar --no-same-owner -xf "$work/mbedtls.tar.bz2" -C "$work/mbedtls" --strip-components=1
cmake -S "$work/mbedtls" -B "$work/build" -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON > "$work/config.log"
cmake --build "$work/build" --target mbedcrypto --parallel 2 > "$work/build.log"
cpp=android/app/src/main/cpp
lib="$work/build/library/libmbedcrypto.a"
for unit in security session; do
  g++ -std=c++17 -O2 -Wall -Wextra -Werror -I "$work/mbedtls/include" "tests/native_${unit}_contract.cpp" "$cpp/spdecode_${unit}.cpp" "$lib" -lpthread -o "$work/$unit"
  "$work/$unit"
done
for unit in hpke catalog; do
  g++ -std=c++17 -O2 -Wall -Wextra -Werror -I "$work/mbedtls/include" "tests/native_${unit}_cli.cpp" "$cpp/spdecode_${unit}.cpp" "$lib" -lpthread -o "$work/$unit"
done
node tests/native_hpke_node_roundtrip.mjs "$work/hpke"
node tests/native_catalog_roundtrip.mjs "$work/catalog"
# Syntax-check JNI with actual official JDK/crypto headers; Android linking is
# independently checked by the release job against each NDK ABI.
cat > "$work/cloud_origin.h" <<'CPP'
#include <string>
namespace { std::string cloudOrigin(){return "https://example.invalid";} std::string cloudTransportPath(){return "/api/v2/transport";} }
CPP
g++ -std=c++17 -DNDEBUG -O2 -Wall -Wextra -Werror -fsyntax-only -I "$JAVA_HOME/include" -I "$JAVA_HOME/include/linux" -I "$work/mbedtls/include" -I "$work" "$cpp/spdecode_transport.cpp"
printf 'PASS native JNI syntax, HPKE/P-256 roundtrips and session/proof contracts\n'
