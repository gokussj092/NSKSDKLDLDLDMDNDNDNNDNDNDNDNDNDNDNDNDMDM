#!/usr/bin/env bash
# Build + run the host test for the offline native ZIVPN decoder.
# Compiles android/app/src/main/cpp/spdecode_zivpn.cpp UNCHANGED against
# Mbed TLS 3.6.7 (the exact archive pinned by
# android/app/src/main/cpp/CMakeLists.txt, SHA-256 verified) and nlohmann
# json, using the host g++. No Android SDK/NDK, no device, no network
# beyond the one pinned download (skipped when SPDECODE_MBEDTLS_ARCHIVE
# points at a local copy, as CI does).
#
# Usage (from the repo root):
#   bash analysis/com.zi.zivpn/184/tools/build_host_harness.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
TOOLS="$ROOT/analysis/com.zi.zivpn/184/tools"
FIXTURES="$ROOT/analysis/com.zi.zivpn/184/tests/fixtures"
BUILD="${TMPDIR:-/tmp}/zivpn-host-build"
MBEDTLS_VERSION="3.6.7"
MBEDTLS_SHA256="a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6"
MBEDTLS_URL="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2"
# nlohmann json single header at the exact commit pinned by CMakeLists.txt
# (FetchContent GIT_TAG 9cca280a... = json 3.11.3).
JSON_SHA256="9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6"
JSON_URL="https://raw.githubusercontent.com/nlohmann/json/9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03/single_include/nlohmann/json.hpp"

mkdir -p "$BUILD"
if [ -n "${SPDECODE_MBEDTLS_ARCHIVE:-}" ] && [ -f "$SPDECODE_MBEDTLS_ARCHIVE" ]; then
    ARCHIVE="$SPDECODE_MBEDTLS_ARCHIVE"
else
    ARCHIVE="$BUILD/mbedtls-${MBEDTLS_VERSION}.tar.bz2"
    if [ ! -f "$ARCHIVE" ]; then
        curl -sL -o "$ARCHIVE" "$MBEDTLS_URL"
    fi
fi
echo "$MBEDTLS_SHA256  $ARCHIVE" | sha256sum -c -
if [ ! -d "$BUILD/mbedtls-${MBEDTLS_VERSION}" ]; then
    tar -xjf "$ARCHIVE" -C "$BUILD"
fi
if [ ! -f "$BUILD/mbedtls-build/library/libmbedcrypto.a" ]; then
    cmake -S "$BUILD/mbedtls-${MBEDTLS_VERSION}" -B "$BUILD/mbedtls-build" \
        -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "$BUILD/mbedtls-build" --target mbedcrypto -j"$(nproc)" >/dev/null
fi
if [ ! -f "$BUILD/include/nlohmann/json.hpp" ]; then
    mkdir -p "$BUILD/include/nlohmann"
    curl -sL -o "$BUILD/include/nlohmann/json.hpp" "$JSON_URL"
fi
echo "$JSON_SHA256  $BUILD/include/nlohmann/json.hpp" | sha256sum -c -

CXX="${CXX:-g++}"
"$CXX" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/android/app/src/main/cpp" \
    -I"$BUILD/mbedtls-${MBEDTLS_VERSION}/include" \
    -I"$BUILD/mbedtls-build/include" \
    -I"$BUILD/include" \
    "$TOOLS/host_zivpn_test.cpp" \
    "$BUILD/mbedtls-build/library/libmbedcrypto.a" \
    -o "$BUILD/host_zivpn_test"
echo "built $BUILD/host_zivpn_test"
"$BUILD/host_zivpn_test" "$FIXTURES"
