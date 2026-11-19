#!/usr/bin/env bash
# Build + run the host test for the offline native SSC decoder.
# Compiles android/app/src/main/cpp/spdecode_ssc.cpp UNCHANGED against
# nlohmann json (the exact single header pinned by
# android/app/src/main/cpp/CMakeLists.txt, SHA-256 verified when
# downloaded; falls back to the system header only if the download
# fails), using the host g++. No Android SDK/NDK, no device.
# The SSC ChaCha20 is hand-rolled in the production file (original DJB
# 64-bit nonce variant), so no Mbed TLS build is needed.
#
# Usage (from the repo root):
#   bash analysis/dev.epro.ssc/96/tools/build_host_harness.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
TOOLS="$ROOT/analysis/dev.epro.ssc/96/tools"
FIXTURES="$ROOT/analysis/dev.epro.ssc/96/tests/fixtures"
EXPECTED="$ROOT/analysis/dev.epro.ssc/96/tests/expected"
BUILD="${TMPDIR:-/tmp}/ssc-host-build"
# nlohmann json single header at the exact commit pinned by CMakeLists.txt
# (FetchContent GIT_TAG 9cca280a... = json 3.11.3).
JSON_SHA256="9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6"
JSON_URL="https://raw.githubusercontent.com/nlohmann/json/9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03/single_include/nlohmann/json.hpp"

mkdir -p "$BUILD"
if [ -f "$BUILD/include/nlohmann/json.hpp" ]; then
    echo "$JSON_SHA256  $BUILD/include/nlohmann/json.hpp" | sha256sum -c - \
        || rm -f "$BUILD/include/nlohmann/json.hpp"
fi
if [ ! -f "$BUILD/include/nlohmann/json.hpp" ]; then
    mkdir -p "$BUILD/include/nlohmann"
    if curl -fsSL -o "$BUILD/include/nlohmann/json.hpp" "$JSON_URL" && \
       echo "$JSON_SHA256  $BUILD/include/nlohmann/json.hpp" | sha256sum -c -; then
        echo "using pinned nlohmann json.hpp"
    else
        rm -f "$BUILD/include/nlohmann/json.hpp"
        if [ -f /usr/include/nlohmann/json.hpp ]; then
            echo "download unavailable; using system /usr/include/nlohmann/json.hpp"
            mkdir -p "$BUILD/include"
            ln -sfn /usr/include/nlohmann "$BUILD/include/nlohmann"
        else
            echo "ERROR: cannot fetch pinned json.hpp and no system header" >&2
            exit 1
        fi
    fi
fi

CXX="${CXX:-g++}"
"$CXX" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/android/app/src/main/cpp" \
    -I"$BUILD/include" \
    "$TOOLS/host_ssc_test.cpp" \
    -o "$BUILD/host_ssc_test"
echo "built $BUILD/host_ssc_test"
"$BUILD/host_ssc_test" "$FIXTURES" "$EXPECTED"
