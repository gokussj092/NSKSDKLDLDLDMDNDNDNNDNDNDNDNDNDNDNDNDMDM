#!/usr/bin/env bash
# Build + run the host test for the offline native TLS Tunnel decoder.
# Compiles android/app/src/main/cpp/spdecode_tls_tunnel.cpp UNCHANGED
# against Mbed TLS 3.6.7 (the exact archive pinned by
# android/app/src/main/cpp/CMakeLists.txt, SHA-256 verified by CMake
# FetchContent) and nlohmann json 3.11.3, using the host g++. No Android
# SDK/NDK, no device. One pinned network download (skipped when
# SPDECODE_MBEDTLS_ARCHIVE points at a local copy, as CI does).
#
# Usage (from the repo root):
#   bash analysis/com.tlsvpn.tlstunnel/516/tools/build_host_harness.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
DOSSIER="$ROOT/analysis/com.tlsvpn.tlstunnel/516"
BUILD="${TMPDIR:-/tmp}/tls-harness-build"
cmake -S "$DOSSIER/tools/host_harness" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD" -j"$(nproc)"
echo "built $BUILD/tls_harness"
~/workspace/http-custom-update/venv/bin/python "$DOSSIER/tools/run_harness.py" \
    --harness "$BUILD/tls_harness"
