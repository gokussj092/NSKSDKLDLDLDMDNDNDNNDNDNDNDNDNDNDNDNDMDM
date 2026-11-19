# REPRODUCE — ZIVPN Tunnel (com.zi.zivpn, versionCode 184) — OFFLINE

Environment: Python 3.12.3, g++ 13.3.0, CMake 3.28.3, OpenSSL 3.0.13,
PyCryptodome 4.5.0, Linux x86_64. `pytest` is NOT installed in this VM,
so the dossier tests run with `unittest` (stdlib).

## 1. Dossier tests (offline, synthetic, no secrets)

```bash
cd analysis/com.zi.zivpn/184
python3 -m unittest tests.test_method -v
python3 tools/verify.py
```

Expected: all tests pass (9 unittest tests; `VERIFY OK`). They use
synthetic vectors only and never touch the network.

Regenerate the fixtures (deterministic — fixed salt/iv):

```bash
python3 tools/make_fixtures.py
git status --short tests/fixtures/   # must be clean afterwards
```

## 2. Host harness: production C++ unchanged (Mbed TLS 3.6.7)

```bash
bash analysis/com.zi.zivpn/184/tools/build_host_harness.sh
```

This downloads the Mbed TLS 3.6.7 archive pinned by
`android/app/src/main/cpp/CMakeLists.txt` (SHA-256 verified; skipped
when `SPDECODE_MBEDTLS_ARCHIVE` points at a local copy, as CI does)
and the nlohmann json 3.11.3 single header at the commit pinned by the
same CMakeLists (SHA-256 verified), builds `libmbedcrypto`, compiles
`tools/host_zivpn_test.cpp` — which includes the production
`spdecode_zivpn.cpp` unchanged — with `-Wall -Wextra -Werror`, and runs
it against `tests/fixtures/`. Expected: `21 passed, 0 failed`.

Run the harness through the dossier verifier as well:

```bash
python3 tools/verify.py --harness /tmp/zivpn-host-build/host_zivpn_test
```

## 3. Repo parity test (same pattern as Dark Tunnel / HTTP Custom)

```bash
# Mbed TLS 3.6.7 line (Android pin), after step 2:
g++ -O2 -std=c++17 -Wall -Wextra -Werror \
  tests/native_zivpn_cli.cpp \
  android/app/src/main/cpp/spdecode_zivpn.cpp \
  -I/tmp/zivpn-host-build/mbedtls-3.6.7/include \
  -I/tmp/zivpn-host-build/mbedtls-build/include \
  -I/tmp/zivpn-host-build/include \
  /tmp/zivpn-host-build/mbedtls-build/library/libmbedcrypto.a \
  -o /tmp/spdecode-zivpn-native
python3 tests/test_offline_zivpn_native_parity.py /tmp/spdecode-zivpn-native
```

Expected: `Ran 13 tests ... OK`. In CI the same test compiles against
the system `libmbedtls-dev` (2.28 line); the production code carries a
version branch for the PBKDF2/SHA-256 entry points that differ between
2.28 and 3.x (see `spdecode_zivpn.cpp`, `pbkdf2Sha256` / `sha256`).

## 4. What is NOT reproducible here

- The Gradle/Android build (no Android SDK/NDK in this VM). It runs in
  CI (`.github/workflows/offline-native-apk.yml`, `zivpn-cpp-parity`
  job + `build` job).
- An emulator/device run of the offline APK.
- A real `zivpn://` link (none supplied; see RESULTS.md). A real
  exported `.ziv` file WAS supplied (2026-11-18) and now opens in the
  native decoder and the oracle; it is kept out of the repo because it
  contains user credentials (RESULTS.md §9).
- A live catalog download (out of scope for the offline app).
