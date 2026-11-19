# DEPENDENCIES — ZIVPN Tunnel (com.zi.zivpn, versionCode 184) — OFFLINE

Inventory of every tool, library and dependency actually used for this
offline investigation, implementation and verification. Versions are the
ones really used; unknown versions are marked UNKNOWN, never invented.

## Production (shipped in the offline APK)

| ID | Name / provider | Type | Version | Purpose | License / origin |
| --- | --- | --- | --- | --- | --- |
| dep-mbedtls | Mbed TLS (Mbed-TLS/mbedtls) | C library, static | 3.6.7 | AES-GCM/CBC, DES, PBKDF2-HMAC-SHA256, SHA-256, Base64 in `spdecode_zivpn.cpp` | Apache-2.0; pinned archive in `android/app/src/main/cpp/CMakeLists.txt`, SHA-256 `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6` |
| dep-json | nlohmann json (nlohmann/json) | C++ header-only | 3.11.3 (commit `9cca280a`) | JSON output of decoded properties in `spdecode_zivpn.cpp` | MIT; pinned commit in `android/app/src/main/cpp/CMakeLists.txt` |
| dep-ndk | Android NDK | toolchain | 27.2.12479018 | Builds `liboffdecode` (not run in this VM; CI) | Android SDK license; pinned in `android/app/build.gradle.kts` |

## Dossier oracle, fixtures and tests (not shipped)

| ID | Name / provider | Type | Version | Purpose | License / origin |
| --- | --- | --- | --- | --- | --- |
| dep-python | Python | runtime | 3.12.3 | Runs the dossier oracle, fixture generator and tests | PSF |
| dep-pycryptodome | PyCryptodome | PyPI package | 4.5.0 | Independent crypto oracle in `tools/zivpn_reference.py` and `tests/test_offline_zivpn_native_parity.py` (PBKDF2/GCM/DES/AES-CBC) | BSD-2-Clause; system Python in this VM; CI parity installs `pycryptodome==3.23.0` in a venv |
| dep-openssl | OpenSSL CLI | system tool | 3.0.13 | FIPS DES/AES known-answer oracle in `tools/verify.py` (DES via the legacy provider) | Apache-2.0 |
| dep-gxx | g++ (Ubuntu) | compiler | 13.3.0 | Host compiler for the harness and the parity CLI (`-std=c++17 -Wall -Wextra -Werror`) | GPL |
| dep-cmake | CMake | build tool | 3.28.3 | Builds `libmbedcrypto` for the host harness | BSD-3-Clause |
| dep-mbedtls-228 | Mbed TLS (Mbed-TLS/mbedtls) | C library, static | 2.28.8 | Second line verified for the CI host-parity path (system `libmbedtls-dev` line); production code carries a version branch for its PBKDF2/SHA-256 entry points | Apache-2.0; tag `mbedtls-2.28.8` |

## Tools

| ID | Name | Version | Purpose |
| --- | --- | --- | --- |
| dep-jadx | jadx | 1.5.3 | DEX decompilation in the 2026-11-14/15 research (online dossier, not re-run here) |
| dep-androguard | androguard | 4.1.4 | DEX/APK inspection helpers in the 2026-11-14/15 research (online dossier, not re-run here) |

## Notes

- No new dependency is introduced by the production code: Mbed TLS
  and nlohmann json are already the offline native build's crypto/JSON
  libraries.
- The DES entry points (`mbedtls_des_*`) are enabled by default in both
  Mbed TLS 3.6.7 and 2.28.8 (`MBEDTLS_DES_C` in the default config).
- The PBKDF2/SHA-256 version branch exists because 2.28 only has the
  `mbedtls_md_context_t` PBKDF2 entry point while 3.x deprecates it in
  favour of `mbedtls_pkcs5_pbkdf2_hmac_ext`; both compute the same
  PBKDF2-HMAC-SHA256, and both lines are host-tested 21/21.
- No network is needed by the decoders or the dossier tests, except the
  one-time pinned downloads for the host harness (Mbed TLS 3.6.7 archive
  + nlohmann json 3.11.3 single header, both SHA-256 verified).
