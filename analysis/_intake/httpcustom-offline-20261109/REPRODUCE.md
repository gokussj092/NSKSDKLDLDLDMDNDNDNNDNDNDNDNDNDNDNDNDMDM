# Reproduction from repository root

Use the official sources and versions in dependencies.lock.json. No system
installation is required: unpack Mbed TLS to `$MBEDTLS_SOURCE`, nlohmann's
header to `$JSON_INCLUDE/nlohmann/json.hpp`, and Argon2 to `$ARGON2_SOURCE`.
Compile their static archives using the upstream makefiles. The corresponding
GitHub Actions recipe is `.github/workflows/offline-native-apk.yml`.

```sh
python3 -m venv .venv-offline
.venv-offline/bin/pip install pycryptodome==3.23.0 argon2-cffi==25.1.0 msgpack==1.1.1
python3 analysis/_intake/httpcustom-offline-20261109/tools/build_unicode_properties.py
git diff --exit-code -- android/app/src/main/cpp/spdecode_hc_unicode.h
g++ -O2 -std=c++17 -Wall -Wextra -Werror -pthread \
  -I"$MBEDTLS_SOURCE/include" -I"$JSON_INCLUDE" -I"$ARGON2_SOURCE/include" \
  tests/native_http_custom_cli.cpp \
  android/app/src/main/cpp/spdecode_http_custom.cpp \
  android/app/src/main/cpp/spdecode_http_custom_legacy.cpp \
  "$MBEDTLS_SOURCE/library/libmbedcrypto.a" "$ARGON2_SOURCE/libargon2.a" \
  -o /tmp/spdecode-hc-native
.venv-offline/bin/python tests/test_offline_hc_native_parity.py /tmp/spdecode-hc-native
.venv-offline/bin/python analysis/_intake/httpcustom-offline-20261109/tests/test_method.py /tmp/spdecode-hc-native
.venv-offline/bin/python analysis/_intake/httpcustom-offline-20261109/tools/verify_private_sample.py \
  /private/path/test.hc /tmp/spdecode-hc-native
```

Expected: 98 synthetic cases pass and private probe `complete_json_equal:true`.
Only hashes/counts/statuses are printed. Do not commit private sample/output.

Diagnostic attempt preserved: `tools/diagnose_legacy.py` recreates the local
temporary translation unit used to expose the swallowed UTF-8 exception.
It accepts an explicit base source file and output path and is never packaged
in Android. Compile that file in place of the legacy translation unit, adding
`-Iandroid/app/src/main/cpp`, to reproduce the pre-fix error with the private
probe. The operational source is not changed by this diagnostic.
