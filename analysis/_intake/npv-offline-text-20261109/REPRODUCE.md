# Reproduction from repository root

Use the same pinned host dependencies as the HTTP Custom intake and the
official native source archives listed in dependencies.lock.json. The
canonical commands also run in `.github/workflows/offline-native-apk.yml`.

```sh
python3 scripts/build_offline_npv_tables.py --output /tmp/spdecode_npv_tables.h
g++ -O2 -std=c++17 -Wall -Wextra -Werror -pthread -I/tmp \
  -I"$MBEDTLS_SOURCE/include" -I"$JSON_INCLUDE" \
  tests/native_npv_cli.cpp \
  android/app/src/main/cpp/spdecode_npv_signed.cpp \
  android/app/src/main/cpp/spdecode_npv_whitebox.cpp \
  android/app/src/main/cpp/spdecode_npv_text.cpp \
  android/app/src/main/cpp/spdecode_npv_legacy.cpp \
  "$MBEDTLS_SOURCE/library/libmbedcrypto.a" -lz -o /tmp/spdecode-npv-native
.venv-offline/bin/python analysis/_intake/npv-offline-text-20261109/tools/verify.py /tmp/spdecode-npv-native
```

Expected: 85 cases passed. Inputs are synthetic, credentials are supplied via
stdin framing, and no third-party VPN service is contacted. Source-only
recipe under tools delegates to the canonical tests rather than duplicating
the whitebox or test generator.
