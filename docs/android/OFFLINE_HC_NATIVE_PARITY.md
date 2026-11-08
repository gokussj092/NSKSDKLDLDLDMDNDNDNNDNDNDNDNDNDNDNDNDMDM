# SP-DECODE Offline HC C++ differential suite

Native library `liboffdecode.so` now links an isolated C++ HTTP Custom
module. It has no Kotlin/Python runtime implementation in the APK.

Host CI builds the **same C++ source** with system Mbed TLS, Argon2 and
nlohmann JSON. It compares all HCX4 build-899 modes against the repository's
independent Python reference generator: no credentials, password, HWID,
password + HWID; 0/1/2 UTF-8-Latin1 carriers; nested options and metadata;
tampered outer, slot, main, profile, HPR1 and sidecar tags; incorrect and
missing credentials. This checks cryptography and JSON parity on Linux,
**not** on-device execution or real exporter certification.

Historical HCCFG 1/2/5/7 has a native code path but requires its own
differential fixtures. The pre-HCCFG legacy .hc XOR+ChaCha8 formats are **not
implemented in C++** and must not fall back to Kotlin or Cloud. They fail
with `HC_UNRECOGNIZED_FORMAT`. The UI should surface this limitation.

Integration files: `spdecode_http_custom.{h,cpp}`,
`spdecode_offline_native.cpp`, `CMakeLists.txt`. Pure C++ one binary target;
split by source files instead of packaging multiple unnecessary .so files.
