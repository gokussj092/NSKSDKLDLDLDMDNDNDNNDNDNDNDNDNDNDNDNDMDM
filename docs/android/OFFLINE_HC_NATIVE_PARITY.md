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

Historical HCCFG schemas 1/2/5/7 now have native C++ paths and are covered
by independent synthetic Python reference fixtures: password-only and HWID
or dual lock (including HPR1, sidecar and tampered tags). Legacy pre-HCCFG
XOR + original 64-bit-nonce ChaCha20 + AES-RST + JKL is independently ported
to spdecode_http_custom_legacy.cpp and a preexisting A.2.3 golden is tested.
The code uses native-only C++ for cryptography. The host differential suite
passes **69 synthetic cases**. Real exporter/device certification and
additional legacy-version compatibility remain outstanding. The original
legacy scheme lacks authenticated tags; parsing must never be described as
strong authenticated decryption.

Integration files: `spdecode_http_custom.{h,cpp}`,
`spdecode_http_custom_legacy.{h,cpp}`, `spdecode_offline_native.cpp`,
`CMakeLists.txt`. Pure C++ one binary target;
split by source files instead of packaging multiple unnecessary .so files.
