# Dependencies executed — offline n19 (build 942)

State: implementation work; the host harness reuses exactly the pinned
sources the app already links. No dependency was added to the app, no
`CMakeLists.txt` or Kotlin file was touched, and `spdecode_http_custom.h`
is unchanged (no `.h.new` needed).

| Component | Version | Function | Origin / license |
| --- | --- | --- | --- |
| Mbed TLS | 3.6.7 | SHA-256, HMAC/HKDF, XChaCha20-Poly1305, ChaCha20, Base64 | github.com/Mbed-TLS/mbedtls / Apache-2.0; tarball SHA-256 `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6` (prebuilt static lib reused from the n15 harness build) |
| nlohmann/json | 3.11.3 (deb headers) / 9cca280a (git fallback) | Envelope/section JSON | github.com/nlohmann/json / MIT |
| Argon2 reference (phc-winner-argon2) | system libargon2 (0~20190702) / 62358ba2 (git fallback) | Argon2id password KDF (`argon2id_hash_raw`, `ARGON2_NO_THREADS`) | github.com/P-H-C/phc-winner-argon2 / Apache-2.0 + CC0 |
| g++ | 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) | Host harness compiler | system toolchain |
| CMake | 3.28.3 | Host harness build (reference recipe) | system toolchain |
| CPython (reference venv) | 3.12.3 | Reference oracle + fixture builder + comparison runner | python.org / PSF |
| PyCryptodome (reference venv) | 4.4.0 | XChaCha20-Poly1305 encryption in the fixture builder; decryption in the reference codec | pycryptodome.org / BSD |
| argon2-cffi (reference venv) | 25.1.0 | Argon2id in the Python reference codec | PyPI / MIT |

Linux x86_64 host. No third-party binaries are committed to Git; the
harness build is out-of-tree (`/tmp/hc942-build`). The production app
build is unchanged (no new Gradle/CMake dependency — the Argon2/Mbed
TLS/json pins already existed in `android/app/src/main/cpp/CMakeLists.txt`).

No network use at decode runtime: the offline decoder is fully local.
