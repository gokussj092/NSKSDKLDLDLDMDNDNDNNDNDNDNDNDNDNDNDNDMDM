# Dependencies executed — offline n15 (build 934)

State: implementation work; the host harness reuses exactly the pinned
sources the app already links. No dependency was added to the app.

| Component | Version | Function | Origin / license |
| --- | --- | --- | --- |
| Mbed TLS | 3.6.7 | SHA-256, HMAC/HKDF, XChaCha20-Poly1305, ChaCha20, Base64 | github.com/Mbed-TLS/mbedtls / Apache-2.0; tarball SHA-256 `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6` |
| nlohmann/json | 3.11.3 (system) / 9cca280a (git fallback) | Envelope/section JSON | github.com/nlohmann/json / MIT |
| Argon2 reference (phc-winner-argon2) | system libargon2 (0~20190702) / 62358ba2 (git fallback) | Argon2id password KDF (`argon2id_hash_raw`, `ARGON2_NO_THREADS`) | github.com/P-H-C/phc-winner-argon2 / Apache-2.0 + CC0 |
| g++ | 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) | Host harness compiler | system toolchain |
| CMake | 3.28.3 | Host harness build | system toolchain |
| CPython (reference venv) | 3.12.3 | Reference oracle + fixture builder + comparison runner | python.org / PSF |
| PyCryptodome (reference venv) | 4.4.0 | XChaCha20-Poly1305 encryption in the fixture builder; XChaCha20-Poly1305 decryption in the reference codec | pycryptodome.org / BSD |
| argon2-cffi (reference venv) | 25.1.0 | Argon2id in the Python reference codec | PyPI / MIT |

Linux x86_64 host. No third-party binaries are committed to Git; the
harness FetchContent downloads go to the out-of-tree build directory
(`/tmp/hc-n15-harness-build`). The production app build is unchanged
(no new Gradle/CMake dependency — the Argon2/Mbed TLS/json pins already
existed in `android/app/src/main/cpp/CMakeLists.txt`).

No network use at decode runtime: the offline decoder is fully local.
