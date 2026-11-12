# Dependencies used

Exact versions, available hashes and source URLs are in dependencies.lock.json.

| Tool | Purpose | Runtime use |
| --- | --- | --- |
| Python 3.12.14 / stdlib | framing, AXML/ZIP inventory, frozen fixtures, tests | server already uses Python |
| PyCryptodome 3.23.0 | ChaCha stream in existing Python codec | existing server dependency |
| Mbed TLS 3.6.7 | C++ ChaCha/Poly1305 and native parity | existing Offline static library |
| nlohmann JSON 3.11.3 | native structured data and parity | existing Offline dependency |
| Argon2 20190702 | unchanged modern HC regressions | existing Offline dependency |
| libsodium 1.0.18 | independent original-AEAD fixture generator | host research only |
| JADX 1.5.6 / Java 21 | authorized DEX model analysis | host research only |
| Capstone 5.0.7 | read-only ARM64 instruction inventory | host research only |
| pyelftools 0.32 | ELF segments/relocations | host research only |
| Unicorn 2.1.4 | bounded local JNI string-codec oracle | host research only |

No new Android or server package was introduced. The new Python module reuses
existing PyCryptodome and the repository's pure Poly1305 implementation; the
new C++ path uses existing Mbed TLS. Native dependency downloads remain the
existing pinned build sources. Analysis packages were installed in an isolated
host venv; installed Python transitives are frozen in the lock.

Sources: official Mbed-TLS, nlohmann/json, P-H-C/phc-winner-argon2, jedisct1/libsodium,
skylot/jadx, capstone-engine/capstone, eliben/pyelftools and unicorn-engine/unicorn
projects, and their official Python distributions. See the lock for provenance.
JADX: Apache-2.0; pyelftools metadata: public domain; Capstone: BSD project
license (distribution metadata lacked a license field: NEEDS_REVIEW); Unicorn
binding metadata: BSD, core redistribution terms NEEDS_REVIEW. These tools and
third-party binaries are not redistributed in Git or the APK.

This does not approve any new unattended F7 adapter or dependency installation.
The oracle's incomplete Java/JNI shims and omission of application startup mean
it certifies the listed primitive vectors only. No VPN connection was made.

Node.js 24.22.1 (https://nodejs.org/, MIT) ran the broker/HC integration tests. These use only built-in modules; no additional npm dependency was installed. Android/Gradle source and pinned toolchain remain unchanged.
