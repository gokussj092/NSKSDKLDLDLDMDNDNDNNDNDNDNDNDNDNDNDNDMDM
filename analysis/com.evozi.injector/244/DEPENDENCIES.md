# Dependencies

- Python 3.12.14: https://python.org/, PSF-2.0.
- androguard 4.1.3: https://github.com/androguard/androguard, Apache-2.0.
- loguru 0.7.3: https://github.com/Delgan/loguru, MIT.

Linux x86_64; installed research environment and transitive versions are recorded once in analysis/_intake/hmac-auth-audit-2026-11-09/dependencies.lock.json, referenced by path/SHA256 in the build lock. Existing distribution archives/checksums are UNKNOWN, not fabricated or approved for unattended execution. No third-party binary is committed. Standard-library zipfile/hashlib/json/importlib inspect data only. Speicers acquisition reuses analysis/com.tunneldoom.http/432/tools/acquire.py without modifying it.

Catalog reinvestigation additions (Linux x86_64 host, ARM64 input data):

| Dependency | Observed version | Purpose | Source / license |
| --- | --- | --- | --- |
| PyCryptodome | 3.23.0 | ARC4 decoding of two native containers as data; not service authentication | https://www.pycryptodome.org/ / BSD-2-Clause, public-domain portions |
| libzstd (host shared library) | 1.5.7 | Bounded decompression of the documented frame through Python ctypes | https://github.com/facebook/zstd / BSD-3-Clause option |
| GNU readelf / Binutils | 2.44 | Manual ELF metadata inspection; no APK code execution | https://www.gnu.org/software/binutils/ / GPL-3.0-or-later |

The historical unpacker is an owned repo script, copied verbatim from commit `03bc9fe3c20a464dd1ea3848850b2d0227f5f477`; its source path and checksum are in MANIFEST. Distribution/package hashes for these preinstalled additions are UNKNOWN, so this records an observed research environment, not an approved automatic installer. Native inputs and recovered artifacts remain private. No Android runtime, Frida, Ghidra or JADX execution was used in this catalog recipe. The existing Paranoid helper was inspected but not executed; it does not establish a recovered catalog request.
