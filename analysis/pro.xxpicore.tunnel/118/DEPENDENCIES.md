# Actual tools and dependencies

Execution platform: Linux x86_64/glibc2.39; inspected ABI AArch64 Android.
The lock records exact runtime versions,43 installed Python distributions,
declared transitives, source URLs and available license metadata. Not every
installed package was used. Distribution hashes not retained are explicitly
null/NEEDS_REVIEW; none are invented. Central approval for automatic Phase7
reuse remains pending. Only manually reviewed isolated primitives ran here.

| Tool | Actual version | Purpose / import | Origin / license |
|---|---|---|---|
|CPython|3.12.14|Orchestration, unittest, urllib, hashlib, struct, metadata|python.org; PSF|
|Androguard|4.1.4|APK manifest/resources, DEX class inventory|github.com/androguard/androguard; Apache2.0|
|Pillow|13.0.0|Inspect original PNG dimensions, no image rewrite|python-pillow.org; MIT-CMU metadata|
|PyCryptodome|3.23.0|`Crypto.Cipher.AES`, PKCS7|pycryptodome.org; BSD/Public Domain metadata|
|pyelftools|0.33|`ELFFile`, symbols and relocations|github.com/eliben/pyelftools; Public domain metadata|
|Capstone|5.0.9|ARM64 offline disassembly|github.com/capstone-engine/capstone; license metadata UNKNOWN, NEEDS_REVIEW|
|Unicorn|2.1.4|Bounded offline ARM64 primitive emulation|github.com/unicorn-engine/unicorn; package metadata BSD License, upstream redistribution terms NEEDS_REVIEW|
|Loguru|0.7.3|Suppress third-party inspection logs|github.com/Delgan/loguru; metadata UNKNOWN, NEEDS_REVIEW|
|OpenJDK|17.0.20+8|Independent JCA reference, string arithmetic|openjdk.org; distribution terms NEEDS_REVIEW|
|JADX|1.5.6|Read DEX code, simple mode,4 workers,2200MiB heap|github.com/skylot/jadx; Apache2.0; pinned ZIP/JAR hashes in lock|
|Node.js|24.22.1|Cloud broker, gateway, controls and tests|nodejs.org; MIT/third-party terms NEEDS_REVIEW|
|curl|8.5.0, Ubuntu8.5.0-2ubuntu10.13|Original authorized acquisition|curl.se; distribution and linked-library terms NEEDS_REVIEW|

Only acquisition/public GET require network. Production worker is offline and
imports PyCryptodome plus unchanged project primitives; it does not need JADX,
Androguard, Java, Capstone or Unicorn. Node uses built-in modules, no added npm
dependency. Existing web package/lock remain unchanged.

Project-owned tools in tools/ and shared scripts in scripts/apk_analysis/ are
hash-listed in MANIFEST/lock. Shared inspector/JADX/resolver/ELF/emulation
interfaces are unchanged. Shared primitives: `decoders/Python/renz.py` and
`apps/Xhypher_Tunnel_Pro/codec.py`, as present at base commit
`a729c86849312f43d1748b16e52d6de3b449d132`; no changes to those files are proposed.
Own oracle derives from existing project references, not redistributed APK
source/native binaries. Lock includes the complete existing venv for audit;
cryptography, lxml, asn1crypto and other packages are inspection transitives or
installed inventory, not new production dependencies.
