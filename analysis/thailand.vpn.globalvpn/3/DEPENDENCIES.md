# Dependencies and actual tooling

- Python 3.12.14: https://python.org/, PSF-2.0.
- OpenJDK 21.0.13: https://openjdk.org/, GPL-2.0-with-Classpath-exception.
- Node.js 24.22.1 local /22 CI: https://nodejs.org/, MIT.
- JADX 1.5.6: https://github.com/skylot/jadx, Apache-2.0.
- sharp 0.35.5: https://sharp.pixelplumbing.com/, Apache-2.0.
- androguard 4.1.3: https://github.com/androguard/androguard, Apache-2.0.
- capstone 5.0.6: https://www.capstone-engine.org/, BSD-3-Clause.
- cryptography 50.0.2: https://cryptography.io/, Apache-2.0 OR BSD-3-Clause.
- pyelftools 0.32: https://github.com/eliben/pyelftools, Public-Domain.

Linux x86_64. Python/Java perform offline inventory and independent oracles; Pillow extracts original PNG pixels; capstone/pyelftools statically read native ELF; cryptography provides the separate AR PRO XTS/GCM reference. No third-party binaries are committed. Relevant versions and full installed Python environment are in dependencies.lock.json; unavailable distribution hashes are explicitly UNKNOWN. sharp0.35.5 and server transitive versions/integrities are pinned by cloud/web/package-lock.json.
