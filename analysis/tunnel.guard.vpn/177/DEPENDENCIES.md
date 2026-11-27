# Executed dependencies — TunelGuard VPN 17.7

- CPython 3.12.3, standard library: fixed-source acquisition, input limits,
  hashing, JSON validation (PSF).
- PyCryptodome 4.6.0: AES-256-GCM envelope/field decryption in the staged
  codec (BSD/Public Domain). The analyst's original scripts use the
  `cryptography` package (50.0.2 in the analysis venv) for the same
  primitive; the staged port uses the repo's pinned PyCryptodome instead
  so no new dependency is introduced.
- jadx 1.5.3: analyst decompilation of the APK (batch 15).
- Capstone: analyst disassembly of `libfrkudp.so` (batch 15); version
  UNKNOWN here, not invented.
- Python distribution archive hashes and transitive license review are
  UNKNOWN, not invented. Reproduction must review those artifacts before
  deployment.

All own scripts used for this re-analysis are the staged decoders
(`decoders/Python/apps/TunelGuard_VPN/codec.py`,
`server_catalog_decoder.py`) and `tools/revalidate_177.py`. The analyst
originals (`tunelguard.py`, `tunelguard_archivos.py`) are referenced in
the manifest; their method was ported into the repo structure, not
copied verbatim, because the repo splits codec/download/file roles
across three files. No Frida, app instrumentation, or dynamic target
execution was used.
