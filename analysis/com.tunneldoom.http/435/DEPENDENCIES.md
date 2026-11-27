# Executed dependencies — TunnelDOOM VPN 4.3.5

- CPython 3.12.3, standard library: fixed-source acquisition, input limits,
  hashing, JSON validation (PSF).
- PyCryptodome 4.6.0: AES-256-CBC NoobCrypt field decryption
  (BSD/Public Domain).
- `curl` (system tool): old-host liveness check only; no download through it.
- androguard / jadx versions used by the batch-15 analyst are UNKNOWN here
  (not re-verified in this session); the decompiled sources they produced
  were read as text, and the crypto claims were re-verified by the live
  catalog decrypting with the unchanged keys.
- Python distribution archive hashes and transitive license review are
  UNKNOWN, not invented. Reproduction must review those artifacts before
  deployment.

All own scripts used for this re-analysis are the staged decoders
(`decoders/Python/apps/TunnelDOOM_VPN/`) and `tools/revalidate_435.py`.
No Frida, app instrumentation, or dynamic target execution was used.
