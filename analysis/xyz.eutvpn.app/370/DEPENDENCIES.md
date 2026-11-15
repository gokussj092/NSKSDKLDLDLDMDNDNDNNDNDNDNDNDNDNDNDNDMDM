# DEPENDENCIES — EUT VPN (xyz.eutvpn.app, versionCode 370)

Inventory of every tool, library and runtime really used during this
research, with the version really used. Nothing is invented: a version
that was not recorded is marked UNKNOWN with the reason.

| Tool / library | Version | Purpose |
|---|---|---|
| Python | 3.12.3 | Runtime of all operational and dossier scripts (stdlib only). |
| jadx | 1.5.3 | DEX decompilation (documented in the source TESTING.md files). |
| androguard | 4.1.4 | DEX/APK inspection helpers in work/ research scripts. |
| OpenSSL | 3.0.13 | Independent oracle for AES-CBC vectors in dossier tests. |
| PyCryptodome | 4.4.0 | Verification oracle only, in the research venv; NOT used by the operational scripts or the dossier tests. |
| argon2-cffi | 25.1.0 | Verification oracle only, in the research venv; NOT used by the operational scripts or the dossier tests. |
| Unicorn | 2.1.4 | Native emulation oracle during research (Ac Tunnel KDF, HTTP Tweak WyrLib); NOT used by the operational scripts. |
| paranoid-deobfuscator | 3.0.2 | Reference LSParanoid string deobfuscator (Ac Tunnel: 1983/1983 strings). |

## Notes

- The operational scripts (`EUT_VPN.py`, `EUT_VPN_archivos.py`) are **Python stdlib only** —
  no third-party dependency at runtime.
- `tools/crypto_pure.py` (this dossier) is a new pure-Python helper written
  for the dossier tests from the public FIPS-197 / XXTEA / Threefish
  specifications; it uses no third-party package.
- PyCryptodome 4.4.0 and argon2-cffi 25.1.0 were used ONLY as verification
  oracles in the research venv (`~/workspace/http-custom-update/venv`,
  versions read from its `pip list` on 2026-11-14). They are not imported
  by the operational scripts or by the dossier tests.
- jadx 1.5.3 is the version documented in the source TESTING.md files; the
  jadx binary is not installed in this VM, so its distribution hash is
  UNKNOWN (not recorded) — see dependencies.lock.json.
- `pytest` is NOT installed in this VM; the dossier tests run with the
  stdlib `unittest` module.
- The pinned lockfile is `dependencies.lock.json` (referenced from
  MANIFEST.json `dependencies`).
