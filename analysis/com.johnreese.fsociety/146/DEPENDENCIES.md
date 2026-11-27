# Executed dependencies — REESE TUNNEL 3.23.28

- CPython 3.12.3, standard library: decoder runtime and tests (PSF).
- `cryptography` 50.0.2: AES-256-GCM for RSE5 in the analysis venv; the
  staged script falls back to PyCryptodome 4.6.0 (BSD/Public Domain)
  when `cryptography` is absent.
- Unicorn: analyst native oracle (`rse5Seal`/`rse5Open` emulation, batch
  15); version UNKNOWN here, not invented. The oracle cross-check
  (36/36) is recorded from the batch-15 run, not re-executed in this
  session (it needs the APK's `librse5.so`).
- Python distribution archive hashes and transitive license review are
  UNKNOWN, not invented. Reproduction must review those artifacts before
  deployment.

All own scripts used for this re-analysis are the staged decoder
(`decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py`) and
`tools/revalidate_146.py`. No Frida, app instrumentation, or dynamic
target execution was used.
