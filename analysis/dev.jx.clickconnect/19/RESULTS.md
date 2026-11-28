# RESULTS — VLX Tunnel VPN v1.11.24.2 (`dev.jx.clickconnect`, code 19)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| Catalog (live) | **VERIFIED_REAL** | Live fetch 2026-11-28: Version 23.794, 16 servers, 731 networks, 621 payloads, 4,549/4,549 field envelopes decrypted, 0 failures |
| Catalog (bundled `api`) | **VERIFIED_REAL** | Bundled asset opens with the field key (older snapshot) |
| `.vlx` file | **VERIFIED_REAL** | Lote-18 sample `muestra.vlx` re-verified (opens); no new v1.11.24.2 export supplied |
| Text links | **VERIFIED_SYNTHETIC** | Round-trip vmess/vless/trojan/ss (standard forms) |
| `configfile.json` | **FAILED** | 680,700 B asset; does not open with the live or field key; 20 sample servers undecrypted |
| `/api/vlx/` blob | **FAILED** | 793,236 B Base64; envelope-like layout, opens with neither key |
| `/api/vlxnew/` | **FAILED** | POST returns `Invalid hash`; hash format undetermined |
| SSH login (catalog or profile) | **PENDING** | Only the catalog was decrypted; no login attempted |

## Tests run (2026-11-28, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, cryptography 50.0.2, pycryptodome 4.6.0, argon2-cffi 25.1.0)

- `python3 -m unittest discover -s analysis/dev.jx.clickconnect/19/tests`:
  **9 passed in 52.4 s** (envelope layout, tampered-tag/truncated/
  wrong-password negatives, deterministic Argon2id, small-parameter
  round-trip, field envelope in profile, full-parameter round-trips
  for catalog and `.vlx` file).
- Live verification (batch analyst, same venv):
  catalog fetch → Version 23.794, 16 servers, 4,549/4,549 fields.
  `muestra.vlx` opens. `configfile.json` / `/api/vlx/` / `/api/vlxnew/`
  all failed as documented.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- Only the decrypted part is integrated: `configfile.json`, the
  `/api/vlx/` blob and `/api/vlxnew/` are excluded.
- The live and field keys are no longer in the new `libgojni.so`
  `.rodata`; they must be carried forward via environment variables.
- The pure-stdlib Argon2id fallback is slow (~15–20 s per envelope);
  use `argon2-cffi` in the worker.
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-GCM calls used are API-stable across both, but
  the coordinator should run the worker suite against 3.23.0.
