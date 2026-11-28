# REPRODUCE — VLX Tunnel VPN v1.11.24.2

Environment: Python 3.12.3; `cryptography` (AESGCM) or
`pycryptodome` (AES.MODE_GCM); `argon2-cffi` for the fast Argon2id
path (a pure-stdlib fallback is included but slow: ~15–20 s per
envelope open, so the full suite takes ~50 s). Verified with the
venv at `~/workspace/.venv-mehaf/bin/python` (cryptography 50.0.2,
pycryptodome 4.6.0, argon2-cffi 25.1.0; the worker image pins
pycryptodome 3.23.0 — the AES-GCM calls used are the same, but the
coordinator should run the worker suite against 3.23.0). Paths below
are repo-relative; from this staging root they work identically (the
staging tree mirrors the repo layout).

## 0. Format keys (not stored in this dossier)

```bash
export VLX_KEY_LIVE=<live key>      # live catalog
export VLX_KEY_FIELD=<field key>    # fields + bundled asset
export VLX_KEY_FILE=<file key>      # .vlx files
```

The values live only in the batch report
(`~/workspace/batch18-work/vlx-tunnel/REPORTE.md`). For the
synthetic tests only, the tools fall back to a TEST-ONLY password
when no key is configured — it opens no real catalog.

## 1. Dossier tests (synthetic fixtures only, no network)

```bash
~/workspace/.venv-mehaf/bin/python -m unittest discover \
  -s analysis/dev.jx.clickconnect/19/tests -v
# Expected: 9 passed (takes ~50 s: two full-parameter Argon2id
# round-trips run with the real derivation parameters).
```

Fixture: a synthetic catalog sealed with the TEST-ONLY password
(`tests/fixtures/synthetic_catalog.json`). No keys, no real
credentials, no live catalog bytes.

## 2. Live catalog (out-of-band, never stored in the repo)

```bash
export VLX_KEY_LIVE=... VLX_KEY_FIELD=...
~/workspace/.venv-mehaf/bin/python \
  analysis/dev.jx.clickconnect/19/tools/VLX_Tunnel_VPN.py \
  --catalog
# Expected: Version "23.794", 16 servers, 4,549/4,549 field
# envelopes decrypted. (The live Version changes over time.)
```

The fetch needs the mandatory `User-Agent: VLX Tunnel VPN`.

## 3. `.vlx` file

```bash
export VLX_KEY_FILE=...
~/workspace/.venv-mehaf/bin/python \
  analysis/dev.jx.clickconnect/19/tools/VLX_Tunnel_VPN_archivos.py \
  <archivo.vlx>
# Expected: the profile JSON. (The lote-18 sample muestra.vlx
# opens; no new v1.11.24.2 export was supplied.)
```

## 4. What is NOT reproducible (documented, not integrated)

`configfile.json`, the `/api/vlx/` blob and `/api/vlxnew/` do not
open with the live or field keys. No workaround is known; see
ANALYSIS.md §3.
