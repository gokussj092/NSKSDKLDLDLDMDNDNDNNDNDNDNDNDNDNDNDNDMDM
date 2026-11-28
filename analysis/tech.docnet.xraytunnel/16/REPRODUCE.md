# REPRODUCE — V2Ray Injector 1.4.2

Environment: Python 3.12.3; `cryptography` (AESGCM) or
`pycryptodome` (AES.MODE_GCM) — the tool tries `cryptography` first
and falls back to PyCryptodome. Verified with the venv at
`~/workspace/.venv-mehaf/bin/python` (cryptography 50.0.2,
pycryptodome 4.6.0; the worker image pins pycryptodome 3.23.0 — the
AES-GCM calls used are the same, but the coordinator should run
the worker suite against 3.23.0). Paths below are repo-relative;
from this staging root they work identically (the staging tree
mirrors the repo layout).

## 0. Format key and worker API key (not stored in this dossier)

```bash
export V2RAY_INJECTOR_CATALOG_KEY=<64 hex chars: AES-256-GCM key>
export V2RAY_INJECTOR_API_KEY=<worker X-API-KEY>
```

Both values live only in the batch report
(`~/workspace/batch18-work/v2ray-injector/REPORTE.md`). For the
synthetic tests only, `V2RAY_INJECTOR_TEST_KEYS=1` selects the
TEST-ONLY key built into the script — it opens no real catalog.

## 1. Dossier tests (synthetic fixtures only, no network)

```bash
~/workspace/.venv-mehaf/bin/python -m unittest discover \
  -s analysis/tech.docnet.xraytunnel/16/tests -v
# Expected: 9 passed
```

Fixtures: a synthetic `.v2k` sealed with the TEST-ONLY key
(`sample_plain.v2k` + `sample_enc.v2k`), synthetic links and an
Xray JSON fragment (`synthetic_links.txt`, `synthetic_xray.json`),
all TEST-NET (`203.0.113.x`) and test UUIDs. No keys, no real
credentials, no live catalog bytes.

## 2. Live catalog (out-of-band, never stored in the repo)

```bash
export V2RAY_INJECTOR_CATALOG_KEY=... V2RAY_INJECTOR_API_KEY=...
~/workspace/.venv-mehaf/bin/python \
  analysis/tech.docnet.xraytunnel/16/tools/v2ray_injector.py \
  catalog --fetch
# Expected: "version": "1.0.0", 1,233 servers, 63 configs (snapshot;
# the live count changes between downloads).
```

## 3. `.v2k` file

```bash
~/workspace/.venv-mehaf/bin/python \
  analysis/tech.docnet.xraytunnel/16/tools/v2ray_injector.py \
  v2k tests/fixtures/sample_enc.v2k
# Expected: the synthetic test config (plain JSON).
```
