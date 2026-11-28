# REPRODUCE — Ultra Custom 15.7

Environment: Python 3.12.3; `cryptography` (AESGCM, ECDSA P-256)
or `pycryptodome` (AES.MODE_GCM) as fallback. Verified with the
venv at `~/workspace/.venv-mehaf/bin/python` (cryptography 50.0.2,
pycryptodome 4.6.0; the worker image pins pycryptodome 3.23.0 —
the AES-GCM calls used are the same, but the coordinator should
run the worker suite against 3.23.0). Paths below are
repo-relative; from this staging root they work identically (the
staging tree mirrors the repo layout).

## 0. Format keys (not stored in this dossier)

```bash
export ULTRA_CUSTOM_UAF2_KEY_HEX=<64 hex chars: UAF2 key>
export ULTRA_CUSTOM_MASK_KEY_HEX=<64 hex chars: mask key>
```

The values live only in the batch report
(`~/workspace/batch18-work/ultra-custom/REPORTE.md`). For the
synthetic tests only, `ULTRA_CUSTOM_TEST_KEYS=1` selects the
TEST-ONLY keys built into the script — they open no real file.

## 1. Dossier tests (synthetic fixtures only, no network)

```bash
~/workspace/.venv-mehaf/bin/python -m unittest discover \
  -s analysis/hz.custom.vpn/157/tests -v
# Expected: 6 passed
```

Fixtures: a synthetic UAF2 file (`synthetic_test.ua`) sealed with
the TEST-ONLY keys and a synthetic profile XML
(`synthetic_profile.xml`), all TEST-NET (`203.0.113.x`) and test
values. No keys, no real credentials, no live bytes.

## 2. Real `.ua` file (out-of-band, never stored in the repo)

```bash
export ULTRA_CUSTOM_UAF2_KEY_HEX=... ULTRA_CUSTOM_MASK_KEY_HEX=...
~/workspace/.venv-mehaf/bin/python \
  analysis/hz.custom.vpn/157/tools/ultra_custom.py \
  Guatemala_Tigo__1__7_fy55.ua
# Expected: 4,682 B XML, profile 'Guatemala Tigo',
# appVersionCode 157, tunnelType 12.
# (The real sample stays in the batch work dir.)
```
