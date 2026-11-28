# REPRODUCE — Surya Tunnel 1.6

Environment: Python 3.12.3; `cryptography` (AESGCM) or
`pycryptodome` (AES.MODE_GCM). Verified with the venv at
`~/workspace/.venv-mehaf/bin/python` (cryptography 50.0.2,
pycryptodome 4.6.0; the worker image pins pycryptodome 3.23.0 —
the AES-GCM calls used are the same, but the coordinator should
run the worker suite against 3.23.0). Paths below are
repo-relative; from this staging root they work identically (the
staging tree mirrors the repo layout).

## 0. Config label (not stored in this dossier)

```bash
export SURYA_CONFIG_LABEL=<config label>
```

The value lives only in the batch report
(`~/workspace/batch20-work/surya-tunnel/REPORTE.md`). For the
synthetic tests only, `SURYA_TEST_LABEL=1` selects the TEST-ONLY
label built into the script — it opens no real file.

## 1. Dossier tests (synthetic fixtures only, no network)

```bash
~/workspace/.venv-mehaf/bin/python -m unittest discover \
  -s analysis/com.suryavpn.tunnel/6/tests -v
# Expected: 10 passed
```

Fixtures: a synthetic V3 profile (`synthetic_v3.st`) sealed with
the TEST-ONLY label, a synthetic profile JSON and synthetic SVPN
links, all TEST-NET (`203.0.113.x`, `192.0.2.x`) and test UUIDs.
No keys, no real credentials, no live bytes.

## 2. Real `.st` file (out-of-band, never stored in the repo)

```bash
export SURYA_CONFIG_LABEL=...
~/workspace/.venv-mehaf/bin/python \
  analysis/com.suryavpn.tunnel/6/tools/surya_tunnel.py \
  Robi_Airtel_Fre_Internet_Slow_Dns_V4_2_261w.st
# Expected: 1 profile, LOCK_ALL, modeIndex 0 (SSH), SlowDNS on.
# (The real sample stays in the batch work dir.)
```
