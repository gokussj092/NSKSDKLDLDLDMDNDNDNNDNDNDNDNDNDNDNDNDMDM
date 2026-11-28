# REPRODUCE — DGM Tunnel 15.11.2026

Environment: Python 3.12.3; `cryptography` (AESGCM) or
`pycryptodome` (AES.MODE_GCM) for DGMTUNNEL_SHARE v2. Verified
with the venv at `~/workspace/.venv-mehaf/bin/python`
(cryptography 50.0.2, pycryptodome 4.6.0; the worker image pins
pycryptodome 3.23.0 — the AES-GCM calls used are the same, but the
coordinator should run the worker suite against 3.23.0). Paths
below are repo-relative; from this staging root they work
identically (the staging tree mirrors the repo layout).

## 0. No format keys

DGM Tunnel has no format key: the feed is plaintext and the share
password (if any) is supplied by the user at open time. Nothing to
configure.

## 1. Dossier tests (synthetic fixtures only, no network)

```bash
~/workspace/.venv-mehaf/bin/python -m unittest discover \
  -s analysis/com.dgmtunnel.app/17/tests -v
# Expected: 8 passed
```

Fixtures: a synthetic feed (`synthetic_feed.txt`) and a synthetic
profile (`synthetic_profile.json`), all TEST-NET (`203.0.113.x`,
`192.0.2.x`) and test UUIDs. No keys, no real credentials, no live
feed bytes.

## 2. Public feed (live, out-of-band)

```bash
~/workspace/.venv-mehaf/bin/python \
  analysis/com.dgmtunnel.app/17/tools/dgm_tunnel.py \
  --feed https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt
# Expected: the live snapshot (8,880 lines / 8,873 links on
# 2026-11-28; the count changes as the list rotates). Catalog =
# first 40 lines.
```

## 3. DGMTUNNEL_SHARE v2

```bash
~/workspace/.venv-mehaf/bin/python \
  analysis/com.dgmtunnel.app/17/tools/dgm_tunnel.py \
  --share <texto DGMTUNNEL_SHARE v2> [--password <contrasena>]
# Expected: the shared config (if the link is not expired and the
# password, if any, is correct). The two real shares verified in
# 2026-11-28 are expired; use a fresh share from the app to
# re-verify end to end.
```
