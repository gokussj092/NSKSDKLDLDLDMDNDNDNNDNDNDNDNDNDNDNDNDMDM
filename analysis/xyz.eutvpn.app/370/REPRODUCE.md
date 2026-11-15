# REPRODUCE — EUT VPN (xyz.eutvpn.app, versionCode 370)

Environment: Python 3.12.3, Linux x86_64. No third-party package is needed
for the dossier tests (stdlib + OpenSSL 3.0.13 as an oracle for DES in the
ZIVPN test only). `pytest` is NOT installed in this VM, so the tests run
with `unittest` (stdlib).

## 1. Dossier tests (offline, synthetic, no secrets)

```bash
cd analysis/xyz.eutvpn.app/370
python3 -m unittest tests.test_method -v
python3 tools/verify.py
```

Expected: all tests pass. They use synthetic vectors only (synthetic test
keys generated inside the test files) and never touch the network.

## 2. Operational scripts (live verification; outside this repo)

The operational scripts live in the research workspace until the
integration phase copies them into the repo:

```bash
cd ~/workspace/catalogs/eut
python3 EUT_VPN.py --self-test
python3 EUT_VPN_archivos.py --self-test
python3 EUT_VPN.py --url --output /tmp/eut-catalog.json   # live download (needs network)
```

`--url` performs the app's exact catalog request. Do NOT paste the
download URL, a token or a key into a ticket, a chat message or this
dossier: the request lives in the script.

## 3. Reproducing the research steps

1. Extract the XAPK (base + ABI splits) and record SHA-256 of every file.
2. Decompile with jadx 1.5.3 (`jadx -d jadx-out <base.apk>`); read the
   classes named in ANALYSIS.md §3.
3. Run the research script in tools/ (see its header for its own
   requirements — androguard 4.1.4 and, for some, loguru/lxml).
4. Run the operational scripts' `--self-test` and, when the network allows
   it, `--url`; compare version/server/network counts with RESULTS.md.

## 4. What is NOT reproducible here

- A live catalog download without network access.
- A real exported file/link (none was supplied; see RESULTS.md).
- For EUT VPN: any live call without a real Play Integrity token from a
  real device (see RESULTS.md — NOT_AUTHORIZED).
