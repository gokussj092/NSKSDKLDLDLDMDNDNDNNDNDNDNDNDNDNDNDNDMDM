# REPRODUCE — Peru VPN 4.1.2

Environment: Python 3.12.3; `pycryptodome` (AES-256-CBC). Verified
with the venv at `~/workspace/.venv-mehaf/bin/python` (pycryptodome
4.6.0; the worker image pins pycryptodome 3.23.0 — the AES-CBC API
used is the same, but the coordinator should run the worker suite
against 3.23.0). Paths below are repo-relative; from this staging
root they work identically (the staging tree mirrors the repo layout).

## 0. Format keys (not stored in this dossier)

`tools/codec.py` loads the two derived 32-byte keys from the
environment:

```bash
export PERU_CATALOG_KEY_HEX=<64 hex chars: SHA-256 of the StringCrypter label>
export PERU_FIELD_KEY_HEX=<64 hex chars: SHA-256 of the de-obfuscated NoobPass string>
```

The derivation (no literals here) is documented in ANALYSIS.md §2;
the values live only in the batch report
(`~/workspace/batch18-work/peru-vpn/REPORTE.md`). For the synthetic
tests only, `PERU_TEST_KEYS=1` selects the TEST-ONLY keys built into
the script — they open no real catalog.

## 1. Dossier tests (synthetic fixtures only, no network)

```bash
~/workspace/.venv-mehaf/bin/python -m unittest discover \
  -s analysis/com.peru.vpn/412/tests -v
# Expected: 7 passed
```

Fixtures are a synthetic catalog sealed with the TEST-ONLY keys
(`tests/fixtures/synthetic_catalog.b64` + `synthetic_catalog.json`,
TEST-NET `203.0.113.10`, user `testuser`). No keys, no real
credentials, no live catalog bytes.

## 2. Live catalog (out-of-band, never stored in the repo)

```bash
export PERU_CATALOG_KEY_HEX=... PERU_FIELD_KEY_HEX=...
~/workspace/.venv-mehaf/bin/python \
  analysis/com.peru.vpn/412/tools/server_catalog_decoder.py
# Expected: JSON with "Version": "532", 390 servers on stdout.
# (The live Version changes over time; re-check the count on re-fetch.)
```

With a saved download instead of the network:

```bash
~/workspace/.venv-mehaf/bin/python \
  analysis/com.peru.vpn/412/tools/server_catalog_decoder.py \
  live_config.enc -o /tmp/peru-532.json
```

## 3. Bundled catalog (no network)

```bash
export PERU_CATALOG_KEY_HEX=... PERU_FIELD_KEY_HEX=...
~/workspace/.venv-mehaf/bin/python \
  analysis/com.peru.vpn/412/tools/server_catalog_decoder.py \
  noobdev.txt
# Expected: Version "2", 8 Peru template servers.
```

(`noobdev.txt` is `res/raw/noobdev.txt` from the 4.1.2 base.apk;
it stays outside the repo.)
