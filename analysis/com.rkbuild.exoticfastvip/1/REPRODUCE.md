# REPRODUCE — ExoticFast VIP "Rk1" (`com.rkbuild.exoticfastvip`, vc 1)

Run from the repo root. Python 3.12 with pycryptodome 4.4.0
(the venv used for verification: `~/workspace/http-custom-update/venv`).

## 1. Dossier tests (synthetic fixtures only, no network, no secrets)

```sh
python3 -m pytest analysis/com.rkbuild.exoticfastvip/1/tests/test_exoticfast_vip.py -v
```

Expected: 5 passed. The tests import the staged adapters from
`decoders/Python/apps/ExoticFast_VIP/` and decode
`tests/fixtures/synthetic.rj` (a synthetic catalog encrypted with the
verified method; fake values only, e.g. `example.invalid`) plus
negative cases (truncated blob, empty input, bad envelope).

## 2. Live catalog (needs network; read-only, no repo writes)

```sh
python3 analysis/com.rkbuild.exoticfastvip/1/tools/exoticfastvip.py --file <live-response.bin>
```

or fetch live (writes `catalogo-completo.json` /
`catalogo-redactado.json` next to the script — run it from a scratch
copy, not from the repo):

```sh
cp -r analysis/com.rkbuild.exoticfastvip/1/tools /tmp/exo-tools
python3 /tmp/exo-tools/exoticfastvip.py
```

Expected: `Version: 5.8`, `Servers: 6 total, 0 FREE, 6 PREMIUM`,
`Networks: 13`. Verified 2026-11-27; the re-fetch was byte-identical
to the delivered sample (SHA-256 of `catalogo-completo.json`
`83a83403d8ef790431dd505f7ea8c03f2368537db3941eb7d3391f9c62def241`).

## 3. Bridge adapter check (no network)

```sh
python3 - <<'EOF'
import sys
sys.path.insert(0, "decoders/Python/apps/ExoticFast_VIP")
from server_catalog_decoder import run
blob = open("analysis/com.rkbuild.exoticfastvip/1/tests/fixtures/synthetic.rj", "rb").read()
print(run(blob)[:200])
EOF
```

Expected: a JSON string starting with the synthetic catalog
(`"Version": "9.9-test"`), with no download API keys.

## 4. File adapter check (no network)

```sh
python3 decoders/Python/apps/ExoticFast_VIP/file_decoder.py \
  analysis/com.rkbuild.exoticfastvip/1/tests/fixtures/synthetic.rj
```

Expected: exit 0, one JSON document on stdout (the synthetic catalog).

## 5. .ovpn helper (not wired to the engine)

```sh
python3 decoders/Python/apps/ExoticFast_VIP/ovpn_decoder.py <profile.ovpn>
```

Expected: a JSON summary (remotes, proto, dev, cipher, auth,
inline blocks). No real user profile is stored in the repo.

## Environment

- Python 3.12, pycryptodome 4.4.0 (`Crypto`).
- No other dependencies. No secrets are needed: the decoder keys are
  the method and live only in `decoders/Python/apps/ExoticFast_VIP/`
  scripts, never in this dossier.
