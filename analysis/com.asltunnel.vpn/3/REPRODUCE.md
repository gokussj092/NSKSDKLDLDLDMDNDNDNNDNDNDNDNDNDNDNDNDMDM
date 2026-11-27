# REPRODUCE — ASL TUNNEL 3.0 (`com.asltunnel.vpn`, vc 3)

Run from the repo root. Python 3.12 with pycryptodome 4.4.0
(the venv used for verification: `~/workspace/http-custom-update/venv`).

## 1. Dossier tests (synthetic fixtures only, no network, no secrets)

```sh
python3 -m pytest analysis/com.asltunnel.vpn/3/tests/test_asl_tunnel.py -v
```

Expected: 6 passed. The tests import the staged adapters from
`decoders/Python/apps/ASL_Tunnel/` and decode
`tests/fixtures/test_plain.asl` and `test_server.asl` (synthetic
round-trip fixtures from the analyst; fake values only) plus negative
cases (invalid Base64, empty input, wrong-marker file).

## 2. Live catalog (needs network; read-only, no repo writes)

Run the staged research script from a scratch copy (it writes
`catalogo-completo.json` next to itself by default — do not run it
from the repo):

```sh
cp -r analysis/com.asltunnel.vpn/3/tools /tmp/asl-tools
python3 /tmp/asl-tools/asltunnel.py catalog /tmp/asl-live.json
```

Expected: `Version: 20.10`, `servers_total: 35`,
`servers_free_NoobLevel0: 35`, `tweaks_total: 292`,
`tweaks_with_payload: 124`. Verified 2026-11-27; the re-fetch was
byte-identical to the delivered sample.

## 3. Bridge adapter check (no network)

```sh
python3 - <<'EOF'
import sys
sys.path.insert(0, "decoders/Python/apps/ASL_Tunnel")
from server_catalog_decoder import run
blob = open("analysis/com.asltunnel.vpn/3/tests/fixtures/test_plain.asl", "rb").read()
try:
    run(blob)
except Exception as e:
    print("expected failure on a .asl blob (not a catalog):", type(e).__name__)
EOF
```

(The bridge only accepts catalog envelopes; `.asl` blobs go through
`file_decoder.py`. A catalog-envelope check needs a live fetch — see §2
— or the delivered sample, which is never stored in the repo.)

## 4. File adapter check (no network)

```sh
python3 decoders/Python/apps/ASL_Tunnel/file_decoder.py \
  analysis/com.asltunnel.vpn/3/tests/fixtures/test_plain.asl
python3 decoders/Python/apps/ASL_Tunnel/file_decoder.py \
  analysis/com.asltunnel.vpn/3/tests/fixtures/test_server.asl
```

Expected: exit 0, one JSON document on stdout each; the server-shape
fixture decrypts its AES/CFB fields (`ServerIPHost`,
`V2ray.UUID`, `SlowDNS.*`); notes (expiry, password) go to stderr.

## 5. Round-trip check (synthetic .asl)

```sh
python3 - <<'EOF'
import sys, json
sys.path.insert(0, "decoders/Python/apps/ASL_Tunnel")
from asltunnel import encode_asl, decode_asl_text
doc = {"Server": "Synthetic Test", "ProxyPort": "80", "ExpireDate": 0}
blob = encode_asl(doc)
back, _ = decode_asl_text(blob)
assert back["Server"] == "Synthetic Test"
print("round-trip OK")
EOF
```

## Environment

- Python 3.12, pycryptodome 4.4.0 (`Crypto`).
- No other dependencies. No secrets are needed: the decoder keys are
  the method and live only in `decoders/Python/apps/ASL_Tunnel/`
  scripts, never in this dossier. (A third-party token observed in the
  app code was excluded from all staged files.)
