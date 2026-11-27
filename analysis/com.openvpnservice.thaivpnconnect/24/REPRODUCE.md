# REPRODUCE — ThaiVPN Connect 2.4

Environment: Python 3.12.3, standard library only. Any Python 3
works; verified with `~/workspace/.venv-mehaf/bin/python`.
Paths below are repo-relative; from this staging root they work
identically (the staging tree mirrors the repo layout).

## 1. Decoder self-test (round-trip + negatives)

```bash
python3 decoders/Python/apps/ThaiVPN_Connect/file_decoder.py --self-test
# Expected: self-test OK: profile.json round-trip,
# truncated/garbage negatives
```

## 2. Dossier tests (synthetic fixtures only)

```bash
python3 -m pytest \
  analysis/com.openvpnservice.thaivpnconnect/24/tests/test_thaivpn.py -v
# Expected: 6 passed
```

Fixtures are one synthetic XXTEA blob + the expected decoded
catalog (`example.invalid`, fake users). No keys, no real
credentials, no live catalog bytes.

## 3. Live catalog (out-of-band, never stored in the repo)

```bash
python3 analysis/com.openvpnservice.thaivpnconnect/24/tools/thaivpn.py \
  --check-catalog
# Expected: Version: 17.9 / Servers: 1 / Networks: 24 /
# OK: no encoded value remains
```

To verify the bridge against live bytes (re-fetched; nothing is
stored in the repo):

```bash
python3 - <<'EOF'
import json
from decoders.Python.apps.ThaiVPN_Connect import server_catalog_decoder as b
from decoders.Python.apps.ThaiVPN_Connect import thaivpn
blob = thaivpn.fetch_catalog_raw().encode()  # live GET, plain
out = json.loads(b.run(blob))
assert out["Version"] == "17.9" and len(out["Servers"]) == 1
assert len(out["Networks"]) == 24 and "decryptionStatus" not in out
print("live blob OK")
EOF
```

## 4. profile.json round-trip

```bash
python3 analysis/com.openvpnservice.thaivpnconnect/24/tools/thaivpn.py \
  --file <profile.json generada desde el catalogo en vivo>
# Expected: the decoded catalog JSON (Version 17.9, 1 server, 24 networks)
```

No real exported `profile.json` exists yet — that is the open
confirmation item (see RESULTS.md).
