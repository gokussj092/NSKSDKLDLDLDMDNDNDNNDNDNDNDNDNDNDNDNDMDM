# REPRODUCE — STLRAY 1.1.36

Environment: Python 3.12.3; `cryptography` (ECDSA) +
`pycryptodome` (AES-256-GCM). Verified with the venv at
`~/workspace/.venv-mehaf/bin/python` (cryptography 50.0.2,
pycryptodome 4.6.0; the worker image pins pycryptodome 3.23.0 —
the AES-GCM API used is the same, but the coordinator should run
the worker suite against 3.23.0). Paths below are repo-relative;
from this staging root they work identically (the staging tree
mirrors the repo layout).

## 1. Decoder self-test (round-trips + negatives)

```bash
~/workspace/.venv-mehaf/bin/python \
  decoders/Python/apps/STLRAY/file_decoder.py --self-test
# Expected: self-test OK: TVC round-trips (normal/locked, 8 schemes,
# hyb://, raw bytes), truncated/garbage negatives
```

## 2. Dossier tests (synthetic fixtures only)

```bash
~/workspace/.venv-mehaf/bin/python -m pytest \
  analysis/com.stlray.thvpn/36/tests/test_stlray.py -v
# Expected: 9 passed
```

Fixtures are ciphertext envelopes + synthetic plaintexts only
(`example.invalid`, fake users). No keys, no real credentials, no
live catalog bytes. The THAIVPN2 bundle fixture carries no ECDSA
signature (the decoder accepts a missing signature with
`sig_ok=None`); live envelopes always carry one.

## 3. Live catalog (out-of-band, never stored in the repo)

```bash
~/workspace/.venv-mehaf/bin/python \
  analysis/com.stlray.thvpn/36/tools/stlray.py catalog
# Expected: config revision=150086 configVersion=15.86 servers=76
# payloads=38 certificates=6 sig=True; modes revision=10009 modes=14
# sig=True; policy revision=10007 sig=True
```

The analyst's `--out` writes the config WITH its `updates`
block; the bridge strips it. To verify the bridge against live
bytes, pack the three live envelopes (config/modes/policy) into
the bundle shape and run the bridge:

```bash
~/workspace/.venv-mehaf/bin/python - <<'EOF'
import base64, json
from decoders.Python.apps.STLRAY import server_catalog_decoder as b
raw = {n: open(f"live-{n}.json", "rb").read()
       for n in ("config", "modes", "policy")}
bundle = {"kind": b.BUNDLE_KIND,
          "catalogs": {n: base64.b64encode(v).decode()
                       for n, v in raw.items()}}
out = json.loads(b.run(json.dumps(bundle).encode()))
assert out["revision"] == 150086 and len(out["servers"]) == 76
assert "updates" not in out and len(out["modes"]["modes"]) == 14
print("live bundle OK")
EOF
```

(`live-*.json` are the analyst's raw downloads in
`~/workspace/batch17-work/stlray/`; they stay outside the repo.)

## 4. Real-sample check (TVC round-trip on a real catalog profile)

The analyst verified the codec by encode/decode round-trip over
the real VLESS profile of server `CELCOM BASIC 01` (15 fields)
from the live catalog: `sray://` normal MATCH, `sray://` locked
MATCH, `tvc://` MATCH, `decode-file` raw MATCH, base64url MATCH.
No real exported `.sray` file or link exists yet — that is the
open confirmation item (see RESULTS.md).
