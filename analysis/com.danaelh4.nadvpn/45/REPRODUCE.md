# REPRODUCE — NadiaVPN 1.4.6

Environment: Python 3.12; `pycryptodome` for AES-256-CBC
(`cryptography` fallback kept). Tested with the venv at
`~/workspace/http-custom-update/venv/bin/python`.
The APK analysis (DEX, Unicorn) was done beforehand; see
`~/workspace/nadiavpn-work/apk-analysis.md` and `text-analysis.md`.

## 1. Decoder self-test (round-trips + negatives)

```bash
~/workspace/http-custom-update/venv/bin/python \
  analysis/com.danaelh4.nadvpn/45/tools/file_decoder.py --self-test
# Expected: self-test OK: V2/PW2/binary round-trips, tampered/V1/HWID
# negatives, sec2 link
```

## 2. Real sample (out-of-band, never stored in the repo)

```bash
NADIA_REAL_SAMPLE=~/workspace/nadiavpn-work/sample-nad-sec2.txt \
  ~/workspace/http-custom-update/venv/bin/python -m pytest \
  tests/test_nadia_vpn.py -v -k real_sample
# Expected: 1 passed (HMAC verifies, JSON complete, 24 keys)
```

The sample file lives outside the repo on purpose: it carries a test
profile. Only its shape (keys) is asserted, never its values.

## 3. Dossier tests (synthetic fixtures only)

```bash
~/workspace/http-custom-update/venv/bin/python -m pytest \
  tests/test_nadia_vpn.py -v
# Expected: 9 passed, 1 skipped (real_sample, needs NADIA_REAL_SAMPLE)
```

## 4. py_compile

```bash
~/workspace/http-custom-update/venv/bin/python -m py_compile \
  decoders/Python/apps/NadiaVPN/file_decoder.py \
  cloud/workers/python/engine.py \
  cloud/workers/python/text_bridge.py \
  cloud/workers/python/supplied_bridge.py \
  spdecode/registry.py \
  spdecode/handlers/extra_text_protocols.py \
  scripts/cloud_formats_catalog.py
```

## 5. Cloud format catalogue regen check

From a repo checkout with this staging applied:

```bash
~/workspace/http-custom-update/venv/bin/python scripts/cloud_formats_catalog.py --write
~/workspace/http-custom-update/venv/bin/python scripts/cloud_formats_catalog.py
# Expected: "Public Cloud format catalogue matches all currently
# registered file engines."
```

## 6. Cloud + bot suites (from the repo root)

```bash
~/workspace/http-custom-update/venv/bin/python -m pytest \
  tests/test_cloud_c8_vpn_registry.py \
  tests/test_cat100_providers.py \
  tests/test_supplied_integrations.py \
  tests/test_nadia_vpn.py -v
node --test cloud/web/tests/text-format-catalog.test.mjs \
  cloud/web/tests/supplied-integrations.test.mjs
```

Note: `cloud/web/tests/http-custom-online.test.mjs` and the
`catalog()`-based node tests currently fail in a bare checkout with
`INVALID_ORIGINAL_ICON` (icons are uploaded separately by the owner
and are not in the worktree); that failure predates this integration.
