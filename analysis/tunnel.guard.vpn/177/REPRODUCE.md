# Reproduce — TunelGuard VPN 17.7 (build 177)

From the repo root, with CPython 3.12 and PyCryptodome installed:

```bash
# 1. Live catalog through the staged decoder (plain GET, no auth).
python3 -m decoders.Python.apps.TunelGuard_VPN.server_catalog_decoder \
  > /tmp/tunelguard-177-live.json
python3 -c "import json; d = json.load(open('/tmp/tunelguard-177-live.json')); \
  print(d['version'], d['config_revision'], len(d['Servers']), len(d['Tweaks']))"
# Expected 2026-11-27: 5.0, revision 50, 90 servers, 1058 tweaks.

# 2. Offline checks: synthetic-only unit tests (no network, no real data).
python3 analysis/tunnel.guard.vpn/177/tests/test_method.py -v

# 3. Revalidation script (live fetch + bundled seed, writes a proof JSON).
python3 analysis/tunnel.guard.vpn/177/tools/revalidate_177.py \
  --report /tmp/tg177-proof.json

# 4. Bundled seed (no network): decrypt the hh1 seed envelope.
#    (The seed envelope string lives in the batch-15 analyst script;
#    the staged codec opens it with the v3 key.)
```

Notes:

- The decrypted live catalog is never stored in the repo. The proof JSON
  records only the version, revision, counts and hashes.
- The `.tgv` file decoder is HELD (see ANALYSIS.md). Do not present the
  Java STUC1 GCM format as verified against a real exported file.
