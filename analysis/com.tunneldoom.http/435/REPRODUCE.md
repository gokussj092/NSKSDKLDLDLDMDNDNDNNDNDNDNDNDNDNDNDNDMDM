# Reproduce — TunnelDOOM VPN 4.3.5 (build 435)

From the repo root, with CPython 3.12 and PyCryptodome installed:

```bash
# 1. Live catalog through the staged decoder (plain GET, no auth).
python3 decoders/Python/apps/TunnelDOOM_VPN/server_catalog_decoder.py \
  > /tmp/tunneldoom-435-live.json
python3 -c "import json; d = json.load(open('/tmp/tunneldoom-435-live.json')); \
  print(d['Version'], len(d['Servers']))"
# Expected 2026-11-27: Version 532, 390 servers (the catalog moves;
# analysis time it was 531 / 391).

# 2. Old host is dead (connection closes, no response).
curl -sS -m 10 https://web.tunneldoom.space/config.json || echo "old host dead (expected)"

# 3. Offline checks: synthetic-only unit tests (no network, no real data).
python3 analysis/com.tunneldoom.http/435/tests/test_method.py -v

# 4. Revalidation script (live fetch + host check, writes a proof JSON).
python3 analysis/com.tunneldoom.http/435/tools/revalidate_435.py \
  --report /tmp/td435-proof.json
```

Notes:

- The decrypted live catalog is never stored in the repo. The proof JSON
  records only the version, server count, byte sizes and hashes.
- `file_decoder.py` (legacy `.sks` Fenix parser) has no real-sample test;
  its synthetic round-trip is covered by `test_method.py`.
