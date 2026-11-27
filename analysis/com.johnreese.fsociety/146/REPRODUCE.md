# Reproduce — REESE TUNNEL 3.23.28 (build 146)

From the repo root, with CPython 3.12 and `cryptography` (or
PyCryptodome) installed:

```bash
# 1. Self-test (RSE5 0xC6 round-trips, error codes, pad/deflate, links).
python3 decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py selftest
# Expected: selftest OK

# 2. Open the synthetic sample (TEST-NET profile, HWID ABC-123, password test123).
python3 decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py \
  analysis/com.johnreese.fsociety/146/tests/fixtures/sample_synthetic.rt \
  --hwid ABC-123 --password-file /tmp/reese-pw.txt
# (echo -n test123 > /tmp/reese-pw.txt first; or use the subcommand form:)
python3 decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py file \
  analysis/com.johnreese.fsociety/146/tests/fixtures/sample_synthetic.rt \
  --hwid abc-123 --password test123

# 3. Synthetic-only unit tests (no network, no real data).
python3 analysis/com.johnreese.fsociety/146/tests/test_method.py -v

# 4. Text parsers (synthetic links).
python3 decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py text \
  "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&path=%2Fws&host=h.example.com#My%20VLESS"
```

Notes:

- There is no live catalog to reproduce (VERIFIED_ABSENT, see ANALYSIS.md).
- The native-oracle cross-check (`test_oracle.py`, 36/36) needs the
  APK's `librse5.so` and Unicorn; it is recorded in the batch-15 work
  dir, not reproduced here. The dossier tests cover the staged script
  against the synthetic sample and the error matrix.
