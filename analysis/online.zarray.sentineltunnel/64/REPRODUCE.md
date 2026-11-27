# REPRODUCE — Sentinel Tunnel 4.0.0 (`online.zarray.sentineltunnel`, vc 64)

Run from the repo root unless stated otherwise. No secrets, APK bytes,
complete catalogs or real credentials are needed for any step below.
The VPS probe is documented with placeholders only — it cannot succeed
without a real Firebase App Check token, which is not stored anywhere.

## Environment

- Python 3.12 (system). Verification venv used here:
  `python3 -m venv /tmp/sent-venv && /tmp/sent-venv/bin/pip install cryptography`
  (cryptography 50.0.2 in that venv; the repo pins its own version).
- The staged decoders import only the standard library plus
  `cryptography` (file decoder). The catalog decoder is stdlib-only.

## 1. `.st` round-trip (synthetic)

```bash
python3 decoders/Python/apps/Sentinel_Tunnel/file_decoder.py --selftest
# expect: 14 round-trips OK (7 types x with/without password),
# tamper detected, PASSWORD_REQUIRED raised without a password, SELFTEST: ALL OK
```

## 2. Dossier tests (synthetic fixtures only)

```bash
python3 analysis/online.zarray.sentineltunnel/64/tests/test_sentinel_tunnel.py
# expect: PASS test_vpngate_fixture, PASS test_vpngate_negatives,
# PASS test_st_roundtrip_and_negatives, ALL TESTS PASSED
```

The fixture `tests/fixtures/vpngate-sample.csv` is 3 synthetic rows
(TEST-NET IPs, fabricated minimal `.ovpn` text), including one row with
Ping `"-"` — the case that crashed the analyst's strict parser.

## 3. VPNGate live feed (public, no auth)

```bash
python3 analysis/online.zarray.sentineltunnel/64/tools/vpngate_fetch.py --out /tmp/vpngate.csv
# expect: VPNGate servers: N (98 on 2026-11-27, 95 on same-day re-run) + country breakdown
python3 decoders/Python/apps/Sentinel_Tunnel/server_catalog_decoder.py /tmp/vpngate.csv | head -30
# expect: catalog JSON, serverCount N, no URLs in the output
```

To compare against the delivered sample (98 servers, 2026-11-27):

```bash
python3 decoders/Python/apps/Sentinel_Tunnel/server_catalog_decoder.py \
  ~/workspace/batch15-work/sentinel-tunnel/raw/vpngate.csv | grep serverCount
# expect: "serverCount": 98
```

## 4. VPS 401 evidence (blocked — expected failure)

Analyst script (batch work dir, NOT in Git — it holds the VPS keys):

```bash
cd ~/workspace/batch15-work/sentinel-tunnel
python3 sentinel_tunnel_catalog.py --out /tmp/sentinel-reverify
# expect: VPS <type> HTTP 401 {"error":"unauthorized"} for the 9 types
# (a single connection reset on one type is the known egress flakiness),
# VPNGate N servers, VPS status "failed: HTTP 401 unauthorized ..."
```

Request shape (values redacted — do not paste real keys anywhere):

```
GET https://api.zarray.online:2096/api/v2/configs/<type>
X-Api-Key: <redacted>
X-Timestamp: <unix seconds>
X-Nonce: <random UUID>
X-Signature: HMAC-SHA256("<apiKey>|<timestamp>|<nonce>")
User-Agent: SentinelTunnel/1.0
X-Firebase-AppCheck: <real token required; fake/empty/forged -> 401>
```

## 5. What was NOT reproduced

- The VPS catalog (needs a real App Check token from a phone running
  the app; see ANALYSIS.md §2 and MANIFEST.json `manual_steps`).
- A real `.st` export (no sample exists yet; round-trips are synthetic
  with realistic payloads from the app's data models).
