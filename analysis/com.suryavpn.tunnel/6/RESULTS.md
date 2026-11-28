# RESULTS — Surya Tunnel 1.6 (`com.suryavpn.tunnel`, code 6)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| `.st` file (V3) | **VERIFIED_REAL** | Real sample `Robi_Airtel_Fre_Internet_Slow_Dns_V4_2_261w.st` (2,301 B) fully decrypted: 1 profile, LOCK_ALL, modeIndex 0 (SSH), SlowDNS on |
| `.st` file (V1, V2, SPW1) | **VERIFIED_SYNTHETIC** | Round-trip with synthetic files; no real V1/V2/SPW1 sample yet |
| SVPN1–SVPN4 links | **VERIFIED_SYNTHETIC** | Round-trip with synthetic links; no real link sample yet |
| Catalog | **VERIFIED_ABSENT** | No built-in catalog; Cloud Sync URL is user-pasted, empty by default |
| SSH login (catalog or profile) | **PENDING** | Only the file was decrypted; no login attempted |

## Tests run (2026-11-28, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, cryptography 50.0.2, pycryptodome 4.6.0)

- `python3 -m unittest discover -s analysis/com.suryavpn.tunnel/6/tests`:
  **10 passed** (V1/V2/V3/SPW1 round-trips, SVPN1–SVPN4 links,
  garbage negative, no real IPs in fixtures).
- Live verification (batch analyst, same venv):
  `surya_tunnel.py` on the real sample → 1 profile, LOCK_ALL,
  modeIndex 0, SlowDNS on. Self-test 13/13.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- The real sample is V3; V1, V2 and SPW1 are synthetic-verified
  only.
- No live catalog exists for Surya Tunnel.
- The `.st` format here is NOT Sentinel Tunnel's `.st` (magic
  `SPN1` vs `STCF`); the two decoders must not be mixed.
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-GCM calls used are API-stable across both, but
  the coordinator should run the worker suite against 3.23.0.
