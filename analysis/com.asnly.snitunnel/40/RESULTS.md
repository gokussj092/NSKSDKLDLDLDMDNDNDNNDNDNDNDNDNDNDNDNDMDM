# RESULTS — SNI Tunnel 1.3.7 (`com.asnly.snitunnel`, code 40)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| Catalog | **VERIFIED_ABSENT** | BYOC client; the app downloads no server list |
| v2rc link (outer layer) | **VERIFIED_REAL** | Real link "SOMBRE" (v2, expired 2026-11-27T23:00:00Z): ECDH P-256 + HKDF-SHA256 (`v2rc-seal-v1`) + ChaCha20-Poly1305 opened; `deviceIDHash` matches open record `v2rc-app-open-v1` |
| v2rc link (inner config) | **FAILED** | Password envelope (PBKDF2-HMAC-SHA256, salt 16 B, 120,000 iters) NOT decrypted: password unknown, link expired |
| Cloud relay `snicfg.asnly.net` | **VERIFIED_REAL** | Live 2026-11-28: create → claim → open; second claim 410 (exhausted) |
| Standard links | **VERIFIED_SYNTHETIC** | Round-trip vmess/vless/trojan/ss (synthetic fixtures) |
| Proprietary file format | **VERIFIED_ABSENT** | No `.sks` file format |
| SSH login (catalog or profile) | **PENDING** | Only the link and the relay were verified; no login attempted |

## Tests run (2026-11-28, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, cryptography 50.0.2, pycryptodome 4.6.0)

- `python3 -m unittest discover -s analysis/com.asnly.snitunnel/40/tests`:
  **8 passed** (seal/open round-trip with a generated test P-256
  keypair, app-open record, password seal/open, device record,
  standard link parsing, invalid-link negative).
- Live verification (batch analyst, same venv):
  cloud relay create → claim → open, second claim 410.
  v2rc "SOMBRE" outer layer opened; inner envelope not opened
  (password unknown).
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- No catalog exists for SNI Tunnel; there is nothing to integrate
  as a catalog.
- The inner config of the real v2rc link remains undecrypted
  (password unknown, link expired).
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-GCM calls used are API-stable across both, but
  the coordinator should run the worker suite against 3.23.0.
