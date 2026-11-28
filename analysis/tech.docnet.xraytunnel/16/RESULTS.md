# RESULTS — V2Ray Injector 1.4.2 (`tech.docnet.xraytunnel`, code 16)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| Catalog (live) | **VERIFIED_REAL** | Live fetch 2026-11-28 (HTTP 200): version 1.0.0, 1,233 servers (snapshot; a first manual fetch saw 1,235), 63 configs, all envelopes opened, 0 encrypted leftovers |
| Catalog (bundled `servers.enc`/`configs.enc`) | **VERIFIED_REAL** | Both bundled assets open with the same key (913 servers / 59 configs — an older snapshot) |
| `.v2k` file | **VERIFIED_SYNTHETIC** | Round-trip plain + encrypted with the app's own format; no real exported `.v2k` supplied yet |
| Xray JSON | **VERIFIED_SYNTHETIC** | Round-trip over a real catalog server, outbounds extracted |
| Text links | **VERIFIED_SYNTHETIC** | Round-trip vless/vmess/ss (both forms)/trojan built from real catalog servers, 5/5 |
| SSH login (catalog or profile) | **PENDING** | Only the catalog was decrypted; no login attempted |

## Tests run (2026-11-28, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, cryptography 50.0.2, pycryptodome 4.6.0)

- `python3 -m unittest discover -s analysis/tech.docnet.xraytunnel/16/tests`:
  **9 passed** (catalog key shape, envelope round-trip, tampered-tag
  negative, `.v2k` plain + encrypted, link parsing, Xray JSON, no
  real IPs in fixtures).
- Live verification (batch analyst, same venv):
  `v2ray_injector.py catalog --fetch` → 1,233 servers, 63 configs,
  0 encrypted leftovers. Asset decryption → 913 / 59.
  `v2k-encode`/`v2k` round-trip 2/2. Xray JSON round-trip 1/1.
  Link round-trip 5/5.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- No real exported `.v2k` file has been supplied, so the `.v2k`
  codec is synthetic-verified only; a real export would confirm it
  end to end.
- The live catalog changes between downloads; counts are snapshots.
- The worker API key is needed for the live fetch; without it the
  worker returns 401.
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-GCM calls used are API-stable across both, but
  the coordinator should run the worker suite against 3.23.0.
