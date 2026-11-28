# RESULTS — Ultra Custom 15.7 (`hz.custom.vpn`, code 157)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| `.ua` file (UAF2) | **VERIFIED_REAL** | Real sample `Guatemala_Tigo__1__7_fy55.ua` (6,287 B) → 4,682 B XML, profile "Guatemala Tigo", appVersionCode 157, tunnelType 12 |
| `.ua` file (legacy EXA1/UAB1, UAP1, bundles) | **VERIFIED_SYNTHETIC** | Round-trip with synthetic files; no real legacy/UAP1 sample yet |
| `ua://` links | **VERIFIED_SYNTHETIC** | Round-trip with synthetic links |
| UCS subscription (CSS1) | **VERIFIED_SYNTHETIC** | Signed-subscription round-trip with a synthetic keypair |
| Catalog | **VERIFIED_ABSENT** | No vendor catalog URL; servers come from a user UCS subscription |
| SSH login (catalog or profile) | **PENDING** | Only the file was decrypted; no login attempted |

## Tests run (2026-11-28, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, cryptography 50.0.2, pycryptodome 4.6.0)

- `python3 -m unittest discover -s analysis/hz.custom.vpn/157/tests`:
  **6 passed** (UAF2 round-trip, legacy round-trip, UAP1
  password round-trip, bundle round-trip, `ua://` link,
  synthetic signed subscription).
- Live verification (batch analyst, same venv):
  `ultra_custom.py` on the real sample → 4,682 B XML, profile
  "Guatemala Tigo". Self-test 5/5.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- The real sample is UAF2; legacy/UAP1/bundle variants are
  synthetic-verified only.
- No vendor catalog exists for Ultra Custom.
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-GCM calls used are API-stable across both, but
  the coordinator should run the worker suite against 3.23.0.
