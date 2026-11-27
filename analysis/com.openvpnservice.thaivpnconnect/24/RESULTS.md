# RESULTS — ThaiVPN Connect 2.4 (`com.openvpnservice.thaivpnconnect`, code 24)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| Catalog (single GET) | **VERIFIED_REAL** | Live fetch 2026-11-27: v17.9, 1 server, 24 networks, `--check-catalog` OK (0 leftover encoded values). Re-fetch byte-identical to the delivered sample |
| `profile.json` file | **VERIFIED_SYNTHETIC** | Round-trip encrypt→decrypt identical with a blob generated from the live catalog; no real exported file yet. Decoder ships NOT wired to `engine.py` (suffix `json` — see ANALYSIS.md §2) |
| Text links | **NOT_APPLICABLE** | No custom scheme in the app; standard `vmess://` / `vless://` / `trojan://` / `ss://` already covered by generic V2Ray decoders |
| SSH login (catalog or profile) | **PENDING** | Only the catalog/profile was decrypted; no login attempted |

## Tests run (2026-11-27, Python 3.12.3, stdlib only)

- `file_decoder.py --self-test`: **OK** (profile.json round-trip,
  truncated/garbage negatives).
- `pytest analysis/com.openvpnservice.thaivpnconnect/24/tests/test_thaivpn.py`:
  **6 passed** (profile fixture, bridge accepts the same blob,
  encrypt round-trip, no leftovers, negatives, no-download-API
  assertion).
- Live verification (analyst script):
  `thaivpn.py --check-catalog` → Version 17.9, Servers 1,
  Networks 24, "OK: no encoded value remains". Re-fetch
  2026-11-27 byte-identical to the delivered
  `catalogo-completo.json`.
- Bridge against live bytes: `run()` over a freshly fetched blob
  → v17.9, 1 server, 24 networks, no `decryptionStatus`, no
  `thaivapp.my.id` string in the result. See REPRODUCE.md §3.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- No real exported `profile.json` yet — the file decoder is
  round-trip verified only.
- The ping list (`kuay/ping.json`) is not part of the catalog and
  is not integrated.
