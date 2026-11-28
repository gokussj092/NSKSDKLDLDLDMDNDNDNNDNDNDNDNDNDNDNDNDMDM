# RESULTS — DGM Tunnel 15.11.2026 (`com.dgmtunnel.app`, code 17)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| "Catalog" (public feed) | **VERIFIED_REAL** | Live fetch 2026-11-28 10:05:49 UTC: HTTP 200, 2,122,468 B, 8,880 lines / 8,873 links; 500 parsed after 557 lines (57 rejected); dedup → 171 unique; catalog = first 40 lines, all Shadowsocks |
| Encrypted catalog | **VERIFIED_ABSENT** | `libgojni.so` is the stock Xray core; no encrypted catalog exists |
| DGMTUNNEL_SHARE v2 (no password) | **VERIFIED_REAL** | Real share `494af5fc…` (expired 2026-11-26 01:39:30 UTC) decrypted; config saved in the batch dir (credentials redacted, NOT included here) |
| DGMTUNNEL_SHARE v2 (with password) | **PARTIAL** | Real share `9bcf46a7…` verified expired (2026-11-27 11:17:15 PST) and password-protected with an unknown password; codec verified by round-trip only |
| Proprietary file format | **VERIFIED_ABSENT** | No `.sks` or any other DGM file format |
| SSH login (catalog or profile) | **PENDING** | Only the feed and the shares were decrypted; no login attempted |

## Tests run (2026-11-28, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, cryptography 50.0.2, pycryptodome 4.6.0)

- `python3 -m unittest discover -s analysis/com.dgmtunnel.app/17/tests`:
  **8 passed** (feed parsing, profile schema, share round-trip
  with and without password, wrong-password negative, redaction
  of real IPs).
- Live verification (batch analyst, same venv):
  feed fetch → 8,880 lines / 8,873 links / 171 unique.
  Share `494af5fc…` decrypted (TROJAN). Share `9bcf46a7…`
  confirmed expired + password-protected.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- The "catalog" is a third-party rotating list with no version; the
  first 40 lines are the catalog at fetch time.
- Both real DGMTUNNEL_SHARE v2 links verified are expired; a fresh
  share from the app would confirm the codec end to end with real
  content.
- The decrypted config of the unprotected share contains real
  credentials and is NOT included in this dossier.
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-GCM calls used are API-stable across both, but
  the coordinator should run the worker suite against 3.23.0.
