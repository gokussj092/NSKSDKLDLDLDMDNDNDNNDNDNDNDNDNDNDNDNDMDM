# Results — TunelGuard VPN 17.7 (build 177)

## Status: VERIFIED (catalog) / PENDING (.tgv file)

| Check | Result |
| --- | --- |
| Live catalog, analysis run 2026-11-27 | HTTP 200, 991,263 bytes, STGCM3, v5.0 / rev 50, 90 servers (85 PREMIUM, 5 VIP, 0 FREE), 1,058 tweaks, 548 with Payload |
| Live catalog, patch re-run 2026-11-27 | Byte-identical envelope (SHA-256 `be741d89…`); staged codec output is fully equal to the analyst's decode |
| Bundled seed | Version 0.1, rev 2, 1 server, 1 tweak — opens with the staged codec (v3 key) |
| Field decryption | 0 `TGCR1.` left, 0 undecrypted CJK, 0 `u8:` left |
| `.tgv` file decoder | HELD at the 12.8 native CBC profile; Java STUC1 GCM format not staged (see ANALYSIS.md) |
| Proprietary text scheme | None exists |
| Synthetic unit tests | `python3 analysis/tunnel.guard.vpn/177/tests/test_method.py -v` — 6 tests, all OK |

## Synthetic unit tests (run 2026-11-27)

```bash
python3 analysis/tunnel.guard.vpn/177/tests/test_method.py -v
```

Expected: 6 tests OK (STGCM3 envelope round-trip on a synthetic catalog,
TGCR1 field decrypt, `u8:` field, bad-tag rejection, unknown-version
rejection, new-URL constant check).

## Negative / boundary cases

- Garbage input → `DecodeError`.
- STGCM9 (unknown version) → `DecodeError`.
- Flipped GCM tag → `DecodeError` (authentication failure, no partial output).
- A catalog with 0 FREE servers is reported as-is; no free/paid notion invented.

## What was NOT verified

- No real `.tgv` file exported by 17.7 exists, so the file format stays
  PENDING and the 12.8 native CBC decoder is kept (decision in ANALYSIS.md).
- The 17.7 native `.tgv` master-key value was not extracted; the 12.8
  `FILE_KEY` is assumed unchanged, unverified for 17.7.
