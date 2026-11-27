# Results — TunnelDOOM VPN 4.3.5 (build 435)

## Status: VERIFIED (catalog) / PENDING (.sks file)

| Check | Result |
| --- | --- |
| Live catalog, analysis run 2026-11-27 | HTTP 200, 643,344 bytes, Version 531, 391 servers, 1,816 encrypted fields decrypted, 0 encrypted values left |
| Live catalog, patch re-run 2026-11-27 | HTTP 200, Version 532, 390 servers (catalog had moved); opens with the unchanged keys |
| Crypto vs 4.3.2 | Identical (StringCrypter `test_key` envelope + NoobCrypt AES-256-CBC fields) |
| Old host `web.tunneldoom.space` | Dead (connection closes) — confirmed 2026-11-27 |
| New host `free.tunneldoom.space` | Live, decrypts fully |
| Bundled `noobdev.txt` | Decrypts (Version 3, 1 `prueba` server) |
| `.sks` file decoder | Synthetic round-trip only (GCM + DES); no real build-435 export |
| Proprietary text scheme | None exists (DEX-verified) |
| Synthetic unit tests | `python3 -m unittest analysis/com.tunneldoom.http/435/tests/test_method.py -v` — see test output below |

## Synthetic unit tests (run 2026-11-27)

Run from the repo root with the staged decoder files in place:

```bash
python3 analysis/com.tunneldoom.http/435/tests/test_method.py -v
```

Expected: 5 tests, all OK (envelope round-trip on a synthetic catalog,
NoobCrypt field round-trip, bad-input rejection, new-host constant check,
old-host absence check).

## Negative / boundary cases

- Garbage bytes as catalog input → `DecodeError` (no crash, no partial output).
- Truncated Base64 field → `DecodeError`.
- Old host URL → connection failure, never a silent fallback to another host.
- A server with an empty `ServerIP` (SNI-only) is preserved as-is, not dropped.

## What was NOT verified

- No real `.sks` file exported by build 435 exists, so the file decoder
  stays PENDING (same as 4.3.2).
- The unexplained `EncServer` asset does not open with any known key and
  has no DEX reader; treated as a possibly dead fixture.
