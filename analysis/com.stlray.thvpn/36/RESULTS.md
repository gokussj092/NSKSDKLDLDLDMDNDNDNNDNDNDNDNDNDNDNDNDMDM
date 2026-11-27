# RESULTS — STLRAY 1.1.36 (`com.stlray.thvpn`, code 36)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| Catalog (3 paired sources) | **VERIFIED_REAL** | Live fetch 2026-11-27: config rev 150086/15.86, 76 servers, 38 payloads, 6 certs, ECDSA signatures valid; modes rev 10009 (14 modes); policy rev 10007. Re-fetch byte-identical except the stripped `updates` block |
| `.sray` / `.tvc` / `.gv` / `.uv` / `.gpx` / `.test` / `.insan` / `.opq` files | **VERIFIED_SYNTHETIC** | Round-trip encode/decode over a real catalog profile (`CELCOM BASIC 01`, 15 fields): normal + locked + all 8 keyed schemes + `hyb://`, raw bytes and base64url text — all MATCH. No real exported file yet |
| `sray://` … `hyb://` texts | **VERIFIED_SYNTHETIC** | Same round-trip as files; `decode_text` returns None for non-STLRAY text |
| `vless://` texts | **VERIFIED_REAL (already registered)** | Standard VLESS `sourceUri` links from the live catalog; no new entry needed |
| `.ovpn` / sing-box JSON / subscriptions | **NOT_APPLICABLE** | Native `libstlraytcore.so` core (`ProfileDecoder.Decode`); out of scope for this Python decoder |
| SSH login (catalog or profile) | **PENDING** | Only the catalog/profile was decrypted; no login attempted |

## Tests run (2026-11-27, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, cryptography 50.0.2, pycryptodome 4.6.0)

- `file_decoder.py --self-test`: **OK** (TVC round-trips normal/
  locked, 8 schemes, `hyb://`, raw bytes; truncated/garbage
  negatives).
- `pytest analysis/com.stlray.thvpn/36/tests/test_stlray.py`:
  **9 passed** (TVC links normal/locked/raw, unknown-scheme None,
  negatives, 3-source bundle merge, single envelope, bad-bundle
  rejection, no-download-API assertion).
- Live verification (analyst script, same venv):
  `stlray.py catalog` → config rev 150086, 76 servers, sig True;
  modes rev 10009, 14 modes, sig True; policy rev 10007, sig True.
  Re-fetch 2026-11-27 ~20:40 UTC: config JSON byte-identical to
  the delivered `catalogo-completo.json` except the `updates`
  block (stripped by the bridge, by design).
- Bridge against live bytes: paired bundle built from the three
  live raw envelopes → `run()` returns the merged catalog
  (76 servers, 14 modes, no `updates`, no `stallionray.my.id`
  string in the result). See REPRODUCE.md §3.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- No real exported `.sray` file or STLRAY link yet — the TVC
  codec is round-trip verified only.
- `.gv` shares its suffix with Generic AES-GCM/PBKDF2: dispatch
  is by content shape (see ANALYSIS.md §3). A TVC raw file could
  in theory look generic-shaped by chance; the probability is
  negligible and the same heuristic class the repo already uses
  for `.ost` / `.bee` / `.eut`.
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-GCM calls used are API-stable across both, but
  the coordinator should run the worker suite against 3.23.0.
