# RESULTS — ExoticFast VIP "Rk1" (`com.rkbuild.exoticfastvip`, vc 1)

Date: 2026-11-27. Environment: Python 3.12, pycryptodome 4.4.0.

## Live catalog — VERIFIED_REAL

- Fetch: plain GET, HTTP 200, 115,080 bytes, `application/json`.
- Re-fetch 2026-11-27: byte-identical to the delivered sample
  (SHA-256 of `catalogo-completo.json`
  `83a83403d8ef790431dd505f7ea8c03f2368537db3941eb7d3391f9c62def241`).
- Version 5.8; 6 servers (0 free, 6 PREMIUM); 13 networks;
  0 SSL networks; 5 server payloads, 9 network payloads non-empty.
- j0 round-trip `l0(j0(x)) == x` on the 20 non-empty j0 fields of the
  live catalog + `OVPNCert`: 0 errors. No encrypted value remains in
  the delivered JSON.
- Result JSON contains no download API (`update_api`/`auth_api`/
  `notice_api` removed by the decoder).

## Files — VERIFIED_SYNTHETIC

- `.rj`: verified by decrypting the real live response and the
  APK-bundled default `res/0k.js` (v1.0, 3 servers, 51 networks)
  with the same envelope. No real user-exported file yet.
- `.ovpn`: verified with a realistic profile built from the app's own
  `OVPNCert` template (remote, proto, dev, cipher, auth,
  `auth-user-pass`, inline `ca`/`cert`/`key` detected). No real user
  file yet. Helper only; not registered.
- `.js`: same blob as `.rj`, but NOT registered (generic extension).

## Dossier tests

`tests/test_exoticfast_vip.py` — 5 tests, synthetic fixtures only:

| Test | Result |
|---|---|
| `test_synthetic_rj_decodes` (bridge `run()` on `synthetic.rj`) | PASS |
| `test_file_decoder_cli` (engine CLI contract, one JSON doc) | PASS |
| `test_corrupt_rj_rejected` (truncated blob) | PASS |
| `test_empty_input_rejected` | PASS |
| `test_result_has_no_download_api` | PASS |

Run: `python3 -m pytest analysis/com.rkbuild.exoticfastvip/1/tests/test_exoticfast_vip.py -v`
Observed at staging (2026-11-27, Python 3.12, pycryptodome 4.4.0):
5 passed.

## Negative / failure cases observed

- Old endpoints `nazmulvippro.xyz` / `rktunnelvip.xyz`: empty
  response (curl 000) — dead.
- Truncated `.rj` blob: rejected with a decode error (no partial output).
- Empty input: rejected.

## Limits (not failures)

- `[rkhost]`/`[rkkey]` placeholders in SERVER 1/2 templates are not
  replaced by any code in this build; kept verbatim.
- No live connection tested (PREMIUM servers, no test account).
- A synthetic fixture proves the implemented logic, not compatibility
  with a real user-exported file; that confirmation is still pending.
