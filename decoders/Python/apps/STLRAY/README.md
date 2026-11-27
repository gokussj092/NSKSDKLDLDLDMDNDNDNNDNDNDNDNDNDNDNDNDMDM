# STLRAY 1.1.36 — SP-DECODE provider

- **App:** STLRAY 1.1.36 (`com.stlray.thvpn`, versionCode 36)
- **Provider id:** `stlray-vpn`
- **Status:** VERIFIED_REAL (live catalog) / VERIFIED_SYNTHETIC (files
  and links — round-trip only, no real exported file/link yet)
- **Dossier:** `analysis/com.stlray.thvpn/36/`

## Catalog (live, 3 files, PAIRED_SOURCES)

One prefix, three THAIVPN2 envelopes (5-layer AES-256-GCM + HMAC +
ECDSA P-256 signature):

- `https://stallionray.my.id/sray_v2x6w9c4/config.json`
- `https://stallionray.my.id/sray_v2x6w9c4/modes.json`
- `https://stallionray.my.id/sray_v2x6w9c4/policy.json`

Plain GET, User-Agent `Dalvik/2.1.0 (Linux; U; Android 14)`, no auth.
The broker fetches all three (paired) and packs them into the bundle
`spdecode-stlray-vpn-catalogs-v1`; `server_catalog_decoder.run()`
decrypts each envelope, verifies the ECDSA signature when present,
drops the `updates` block from all three documents (download API /
locator — never in a result JSON, per Pedro's rule) and returns the
config catalog with the decrypted `modes` and `policy` documents
under those keys.

Verified live 2026-11-27: config rev 150086 / 15.86, 76 servers
(71 free + 5 premium), 38 payloads, 6 certificates, signatures
valid; modes rev 10009 (14 modes); policy rev 10007. Re-fetch
byte-identical to the delivered sample except the stripped `updates`
block.

## Files — codec "TVC" (`file_decoder.py` over `stlray.py`)

`.sray` `.tvc` `.gv` `.uv` `.gpx` `.test` `.insan` `.opq`: raw
link-body bytes (`salt || MASK(GCM layers)`) or base64url text.
Per-scheme 32-byte keys; `hyb://` reuses the `sray://` key.
Variants tried in order: locked (salt 16, 7 layers, 128 rounds),
normal (salt 12, 1 layer, 64 rounds), legacy (salt 16, 7 layers,
64 rounds). No password needed.

**`.gv` collision:** `.gv` is already registered as "Generic
AES-GCM / PBKDF2" (`decoders/Python/generic_aes.py` — exactly three
dot-separated Base64 segments: salt.nonce.ciphertext+tag). STLRAY
`.gv` files are TVC bytes or a single base64url token (no dots), so
the engine dispatches by content: a file that is NOT a generic
3-segment envelope goes to STLRAY; a generic-shaped file keeps the
frozen generic route (same negative-shape predicate pattern as
`.ost` / `.bee` / `.eut`). The public `file-formats.json` entry for
`gv` therefore names both formats. See the engine fragment and
`REPORT.md`.

## Texts (`decode_text` in `file_decoder.py`, wired in `text_bridge.py`)

`sray://` `tvc://` `uv://` `gv://` `gpx://` `insan://` `opq://`
`test://` `hyb://` (TVC codec) and standard `vless://` (already
registered — the catalog's `sourceUri` links; no new entry).

## Files in this directory

- `stlray.py` — analyst script, verbatim (catalog THAIVPN2 + TVC
  codec + vless parser + redaction). Canonical method source.
- `server_catalog_decoder.py` — bridge adapter, `run(bytes) -> str`.
- `file_decoder.py` — file/text adapter (`decode` / `run` /
  `decode_text`, `--self-test`).
- `manifest.json` — provider registry data.

## Dependencies

Python 3.12, `cryptography` (ECDSA P-256 verification),
`pycryptodome` (AES-256-GCM). No network in the decoders — the
broker downloads, the worker only decrypts.

## Pending

- A real exported `.sray` file or STLRAY link, to confirm the TVC
  codec end-to-end (round-trip verified on a real profile from the
  live catalog; see the dossier).
- Icons: `stlray-vpn.png` (SHA-256 in the group REPORT.md) — Pedro
  uploads it; never committed here.
