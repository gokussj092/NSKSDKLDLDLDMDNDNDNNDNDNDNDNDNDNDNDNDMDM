# RESULTS — Peru VPN 4.1.2 (`com.peru.vpn`, code 412)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| Catalog (live) | **VERIFIED_REAL** | Live fetch 2026-11-28 (two downloads, byte-identical): HTTP 200, 641,872 B, Version 532, 390 servers, 1,812 encrypted fields, all decrypted; `web.tunneldoom.space` dead (HTTP 000) and absent from the DEX |
| Catalog (bundled `noobdev.txt`) | **VERIFIED_REAL** | `res/raw/noobdev.txt` from the 4.1.2 base.apk decodes with the same codec: Version 2, 8 servers, 40 fields |
| Proprietary file format | **VERIFIED_ABSENT** | 0 literals `.sks`/`.td`/`.peru` in DEX; no file intent filter in the manifest |
| Proprietary text scheme | **VERIFIED_ABSENT** | Only standard import (manual/clipboard/QR of vless/vmess/trojan/hysteria2/wireguard URIs) |
| SSH login (catalog or profile) | **PENDING** | Only the catalog was decrypted; no login attempted |

## Tests run (2026-11-28, venv `~/workspace/.venv-mehaf/bin/python`, Python 3.12.3, pycryptodome 4.6.0)

- `python3 -m unittest discover -s analysis/com.peru.vpn/412/tests`:
  **7 passed** (synthetic catalog fixture decode, envelope round-trip,
  empty field, truncated/garbage negatives, bad-field negative, no
  real IPs in fixtures).
- Live verification (batch analyst, same venv):
  `server_catalog_decoder.py` (live download) → Version 532,
  390 servers; second download byte-identical. `catalogo_completo.json`
  (423,235 B) and `catalogo_redactado.json` (0 IPs) produced in the
  batch work dir; the complete copy is chat-only, never in the ZIP.
- `py_compile` on every new Python file in this staging: **OK**.

## Known limits

- The app defines no proprietary file or text format: there is nothing
  to decode beyond the catalog, and no new file/text entries are needed.
- The bundled asset `assets/config/config/…/config.json`
  (EncServer/Nonce/Hash, AES-GCM) is unexplained and unreferenced by
  any DEX code in this build; it does not block the catalog.
- The repo entry for Peru VPN still points at the dead host
  `web.tunneldoom.space`; it must be updated to
  `https://free.tunneldoom.space/config.json` when this dossier is
  integrated (not done here).
- Verification ran with pycryptodome 4.6.0; the worker image pins
  3.23.0. The AES-CBC calls used are API-stable across both, but the
  coordinator should run the worker suite against 3.23.0.
