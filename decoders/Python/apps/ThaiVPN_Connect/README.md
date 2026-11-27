# ThaiVPN Connect 2.4 — SP-DECODE provider

- **App:** ThaiVPN Connect 2.4 (`com.openvpnservice.thaivpnconnect`,
  versionCode 24)
- **Provider id:** `thaivpn-connect`
- **Status:** VERIFIED_REAL (live catalog) / VERIFIED_SYNTHETIC
  (`profile.json` — round-trip only, no real exported file yet)
- **Dossier:** `analysis/com.openvpnservice.thaivpnconnect/24/`

## Catalog (live, single file)

Plain GET, no headers, no auth:

- `https://thaivapp.my.id/app/thvpn.json`

The server answers with a one-line Base64 blob: outer XXTEA
(delta 772515655, static key from `MainDetail.b()` — see
`thaivpn.py`) -> JSON
with `Version` / `Message` / `Servers` / `Networks` / `setOpenVPN`;
inner fields are Base64 at runtime (`ServerIP`, `Username`,
`Password`, `PublicKey`, `UDPConfig`, `setOpenVPN`, `Sni`,
`Payload`, `SquidProxy`, `ServerDNS`, `V2Ray`). See `thaivpn.py`.

Verified live 2026-11-27: catalog v17.9, 1 server
(`GENERAL 01`), 24 networks, 0 leftover encoded values.
Re-fetch byte-identical to the delivered sample. The result JSON
carries NO download API.

## Files — `profile.json` (`file_decoder.py` over `thaivpn.py`)

The app stores the same encrypted JSON in its private file
`profile.json` (Base64 + XXTEA, same key). `file_decoder.py`
decodes it (`decode` / `run`, CLI `file_decoder.py <profile.json>`,
`--self-test` round-trip, `--encrypt` to rebuild the blob).

**Routing decision (deliberate): this decoder is NOT wired to
`cloud/workers/python/engine.py`.** The file is literally named
`profile.json` — its suffix is `json` — and registering a `json`
engine would claim every `.json` file a user imports. There is no
filename-scoped route in the engine. The supported live route is
the catalog; the file decoder ships for operator/manual use and
for the dossier's round-trip verification. If Pedro wants the
file route wired later, the engine needs a filename-scoped
(`profile.json`) dispatch first — see the group REPORT.md.

## Texts

None. The app has no custom scheme; its V2Ray part only handles
the standard `vmess://` / `vless://` / `trojan://` / `ss://`
links, already covered by the generic V2Ray decoders.

## Files in this directory

- `thaivpn.py` — analyst script, verbatim (catalog + profile.json
  + encrypt). Canonical method source.
- `server_catalog_decoder.py` — bridge adapter, `run(bytes) -> str`.
- `file_decoder.py` — profile.json adapter (NOT engine-wired, see
  above).
- `manifest.json` — provider registry data.

## Dependencies

Python 3.12, standard library only. No network in the decoders —
the broker downloads, the worker only decrypts.

## Pending

- A real exported `profile.json` from the installed app, to
  confirm the file format end-to-end (round-trip verified with
  the live catalog).
- Icons: `thaivpn-connect.png` (SHA-256 in the group REPORT.md) —
  Pedro uploads it; never committed here.
