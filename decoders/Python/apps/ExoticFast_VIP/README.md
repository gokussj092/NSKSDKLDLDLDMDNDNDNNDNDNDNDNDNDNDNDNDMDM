# ExoticFast VIP — SP-DECODE server decoders

App: ExoticFast VIP, versionName "Rk1" (versionCode 1), package
`com.rkbuild.exoticfastvip`. Dossier:
`analysis/com.rkbuild.exoticfastvip/1/`.

## Catalog (live, VERIFIED)

- Broker: plain GET, no special headers.
- Live catalog v5.8 (verified 2026-11-27, re-fetch byte-identical):
  6 servers (0 free, 6 PREMIUM), 13 networks, 0 SSL networks.
- Envelope: block-alphabet -> Base64 -> AES-256-CBC (IV zero);
  then every `j0` field (XXTEA + Base64) is decrypted. All fields
  verified decrypted (20 j0 fields + `OVPNCert`, 0 errors).
- `server_catalog_decoder.py` exposes `run(bytes) -> str` for the
  bridge. The result JSON contains only catalog data — no download
  API. `exoticfastvip.py` is the shared logic module (analyst script,
  kept intact); `xxtea_j0.py` is the `j0`/`l0` implementation.

## Files

- `.rj` — offline-update blob: the same encrypted envelope the
  server returns. `file_decoder.py` decodes it (engine CLI contract:
  one JSON document on stdout). Verified against the live response
  and the APK-bundled default (v1.0).
- `.js` — the app accepts the same blob as `.js`, but `.js` is a
  GENERIC extension and is NOT registered as an app suffix. Only
  `.rj` is registered. A `.js` blob still decodes if passed to
  `file_decoder.py` directly.
- `.ovpn` — plain OpenVPN profile, parsed by the app with a generic
  profile parser. NOT registered as an app suffix: it is a generic
  format, not ExoticFast-specific. `ovpn_decoder.py` in this directory
  is a helper parser only; it is not wired to the engine.
- No text schemes: the manifest has no VIEW intent filters with data
  schemes. `vless://` links appear only as payloads inside the
  catalog, not as import links.

## Honest limits

- SERVER 1 and SERVER 2 carry `vless://` templates with
  `[rkhost]`/`[rkkey]` placeholders that no code in this build
  replaces; they are kept verbatim.
- No real user-exported `.rj`/`.js` file and no real `.ovpn` file
  from a user yet (verified with the live response, the bundled
  default, and a realistic profile built from the app's own
  `OVPNCert` template).
- No live connection tested: all 6 servers are PREMIUM and auth uses
  the user's login; there is no test account.

## Files in this directory

- `exoticfastvip.py` — catalog logic (shared by both adapters)
- `xxtea_j0.py` — XXTEA `j0`/`l0`
- `server_catalog_decoder.py` — bridge entry point `run(bytes)->str`
- `file_decoder.py` — engine CLI adapter for `.rj`
- `ovpn_decoder.py` — helper parser for plain `.ovpn` (not registered)
- `manifest.json` — integration metadata
