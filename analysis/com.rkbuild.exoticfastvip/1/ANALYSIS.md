# ANALYSIS — ExoticFast VIP "Rk1" (`com.rkbuild.exoticfastvip`, vc 1)

- Observed: 2026-11-27. APK `exoticfastvip_2_fy53.apk` (91,583,599 B),
  SHA-256 `44e61a1a089924422ae73efe835c388f3c8cba4bab3e491ea314d44a4800290d`.
- Status: catalog VERIFIED_REAL; `.rj` file VERIFIED_SYNTHETIC;
  `.js`/`.ovpn` NOT_APPLICABLE as app suffixes; no text schemes.

## Objective

Decode the live catalog and the file formats ExoticFast VIP imports,
so SP-DECODE Cloud can serve the catalog and decode `.rj` offline
updates. The app is a technore-family build (OpenVPNClient + Hysteria2
+ V2Ray); all 6 live servers are PREMIUM.

## What was observed

- Catalog fetch: plain HTTP GET, no special headers (class `f4/b.java`).
  Response HTTP 200, 115,080 bytes, `application/json`.
  SHA-256 of the raw live response:
  `517c049a07d8a907a920e0ed162ce9b214d82074e342350f292fa7b08910a5b2`.
- Live catalog: Version 5.8, 6 servers (0 free, 6 PREMIUM), 13 networks,
  0 SSL networks, 5 server payloads and 9 network payloads non-empty.
- Bundled default catalog: APK resource `res/0k.js`, Version 1.0,
  3 servers (0 free, 3 PREMIUM), 51 networks, 0 server payloads.
  Used only when no saved `Servers.js` exists.
- Old endpoints `nazmulvippro.xyz` and `rktunnelvip.xyz` are dead
  (empty response, curl 000). Do not retry.

## Method (observation -> hypothesis -> verification)

### Outer envelope

- Observation: the response is a string of block characters from a
  16-character alphabet. Hypothesis: each pair of characters is one
  byte, the bytes are ASCII Base64, and the Base64 payload is an
  AES-256-CBC ciphertext with IV zero. Verification: implemented in
  `exoticfastvip.py` (`outer_decrypt`); the live response decrypts to
  valid JSON. The AES key is derived (SHA-256) from a fixed string
  recovered from the app code plus the outer key; two outer keys are
  tried in order (live key first, fallback second), mirroring the app.
  Key values live only in the decoder script, never in this dossier.
- Fallback behaviour (as the app does): if all keys fail and the input
  already starts with `{`, it is used as-is.

### Field layer (j0)

- Observation: server/network fields and `OVPNCert` are opaque
  Base64 strings. Hypothesis: XXTEA + Base64 with a fixed key
  recovered from the app (`OpenVPNClient.j0`). Verification:
  `l0(j0(x)) == x` on the 20 non-empty j0 fields of the live catalog
  plus `OVPNCert`: 0 errors. All decrypted fields are readable text;
  no encrypted value remains in the delivered JSON.
- j0 fields — servers: `ServerIPHost`, `ServerCloudFrontHost`,
  `ServerHTTPHost`, `Username`, `Password`, `Payload`, `Nameserver`,
  `PublicKey`, `ServerEntry`. Networks: `Payload`, `FrontQuery`,
  `BackQuery`, `SNIHost`, `ProxySettings.Squid` (except `"[Default]"`).
  Top level: `OVPNCert`.

### Deobfuscation trap (relevant)

- The LSPosed deobfuscator class holds 150 string chunks. The jadx
  decompilation of `RandomHelper.next()` is WRONG (int operations);
  the real bytecode computes the return in LONG. The faithful version
  is `deobfuscate.py` (work dir). 1,358 deobfuscated strings were
  recovered. `deob_map.json` is TRUNCATED — do not use it.

## Files and texts

- `.rj` / `.js` (offline update): the update dialog offers "Offline
  Update - Needs to import .rj or .js file". The file is the same
  encrypted envelope the server returns. Verified by decrypting the
  real live response and the bundled `res/0k.js` (v1.0). `.js` is NOT
  registered: it is a generic extension and registering it would claim
  every JavaScript file for this app. Only `.rj` is registered.
- `.ovpn`: imported in `OpenVPNClient.onActivityResult` (requestCode 2);
  the path must end in `.ovpn`; parsed with a generic ics-openvpn
  profile parser. It is a plain profile (directives + inline
  `<ca>`/`<cert>`/`<key>` blocks). NOT registered: `.ovpn` is generic,
  not ExoticFast-specific, and no generic `.ovpn` route exists in the
  server engine. `ovpn_decoder.py` is a helper parser only.
- No text schemes: the manifest has no VIEW intent filters with data
  schemes. `vless://` links occur only as payloads inside the catalog.

## Catalog content (live v5.8, summary — no credentials)

- Servers: SERVER 4 (DE, Protocol 0), MEGA SERVER 1/2 (DE/IM,
  Protocol 1, Hysteria2), MEGA SERVER 4 (UG, Protocol 1, Hysteria2),
  SERVER 1/2 (US/ZA, Protocol 2, `vless://` templates). All PREMIUM;
  per-server Username/Password empty (auth uses the user's login).
- Networks: 13 tweaks, mostly Uganda Airtel/MTN and DRC Orange;
  `ServerHostDNS: "cf"` (CloudFront) on all.
- `OVPNCert` decrypts to an OpenVPN client template with its CA.
- Placeholders `[rkhost]`/`[rkkey]` in the SERVER 1/2 `vless://`
  templates are replaced by NO code in this build (grep over the full
  jadx output: 0 results). They are kept verbatim.

## HMAC audit (policy §2.2)

- File/catalog: NOT_OBSERVED — AES-256-CBC + PKCS7 with no MAC;
  XXTEA fields with no MAC.
- Transport VPN: NOT_OBSERVED — no HMAC in the reviewed paths.
- Connection authentication: NOT_OBSERVED — no evidence any HMAC
  authenticates a connection; no live login/connection attempted.
- "NOT_OBSERVED" covers only the reviewed paths (catalog fetch,
  offline update, `.ovpn` import); it does not prove universal absence.

## Failed / negative attempts

- Old endpoints (`nazmulvippro.xyz`, `rktunnelvip.xyz`): empty
  responses; dead, not retried.
- `deob_map.json` truncated/incomplete: not used.
- jadx `RandomHelper.next()` decompilation wrong: corrected from
  bytecode (see above).

## What is still pending

1. A real user-exported `.rj`/`.js` file and a real user `.ovpn` file.
2. A real connection test (needs a premium account) to see whether
   `[rkhost]`/`[rkkey]` resolve at connect time.
