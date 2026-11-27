# ANALYSIS — ASL TUNNEL 3.0 (`com.asltunnel.vpn`, vc 3)

- Observed: 2026-11-27. APKS `ASL_TUNNEL_VPN_3.0_3_m241.apks`
  (49,672,320 B), SHA-256
  `825bb4b5d363ab6419cffb2ec1cec65619b9c9b89ea874785c1638ccef64ee55`.
- Status: catalog VERIFIED_REAL; `.asl` file VERIFIED_SYNTHETIC;
  standard texts VERIFIED_REAL (generic handling); `asl://` PENDING.
- Platform: v2rayNG fork (NoobDev) + Sandok/Ultra layers. Native
  libraries live in `split_config.arm64_v8a.apk` (incl. `libwg-pro.so`,
  where the native NoobCrypt lives).

## Objective

Decode the live catalog and the `.asl` file format ASL TUNNEL
imports, so SP-DECODE Cloud can serve the catalog and decode `.asl`
files. Text links are the standard v2rayNG set and need no new code.

## What was observed

- Catalog fetch: plain HTTP GET, no headers, no auth (class `LSu`,
  runnable `LN.run`). Response HTTP 200, 462,840 bytes, fetched twice
  with identical content. SHA-256 of the live response:
  `c89f2e39cb777047b78e76e76799557b836f15db185f5907a4017698bdd068e7`.
- Live catalog: Version 20.10, 35 servers (all NoobLevel 0 = free),
  292 tweaks (124 with Payload). Protocols: OVPN 8, SSH 8, DNS 5,
  Hysteria/UDP 4, V2Ray/ULTRA 10.
- Bundled catalog: APK resource `res/raw/noobdev.js`, Version 1.0.1,
  1 server PREMIUM + 1 tweak, `unlimited: true`.
- Related endpoint (NOT the catalog): the app checks updates at a
  separate API host (see `asltunnel.py` notes in the work dir); it is
  not part of this integration.

## Method (observation -> hypothesis -> verification)

### Envelope

- Observation: the response body is one line of Base64. Hypothesis:
  Base64 -> XXTEA (custom delta, fixed 16-byte key recovered from the
  app code) -> JSON, with the plaintext length in the last word.
  Verification: `decrypt_alt` in `asltunnel.py` yields 347,124 bytes
  of JSON. Key values live only in the decoder script, never in this
  dossier.

### Field layers

- Observation: server/top-level string fields and tweak fields are
  opaque Base64. Hypothesis: servers use AES/CFB (fixed key/IV
  recovered from the app code); tweaks use AES/CBC (fixed key/IV
  recovered from the app code); nested `V2ray`/`SlowDNS`/`UDP`
  sub-objects use the same AES/CFB as servers. Verification: all
  fields decrypt to readable text — 38 nested values, 0 failures.
  Tweak `Flag` is PLAINTEXT (`NOOB_DEV`) and is never decrypted.
- No encrypted or encoded value remains in the delivered JSON.

### `.asl` format (reversed from the native library)

- Observation: import filter `.*\.asl` -> `d0(Uri)` reads the file as
  one string -> `S()` calls native `NoobCrypt.Nbdecrypt(String, int)`.
  Hypothesis (mode 1): Base64 -> IV[16] + AES-256-CBC -> the marker
  `ASL TUNNEL VPN` + JSON, with a fixed 32-byte ASCII key from
  `libwg-pro.so` `.rodata`. Verification: native disassembly
  (`nbdecrypt_annotated.asm`, `nbencrypt.asm` in the work dir) confirms
  the layout; round-trip (encode -> decode -> identical) passes for
  both shapes (see below). Key values live only in the decoder script.
- Two shapes: the Q() import config (plaintext fields) and the LCl.b
  custom-server object (string fields AES/CFB-encrypted, same scheme
  as the catalog server fields). The decoder tells them apart by keys
  that only the server shape has (`ProxyPort` is shared by both and is
  NOT a discriminator) and decrypts only the server shape.
- Import checks (reported, not enforced by the decoder): `ExpireDate`
  (ms epoch, 0 = no expiry), `DeviceID` (`;`-separated allowlist,
  empty = any device), `RootBlock` (refuses rooted devices),
  `PSInstall` (requires Play installer), `isPassON` (prompts for the
  password in `MyPass`).
- Other NoobCrypt modes (0 = AES-256-GCM, 2 = ChaCha20, 3 =
  ChaCha20-Poly1305) share the key table but their nonce/tag layouts
  were not mapped; `.asl` uses mode 1 only.

## Files and texts

- `.asl` — VERIFIED_SYNTHETIC (round-trip, both shapes). No real
  user-exported file yet.
- `.ovpn` — standard OpenVPN profile, no app-specific crypto. NOT
  registered (generic format).
- `vmess://`, `vless://`, `trojan://`, `ss://` — standard v2rayNG
  import (scheme table, import handler; the app also generates
  `vless://...#Noob_XHTTP` / `#Noob_V2ray`). Already handled
  generically; no new entries.
- `asl://<20 chars>` — the app's own cloud-export link
  (`ExportActivity.l`, "Uploading to cloud"). Its resolution endpoint
  was NOT identified (no real exported link sample). Documented, NOT
  implemented, NOT registered. Pending a real `asl://` link.

## HMAC audit (policy §2.2)

- File/catalog: NOT_OBSERVED — XXTEA envelope, AES/CFB, AES/CBC, all
  with no MAC.
- Transport VPN: NOT_OBSERVED — no HMAC in the reviewed paths.
- Connection authentication: NOT_OBSERVED — no evidence any HMAC
  authenticates a connection; no live login/connection attempted.
- "NOT_OBSERVED" covers only the reviewed paths; it does not prove
  universal absence.

## Excluded finding

- A third-party service token was observed in the app code during the
  analysis (alongside a VirusTotal API use). It is NOT included in this
  dossier, in any staged file, or in any fixture — only this note that
  a third-party token was observed and excluded.

## Data quirks (kept verbatim)

- One Hysteria server uses `~` as a host separator; one GCP OVPN
  server's host ends with a literal `"` character.
- Catalog message announces "New Update" (GCP ONLINE) and links the
  app's Telegram group; `defTime 30`, `addTime 180`, `bonus 120`.

## Failed / negative attempts

- Invalid `.asl` (bad Base64 / wrong marker): rejected with
  "Invalid config: does not belong to this app".
- The bundled catalog (v1.0.1) decrypts with the same envelope, but
  it is NOT the live catalog (1 server vs 35).

## What is still pending

1. A real user-exported `.asl` file and/or CONFIG KEY.
2. A real `asl://` link, to identify the cloud resolution endpoint.
3. A real-phone confirmation that an imported `.asl` opens the server.
