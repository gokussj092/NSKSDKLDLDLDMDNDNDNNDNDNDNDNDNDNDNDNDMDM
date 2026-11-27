# ASL TUNNEL — SP-DECODE server decoders

App: ASL TUNNEL 3.0 (versionCode 3), package `com.asltunnel.vpn`.
Fork of v2rayNG (NoobDev) + Sandok/Ultra layers. Dossier:
`analysis/com.asltunnel.vpn/3/`.

## Catalog (live, VERIFIED)

- Broker: plain GET, no headers, no auth.
- Live catalog v20.10 (verified 2026-11-27, re-fetch byte-identical):
  35 servers (all free, NoobLevel 0), 292 tweaks (124 with Payload).
- Envelope: Base64 -> XXTEA (custom delta) -> JSON; then servers and
  top-level fields with AES/CFB, tweaks with AES/CBC, and nested
  `V2ray`/`SlowDNS`/`UDP` objects with AES/CFB. 38 nested values
  verified, 0 failures; no encrypted value remains in the JSON.
- `server_catalog_decoder.py` exposes `run(bytes) -> str` for the
  bridge. The result JSON contains only catalog data — no download
  API. `asltunnel.py` is the shared logic module (analyst script,
  kept intact).

## Files

- `.asl` — Base64 -> IV[16] + AES-256-CBC -> `"ASL TUNNEL VPN"` +
  JSON. `file_decoder.py` decodes it (engine CLI contract: one JSON
  document on stdout). Two shapes: the Q() import config (plaintext
  fields) and the LCl.b custom-server object (AES/CFB-encrypted
  fields), told apart by keys. Verified by synthetic round-trip
  (encode -> decode -> identical) for both shapes; no real
  user-exported `.asl` yet.
- Password: when `isPassON` is true the app prompts for the password
  in field `MyPass`. The decoder reports the config verbatim and
  notes the requirement on stderr; it does not enforce device, root,
  expiry or installer checks.
- `.ovpn` — standard OpenVPN profile, no app-specific crypto. Not
  registered (generic format). `asltunnel.py ovpn <file>` reads one.

## Texts

- `vmess://`, `vless://`, `trojan://`, `ss://` — standard v2rayNG
  import, already handled generically. No new entries.
- `asl://<20 chars>` — the app's own cloud-export link. Its
  resolution endpoint was NOT identified (no real exported link
  sample), so it is documented here, NOT implemented and NOT
  registered. Pending a real `asl://` link.

## Honest limits

- No real user-exported `.asl` file or CONFIG KEY yet (round-trip
  synthetic only, with the verified key).
- No live connection tested; no real `asl://` link sample.
- NoobCrypt modes 0 (AES-256-GCM), 2 (ChaCha20) and 3
  (ChaCha20-Poly1305) nonce/tag layouts not mapped (`.asl` uses mode 1
  only).

## Files in this directory

- `asltunnel.py` — catalog + file logic (shared by both adapters)
- `server_catalog_decoder.py` — bridge entry point `run(bytes)->str`
- `file_decoder.py` — engine CLI adapter for `.asl`
- `manifest.json` — integration metadata
