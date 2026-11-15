# HAMARA TUNNEL LITE — SP-DECODE provider

App: HAMARA TUNNEL LITE, `com.hamarateam.litetunnel`, version 2.9
(versionCode 20, minSdk 24). APK source: APKPure XAPK (arm64-v8a),
SHA-256 `6fbecfdaecf3925a66e0f23917182a68910310b5cc75b1ef350e7ac62a58d817`.
No coverage of this app in the SP-DECODE repo (branch
`feat/nuevas-integraciones`, 86 provider folders) — new provider.

## Catalog — `HAMARA_TUNNEL_LITE.py`

- Download: plain GET `https://paperonboard.com/updater/d146deb8a1d4f91cc0a7bbdac230da`,
  no headers/auth (Volley request, `C3861kY.e()` returns no custom headers).
  Script sends `User-Agent: Dalvik/2.1.0` + `Accept-Encoding: identity`
  (the platform-agent family the app's stack produces); the server answers
  200 to any UA. If the plain GET is cut mid-body (the LiteSpeed host does
  this), the script resumes by `Range` requests with the same headers.
- Cipher: Base64 → modified XXTEA, delta `0x9E5729B1`, fixed key
  `...|...` (last word = plaintext length), no MAC. Byte-for-byte the
  APNA Tunnel Lite method (same delta, same key, same host family); only
  the updater token differs.
- Document: `Version`, `Free_servers`, `Premium_servers`, `Vip_servers`,
  `Private_servers`, `Payloads`, plus `UpdaterLink`, `Username`,
  `Password`, `Changelogs`. The app never fetches `UpdaterLink`
  (`https://amtun.xyz/updater/9d5eca6d963a309f5aec50398bd68c`) in this
  version; it is reported, not followed.
- Live test (2026-11-13): **Version 587, 38 free servers, 640 payloads**
  (Premium/VIP/Private 0). Bundled asset `assets/janu.json`:
  **Version 322, 23 free servers, 504 payloads**.
- Server entry fields: `server_name`, `server_host` (`;`-separated list),
  `server_port`, `server_udp_port`, `ssl_port`, `category`, `username`,
  `password`, `custom_cert`. Payload fields: `friendly_name`, `payload`,
  `sausage`, `host`, `port`, `dothost`, `message`, `method`, `category`,
  `query`, `sslws`.

Usage:

```sh
python3 HAMARA_TUNNEL_LITE.py --summary          # live download, counts only
python3 HAMARA_TUNNEL_LITE.py --url <url> -o out.json
python3 HAMARA_TUNNEL_LITE.py --input janu.json --summary   # bundled asset
python3 HAMARA_TUNNEL_LITE.py --apks app.xapk --summary     # asset from bundle
python3 HAMARA_TUNNEL_LITE.py --self-test
```

## Files — `HAMARA_TUNNEL_LITE_archivos.py`

Two importable formats (both verified from the DEX + Hamara's own
`libputils.so`):

1. **Single profile `.hamaratnl`**: one lowercase hex line =
   `hex(XOR(UTF-8 JSON, 12-byte key "4%PdXch>fkP]"))`. The key was proven
   from this APK's own `libputils.so` (xor helper @0x1466d4 loads it from
   `.rodata` 0xbfe2c; UDIV/MSUB `% 12`, EOR @0x146850) — same key as
   TRM/HX/RJC. Imported via VIEW intent (`ImportTweakActivity` →
   `OpenVPNClient`, first line only) or the in-app picker (requestCode
   1001). After decryption the app checks `tweak_password` (empty → save
   directly; else password dialog), `tweak_expiry`, `hwid_lock`,
   `block_rooted` — all AFTER decryption, not part of the key.
2. **Offline catalog-update file** (in-app picker, `ACTION_GET_CONTENT`,
   type `*/*`, requestCode 0): whole file = Base64 → XXTEA (`...|...`)
   → catalog JSON; it must contain `Version`, then the raw text is saved
   as `filesDir/janu.json`. Same envelope as the catalog script.
3. **Text `hamaratnl://`**: export shows `hamaratnl://` + hex of the
   profile; import splits the pasted text on `hamaratnl://` and decrypts
   [1] with the same XOR. NOTE: the scheme is NOT registered as an
   Android deep link in the manifest — it only works as text pasted
   inside the app. No `.sks` files (none referenced).

Usage:

```sh
python3 HAMARA_TUNNEL_LITE_archivos.py perfil.hamaratnl
python3 HAMARA_TUNNEL_LITE_archivos.py --text "hamaratnl://<hex>"
python3 HAMARA_TUNNEL_LITE_archivos.py janu.json --summary   # catalog-update file
python3 HAMARA_TUNNEL_LITE_archivos.py --self-test
```

## Files in this folder

- `HAMARA_TUNNEL_LITE.py` — catalog decoder (`decode()` + `run()` + CLI `--url`)
- `HAMARA_TUNNEL_LITE_archivos.py` — `.hamaratnl` / catalog-update / `hamaratnl://` decoder
- `HAMARA_TUNNEL_LITE.png` — 512×512 icon (resized from the XAPK `icon.png`)
- `janu.json` — bundled encrypted catalog asset (Version 322), used by `--self-test`

## Pending

- No real `.hamaratnl` file exported from a phone exists yet: the
  hex/XOR key and algorithm are proven from the app's own library and the
  round-trip self-test passes, but end-to-end confirmation with a real
  export is still pending.
- Same for a real `hamaratnl://` text and a real offline catalog-update
  file from the phone.
