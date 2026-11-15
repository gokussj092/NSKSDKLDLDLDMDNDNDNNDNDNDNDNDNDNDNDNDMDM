# PUKANG VPN — SP-DECODE

App: **PUKANG VPN**, `com.pukangvpn.th`, version **8.7** (versionCode 87,
minSdk 32). Version of Google Play (updated 10 Oct 2026), downloaded from
APKPure as XAPK (SHA-256
`854428db63b5171717a3bc6e1fd3925f6d0d8c6ebe5e2f5fa77a189d812ecc43`).

No prior coverage in the SP-DECODE repo (checked `decoders/Python/apps/`,
`analysis/` and `decoders.json` on branch `feat/nuevas-integraciones`:
no `pukang` entry). Sister app KHAM VPN (`decoders/Python/apps/KHAM_VPN/`)
uses the same method with a different key/URL; PUKANG was verified
independently against its own `libapi-pukang.so`.

## Catalog

- URL: `https://pukangvpn.xyz/pukangvpn/Config.json`
  (from `MainDetail.a()` in `libapi-pukang.so`, `.rodata` 0x4e6)
- Request (exact, as the app does it with OkHttp 5.3.2):
  `GET https://pukangvpn.xyz/pukangvpn/Config.json`
  with `User-Agent: okhttp/5.3.2` and `Accept-Encoding: identity`.
  No authentication, no query parameters, no custom headers.
- Envelope: one line of standard Base64 → **modified XXTEA**
  (delta `0x2E0BA747`, last word = plaintext length, key = the format
  key zero-padded/truncated to 16 bytes) → JSON.
  Format key (from `MainDetail.b()` in `libapi-pukang.so`, `.rodata`
  0x4d8): `pukangvpn270@`.
  The XXTEA code is `ea2.i` (decrypt) / `ea2.j` (encrypt) in the app.
- JSON: `{"Version", "Message", "Servers"[], "Networks"[],
  "setOpenVPN"}`. Server and network string fields that are Base64 in
  the catalog are decoded in place (same field lists as KHAM VPN):
  servers `ServerIP, Cloudfront, NameServer, PublicKey, ServerDNS,
  ProxyIP, Username, Password, setOpenVPN, V2Ray, UDPConfig`;
  networks `Sni, ServerDNS, Payload, SquidProxy`; top level
  `setOpenVPN`. `UDPConfig` decodes to a JSON object (obfs/auth).

## Live result (verified 2026-11-14)

- HTTP 200, 60,588 bytes → **Version 144, 17 servers, 19 networks,
  16 networks with a non-empty Payload**.
- The catalog carries **no free/premium/VIP marker** on any server
  (no `isFree`/`free` field anywhere); all 17 servers are listed
  without a free/paid distinction.
- The app compares the catalog `Version` (as a number) with the stored
  version in SharedPreferences `OnlineStatus` (key `update`,
  default `0.0`) and shows an update dialog when the catalog is newer.

## Files

- `PUKANG_VPN.py` — catalog decoder. `decode()` + `run()` + CLI:
  `--url` (live download), `--file` (saved blob), `--asset`
  (included live sample), `--self-test`, `-o`, `--summary`,
  `--decoded`. Pure Python standard library.
- `PUKANG_VPN_archivos.py` — file decoder for the profile the app
  saves: after a successful download the app writes
  `filesDir/profile.json` = `Base64(XXTEA(catalog JSON))` with the
  same key (`kt.run()` case 3, `k3.r()` = Base64 + `ea2.j`), and on
  startup it reads it back with the same envelope (`ky0.a()`:
  Base64 → `ea2.i` → JSON). Decodes such a file (also accepts a raw
  catalog blob or already-decrypted JSON); `--encode` rebuilds the
  `profile.json` envelope from a decoded catalog JSON (round-trip
  verified). No `.sks` support — the app has no `.sks` format.
- `PUKANG_VPN.png` — launcher icon, 512×512 RGBA (from the XAPK).
- `catalog_sample.b64` — the live encrypted catalog body captured
  2026-11-14 (Version 144, 60,588 bytes), used by `--self-test` /
  `--asset`.

## Text schemes / other formats

- None. The manifest declares only MAIN/LAUNCHER; there is no
  `pukangvpn://` or other custom scheme, no `ACTION_VIEW` file
  association, and no import/export of user profile files. The app is
  a v2rayNG fork: it also handles the standard `vmess://`, `vless://`,
  `ss://`, `trojan://` links and generic V2Ray subscriptions, which
  SP-DECODE already covers. `.ovpn` profiles are standard OpenVPN,
  already covered by SP-DECODE.

## Pending

- End-to-end confirmation with a real `profile.json` taken from a
  phone (the envelope is verified against the live catalog body and
  the app's own read/write code, but no real saved file was tested).
- Nothing else: the catalog method is fully closed (live verified,
  encrypt round-trip reproduces the original body byte for byte).
