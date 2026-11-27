# TunnelDOOM VPN 4.3.5 — re-analysis (build 435)

- **App:** TunnelDOOM VPN 4.3.5, versionCode 435, package `com.tunneldoom.http`
- **Source:** `TunnelDOOM_VPN_4.3.5_13_h09m.apks`, 54.4 MB,
  SHA-256 `7a8cb69b53b7faf154d83ad330e653f44319d65e4c2c4bf337907e91f37bc757`
- **Date:** 2026-11-27. **Base:** 4.3.2 / vc 432, already in the repo.
- **Result:** re-analysis, not a new method. Crypto identical; one functional
  change (catalog host).

## What changed vs 4.3.2

1. **Catalog host: `web.tunneldoom.space` → `free.tunneldoom.space`.**
   The old host is dead (2026-11-27: the connection closes with no response).
   This is the ONLY functional change. It affects two places:
   - `decoders/Python/apps/TunnelDOOM_VPN/server_catalog_decoder.py`
     (`SOURCE` constant, used by the CLI download path).
   - `cloud/web/lib/server-vpn-provider.mjs` (`tunneldoom-vpn` broker entry)
     — see `stage/_fragments/groupC/server-vpn-provider.mjs.fragment`.
2. **Crypto unchanged**, verified in the decompiled 4.3.5 source:
   - `StringCrypter.processString('d')`: Base64 → XOR with SHA-256 of
     `test_key` → strip 32 chars of hex salt. Identical.
   - `NoobPass.star()`: bytes `[117,112,49,33,5,32,44,47,15,113,38,41,107,
     54,116,115,123,49,51,48,53,42,43,36]`, XOR `QXWR`, reversed. Identical.
   - `NoobCrypt`: AES-256-CBC, IV of 16 zero bytes, PKCS7. Identical.
   - The live catalog v531 decrypts completely with the old keys: definitive
     proof the keys did not rotate.
3. **Catalog:** Version 496 → 531; servers 382 → 391.
4. **Unchanged:** `res/raw/noobdev.txt` byte-identical (SHA-256
   `e662093ebcd6523e4065166fc4732b0d2021fa36baf810c4b67197ecbb0438b4`;
   Version 3, 1 `prueba` template); signer certificate identical
   (`12704504f5711f22d78ee436f38baeb90557c2fa72c4dfb281c766f59800461d`);
   launcher icon byte-identical (SHA-256
   `ce33bc4ef6b663f43af31dc72bc32d6d7981fd4cb33bc0d89bc9b1b699187980`,
   1000×1000). No native library takes part in catalog decryption
   (Java: StringCrypter + NoobCrypt).

## Live catalog — VERIFIED_REAL

- **Source:** `GET https://free.tunneldoom.space/config.json`, plain GET,
  no custom headers, no auth, no token. Literal in
  `ConfigUpdateco.doInBackground` (4.3.5 decompile).
- **Analysis run:** HTTP 200, 643,344 bytes, SHA-256
  `6a9ac06cc9c43afb74f7ebf429b435e4eb0b0d64d0c766615d12a964f5913647`.
  Version 531, 391 servers, 1,816 non-empty encrypted fields decrypted.
  Decrypted JSON 424,147 bytes, SHA-256
  `8c9472c5208ef6d78df4ae6d55d6fbd94f7ba0aab65b0b170332cdd3f8f8f4b4`.
- **Re-run 2026-11-27 (this patch):** the catalog had already moved to
  Version **532, 390 servers** (stdout `/tmp/td-live-20261127.json`,
  SHA-256 `57ab5536abf20f929354e0888d61ffe23130695974ba6f8febf6ba12a993db23`).
  The decoder opens it with the unchanged keys. The catalog moves often;
  the version/count in the manifest is the analysis-time value.
- Servers: 391, no premium marker (all without free/premium distinction).
  Payloads: 243 servers with a non-empty `Payload`. No separate networks
  section; each server carries `sPais` and `FLAG` (57 distinct FLAGs).
  Types: 115 SSL, 152 direct, 17 inject, 7 UDP, 2 SlowDNS, 14 BHTTP,
  34 with SSL payload, 50 `isV2ray`. `V2rayConfig` (67 non-empty, all in
  clear): 19 V2Ray JSON configs, 45 `vless://` links, 2 `hysteria2://`
  links, 1 multipart payload text. `ReleaseNotes` present.
- **No encrypted values remain:** sweep of the final JSON — no long
  suspicious Base64 tokens in clear fields; `Slowchave` values are 64-char
  hex keys (32 bytes), the catalog's own clear value. One server
  (`Tigo Pack Rds WhatsApp 🇵🇦`) has an empty `ServerIP` and connects via
  SNI (`graph.whatsapp.com`); kept as-is.
- **No download API in the result JSON:** the result contains only the
  decrypted catalog data (per the owner's rule).

## Files and texts

| Format | Status | Evidence |
| --- | --- | --- |
| `.sks` | PENDING (legacy parser, carried over) | Round-trip synthetic: a GCM `.sks` and a DES `.sks` built with the Fenix recipe decrypt with `file_decoder.py`. No `.sks` literal in the 4.3.5 DEX, no own export/import UI path. Same as 4.3.2. |
| Proprietary text | None exists | DEX: only standard manual import (`menu_item_import_config_manually_{ss,http,socks,vless,vmess,trojan,hysteria2,wireguard}`) and standard V2Ray links. No TunnelDOOM prefix invented. |
| Bundled `noobdev.txt` | VERIFIED | Decrypts with the codec (Version 3, 1 `prueba` server). |
| Remote catalog | VERIFIED_REAL | Live GET 2026-11-27, twice (analysis + this patch's re-run). |

## Open items

1. Real `.sks` export from build 435 (and an active UI path): without a
   real sample the file decoder stays a legacy contract, as in 4.3.2.
2. Asset `assets/config/config/config/config/config/config/config/config/
   config/config/config/config.json` (11 `config/` levels; `config1.json`
   identical): `EncServer` (2,139 B) + `Nonce` (12 B) + `Hash` (32 B),
   AES-GCM shape. Does not open with the catalog key or the field key
   (GCM/CBC and StringCrypter tried). No DEX code references `EncServer`
   or that path (the asset reader that exists, `SkProtect`, reads
   `assets/flags/zs.png`, not this file). Possibly a dead fixture left in
   the APK. Does not block the catalog.

## HMAC audit

No HMAC observed for file/catalog integrity, transport MAC, or connection
authentication in the reviewed code paths. Catalog integrity rests on
successful AES-CBC decryption of every field; no separate MAC is checked.
