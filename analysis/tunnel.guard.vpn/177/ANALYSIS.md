# TunelGuard VPN 17.7 — re-analysis (build 177)

- **App:** TunelGuard VPN 17.7, versionCode 177, package `tunnel.guard.vpn`,
  50.1 MB
- **Source:** `TunelGuard_VPN_17.7_4_yq9p.apks`, SHA-256
  `23d6366c84daca948fb515aaaccc62cef0360b26dcc8628a4fcb481c1b6a4e3f`
- **Date:** 2026-11-27. **Base:** 12.8 / vc 128, already in the repo.
- **Rebrand note:** the code is "SpeedTunnel" by tekidoer
  (`com.tekidoer.speedtunnel` / `com.tekidoer.sshbase`, ~31 app classes).
  It does NOT follow the v2rayNG/Sandok pattern (Argon2id +
  strongteam.co) of Fat/Katiba/Tx: its catalog lives in GitHub raw and
  its crypto is STGCM/TGCR1/STUC1 with keys embedded in `libfrkudp.so`.

## What changed vs 12.8

| Area | 12.8 (repo) | 17.7 (this build) |
| --- | --- | --- |
| Catalog URL | `https://raw.githubusercontent.com/eddyme23/octo/refs/heads/main/xxTG.js` | `https://raw.githubusercontent.com/guruzgh-ed/edd/refs/heads/main/tg.js` |
| Envelope version | STGCM2 only | STGCM3 (live + bundled seed); STGCM2 and TGCR1 kept as legacy |
| Catalog keys | v2 only (`c09300e6…`) | v3 `be5e019c…` (new), v2 `c09300e6…` (unchanged), v1 TGCR1 `b7d6b2f7…` (newly documented) |
| Field crypto | XOR only (listed fields) | TGCR1. → v1 decrypt; `u8:` → base64 UTF-8; XOR applied only when the result reads as clean text (deep, all string fields) |
| Download | UA `Royal Tunnel VPN/7.0`, no-redirect | Plain GET, no custom headers, follow redirects, 15 s connect / 20 s read, max 8 MB, CR/LF stripped; ETag/`If-Modified-Since` on repeat fetches; 304 = unchanged |
| Catalog version | (12.8-era) | 5.0, schema 2, config_revision 50, minimum_app_version 177 |
| `.tgv` file format | Native AES-128-CBC profile in the repo decoder | **HELD — see the .tgv decision below** |

No broker-URL change is needed: the TunelGuard catalog is not brokered
through `server-vpn-provider.mjs` (its card has `remote: null` and
decoding disabled there); the URL lives only in
`server_catalog_decoder.py`, which is updated in this patch.

## Method (verified)

- **Envelope** `STGCM<ver>.TG.<nonce_b64url>.<ct+tag_b64url>`,
  `TGCR1.<nonce_b64url>.<ct+tag_b64url>`: AES-256-GCM, nonce 12 B,
  AAD = the prefix with the trailing dot (`STGCM3.TG.` / `STGCM2.TG.` /
  `TGCR1.`). Keys are 32-byte blobs embedded obfuscated in
  `libfrkudp.so`, routines 0xdc688 (v3), 0xdc9a4 (v1), 0xdccc0 (v2):
  `out[i] = enc[i] ^ 0xa7 ^ (seed + delta_i)`, deltas cycling
  `[73,-110,-37,36,109,-74,-1]` decreasing by 1 per round. Verified by
  GCM tag against the bundled seed and the live envelope.
- **Fields** (`p64.O00oO0o` / `MainActivity.b1`): `TGCR1.` → native v1
  decrypt; `u8:` → base64 UTF-8; rest obfuscated → XOR per UTF-16 code
  unit, cycle `[30482, 14551, 22566, ~]` (involution). Applied only when
  the result is clean text: Name/Flag/Country/ServerId/SupportedModes
  stay in clear. Emoji (surrogate pairs) handled at UTF-16-unit level.
- **Obfuscated strings `wo2`:** `new wo2(new long[]{...})`, case 0:
  seed = longs[0], `java.util.Random(seed)`, each value = longs[i] XOR
  `nextLong()` (signed), bytes little-endian, 8 per long. Verified:
  `config_version`.
- **Local catalog:** JSON encrypted in SQLite `system.db`, table
  `spkmoder_table` (last row wins, class `af0`); bundled seed in
  `hh1.l1I1Il1`. Native `nDecryptConfig` (0xda900, core 0xdb5f0) also
  enforces integrity checks (package name, signature, root/tamper)
  that are not needed to reproduce the crypto offline.
- **HWID** (`hh1.getHWID`): MD5 of (Build.SERIAL + lengths of
  BOARD/PRODUCT/MODEL/MANUFACTURER/DEVICE + HARDWARE). Does not take
  part in the catalog key.

## Live catalog — VERIFIED_REAL

- **Download (class `iy0`):** plain GET, no extra headers on the first
  request, no body, follow redirects, 15 s connect / 20 s read, max
  8 MB, CR/LF stripped. Repeat fetches send `If-None-Match` (ETag) /
  `If-Modified-Since`; 304 = `__VC_UNCHANGED__`. The URL comes from the
  `url_updater` field of the decrypted catalog (or SharedPreferences
  `def` → `url_updater`).
- **Live test 2026-11-27:** HTTP 200, 991,263 bytes, STGCM3 envelope
  (nonce `loV76OIDQDchiB4r`), ETag
  `"007617173f784f12296fd6a7300cd1f451286b36fb62d906b9713101bc1be33c"`.
- **Version 5.0, schema 2, config_revision 50, minimum_app_version 177**,
  force_update false.
- **Servers: 90** — PREMIUM 85, VIP 5, **FREE 0**. Flags: us 18, fr 16,
  de 15, jp 12, za 12, ch 10, sg 2, gb 2, ma 1, fi 1, gh 1. Modes:
  hy1 16, ws 15, ssh 13, slowdns 6, hy2 6, ovpn 6, wg 6, hcr 6,
  udpcustom 6, xray_gcp 4, bhttp 3, xray 2, cf 1. With data: SSHHost 15,
  Username 40, UDPDetails 16, Hysteria2Details 2, WireGuardDetails 8,
  OpenVPNProfile 8, HcrProfile 6, BhttpHost 5.
- **Tweaks: 1,058** — 88 countries (ALL 177, SA 86, NG 66, PK 39,
  ID 30, ET 28, ZA 26, GB 25, …). With Payload: 548. With Sni 404,
  with Bug 363, with DNSHost 65, with ProxyHost 38, with Hcr* fields 3.
  ServerMode: ssh 505, ws 308, xray 70, slowdns 65, cf 55, hy1 27,
  xray_gcp 10, ovpn 8, hcr 3, udpcustom 2, hy2 2, bhttp 2, wg 1.
- **Bundled seed (`hh1`):** version 0.1, revision 2, 1 server, 1 tweak.
- **Full-decrypt verification:** 0 `TGCR1.` values left, 0 undecrypted
  CJK characters, 0 `u8:` prefixes left in the result. The result JSON
  does NOT include `url_updater` (owner rule: no download APIs).
- **Re-run 2026-11-27 (this patch):** byte-identical live envelope
  (SHA-256 `be741d89…`), same revision 50, 90 servers, 1,058 tweaks.
  The staged codec reproduces the analyst's decode exactly
  (full-document equality).

## The .tgv decision — HOLD the file update

Evidence:

- The batch-15 `.tgv` decoder (`tunelguard_archivos.py`) implements the
  **Java** `UserConfigEnvelope` format: `STUC1.<type>.<variant>.<salt>.
  <nonce>.<ct+tag>`, AES-256-GCM, K mode via HKDF-HMAC-SHA256, P mode
  via PBKDF2-HMAC-SHA256 (210,000 iterations). Self-test round-trips.
- BUT the report's own Pending §1 (verified by disassembly) states the
  real import/export path is **native**: `k64` →
  `TekProtect.nDecryptUserConfig` / `nEncryptUserConfig`
  (`libfrkudp.so` 0xe3a00), which uses **AES-128-CBC** (176-byte expanded
  key schedule from a 16-byte embedded master key, IV = the 16-byte
  salt, PKCS#7 unpadding, core 0xeb5f8) — NOT the Java AES-GCM. The Java
  class is only used for `requiresPassword()`.
- The repo's existing `file_decoder.py` / `codec.decode_profile`
  implements the **native CBC** format (Base64, IV = first 16 bytes,
  AES-128-CBC, 16-byte master key `TGV_USER_C0NF1G_`), which matches the
  native path described in the report.
- No real `.tgv` file exported by 17.7 (or any version) was available.

**Decision: HOLD.** The staged `codec.py` keeps `decode_profile`
unchanged (native CBC) and `file_decoder.py` is NOT staged. Replacing
the repo decoder with the Java GCM format would most likely break real
files. What is still needed: a real `.tgv` exported by the app, plus
the 17.7 native master-key value (the report extracted the key-schedule
routine but not the key value; the 12.8 `FILE_KEY` is assumed unchanged,
unverified for 17.7).

## Files and texts

- **`.tgv`:** only file type of the app (manifest VIEW filter
  `.*\.tgv`, file/content, mime `*/*`). Status PENDING per the decision
  above.
- **Texts/links:** no proprietary scheme (only the `*.tgv` file filter).
  Standard v2rayNG links are already covered by SP-DECODE.
- **No `.sks`.**

## HMAC audit

No HMAC observed for file/catalog integrity, transport MAC, or
connection authentication in the reviewed material. Catalog integrity
rests on AES-GCM tag verification (envelope and TGCR1 fields). The
native `nDecryptConfig` integrity checks (package name, signature,
root/tamper) are device-side guards, not a connection-authentication
HMAC.
