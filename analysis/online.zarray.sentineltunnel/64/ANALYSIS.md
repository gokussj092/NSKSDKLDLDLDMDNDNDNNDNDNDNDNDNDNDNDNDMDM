# ANALYSIS — Sentinel Tunnel 4.0.0 (`online.zarray.sentineltunnel`, vc 64)

- **APK:** `Sentinel_Tunnel_4.0.0_5_ht8l.apks` (47.5 MB; base + arm64 + es + xhdpi)
- **SHA-256:** `7fe89b60cd73c0f62d615e3020d6e6df1bb41f40851f372ec295e4acbcd659b4`
- **Analysed:** 2026-11-27 (lote 15, app 5 of 8; analyst work in
  `~/workspace/batch15-work/sentinel-tunnel/`).
- **Status:** PARTIAL — files VERIFIED (synthetic), VPNGate catalog
  VERIFIED live, own-VPS catalog BLOCKED.

## 1. What the app is

Sentinel Tunnel is a user-config VPN client (SSH / SSL / OpenVPN /
DNSTT / Hysteria2 / Xray) with two server sources: its own VPS catalog
and a public VPNGate free-server browser. It exports configs as `.st`
files and imports standard Xray links. It has no proprietary URI scheme.

## 2. Own VPS catalog — BLOCKED (observed, not hypothesised)

- Endpoint (from native `libvpscrypto.so` `baseUrl()`):
  `GET https://api.zarray.online:2096/api/v2/configs/{type}`, 9 types:
  `version`, `ssh`, `ssl`, `ssl_ovpn`, `openvpn`, `ovpn_files`, `hy2`,
  `xray`, `dnstt`.
- Request signing (implemented and verified against the native code via
  the analyst's Unicorn emulator of `libvpscrypto.so`): `X-Api-Key`,
  `X-Timestamp`, `X-Nonce`, `X-Signature = HMAC-SHA256("apiKey|timestamp|nonce")`,
  `User-Agent: SentinelTunnel/1.0`. Response envelope
  `{"data": base64, "iv": base64, "v": int}` → AES-256-GCM.
- **Result, 2026-11-27:** all 9 types return HTTP 401
  `{"error":"unauthorized"}` (raw evidence in the batch work dir,
  `raw/vps_<type>.json`). Cause confirmed in code: v2 additionally
  requires `X-Firebase-AppCheck` with a Firebase App Check token (Play
  Integrity), fetched in-app via `FirebaseAppCheck.getInstance().getToken()`
  (45 s cache, 10 s timeout). Fake token, empty token and a forged JWT
  all return 401. `/api/v1/configs/version` → connection reset;
  `/api/v2/version` → 404. No debug token is embedded in the DEX.
  Firebase project: `sentinel-tunnel` (no. `17276010460`).
- Re-verified during this patch (2026-11-27, same day): 8× HTTP 401 +
  1 connection reset (egress-proxy flakiness already noted by the
  analyst). Still blocked.
- **Key material is NOT reproduced here.** The API key, HMAC key and
  AES key recovered from `libvpscrypto.so` `.rodata` live only in the
  analyst's batch work dir (never in Git, never in this dossier) and
  are not needed to serve the VPNGate remote or decode `.st` files.
- **Unlock:** a real App Check token, only mintable on a real phone
  running the app (certificate pinning blocks proxy interception).
  With it, the analyst catalog script accepts `--appcheck-token` /
  `SENTINEL_APPCHECK_TOKEN` and downloads + decrypts all 9 types.
  Nothing about the VPS catalog (version, server count) is invented:
  version unknown, 0 servers delivered.

## 3. VPNGate catalog — LIVE (the registered remote)

- Source: `VPNGateRepository` in the app — the app's own free-server
  browser fetches `GET https://www.vpngate.net/api/iphone/` (fallback
  `https://vpngate.net/api/iphone/`), UA `SentinelTunnel/2.5`.
- 2026-11-27: HTTP 200, 1,320,394 bytes, **98 servers**, all 98
  `.ovpn` configs in Base64 decode correctly. By country: JP 50, KR 32,
  TH 7, RU 3, VN 2, US 1, RO 1, PE 1, MM 1. By protocol: TCP 80, UDP 18.
  Fields per server: hostName, IP, score, ping, speed, countryLong/Short,
  numVpnSessions, uptime, totalUsers, totalTraffic, logType, operator,
  message, protocol, port, ovpnConfig.
- Same-day re-run during this patch: **95 servers** (feed is live
  volunteer data; count varies). One row carried Ping `"-"`
  (unmeasured) and crashed the analyst's strict `int()` parser — the
  staged `server_catalog_decoder.py` tolerates non-numeric numeric
  fields (default −1) and was verified against both the delivered
  98-row feed and the fresh 95-row feed.
- The broker registers this public feed as the `sentinel-tunnel`
  remote (HTTPS only, UA `SentinelTunnel/2.5`). The analyst script's
  plain-HTTP fallback exists only because this VM's egress proxy resets
  VPNGate HTTPS; it is NOT part of the broker entry.
- This matches what the app itself serves as free servers. The feed is
  VPNGate volunteer servers, not Sentinel's own VPS — the card and the
  result JSON say so; the VPS catalog stays PARTIAL.

## 4. Files (.st) — STCF, verified by round-trip

- Format: `STCF` + v1 + JSON `ConfigExport`; XOR with the 32-byte
  format key + reverse first 16 bytes of each 32-byte block.
  `ConfigExport`: version, appSignature `SENTINEL_TUNNEL_CONFIG_V1`,
  configType (7 types), name, isLocked, isPasswordProtected,
  passwordHash, salt, notes, createdAt, expiresAt,
  configData {iv, data, hmac, keySalt}.
- Payload: AES-256-GCM (IV 12 B, tag 128 b) + HMAC-SHA256(`iv||ct`)
  verified before decrypt. No password: key = SHA-256(KEY || salt).
  With password: PBKDF2-HmacSHA256(password, salt, 100000, 256-bit),
  salt = `ConfigExport.salt` = `configData.keySalt`.
- **Verified app bug:** on password-protected export the app computes
  `passwordHash` with a SECOND random salt that is never stored, so its
  own password check always fails and a protected `.st` cannot be opened
  even by the app itself. The data key is still correct, so the decoder
  ignores `passwordHash` and decrypts with the password directly (the
  HMAC proves the key).
- Verification: 14/14 round-trips (7 types × with/without password,
  payload identical) + 1-byte tamper detected (HMAC/magic fail).
  Synthetic only — no real `.st` sample exists yet.

## 5. Texts

No own scheme (`sentinel://` does not exist). The importer accepts
standard Xray links, verified in code (`W3/h.b`) and by parsing:
`vless://`, `vmess://`, `trojan://`, `ss://` + raw Xray JSON
(`outbounds[0]` → CustomXrayParams). All already registered generically
in SP-DECODE. No new text entries.

## 6. HMAC audit (evidence policy §2.2)

| Scope | Status | Evidence |
| --- | --- | --- |
| File integrity (`.st`) | **CONFIRMED** | HMAC-SHA256(key, `iv\|\|ciphertext`) stored as `configData.hmac`, verified before AES-GCM decrypt in `W3/e.a`; tamper test fails as expected. Key provenance: derived per file (SHA-256 of format key + salt, or PBKDF2 of the user password + salt). Verifier: the decoder itself. |
| Catalog integrity (VPNGate) | **NOT_OBSERVED** | The public CSV feed carries no HMAC/signature; integrity comes from HTTPS transport + per-row Base64 `.ovpn` decode. No claim made beyond that. |
| Request signing (VPS v2 API) | **CONFIRMED (signing, not connection auth)** | `X-Signature = HMAC-SHA256("apiKey\|timestamp\|nonce")` with the HMAC key from `libvpscrypto.so`; reproduced exactly by the Unicorn emulator. This authenticates the API request, not a VPN connection. Key provenance: static key in the native library (value not stored here). |
| Transport / connection authentication (OpenVPN, Hysteria2, Xray) | **NOT_OBSERVED** | No evidence was traced that any HMAC authenticates a VPN connection: the VPNGate `.ovpn` configs use standard OpenVPN certificates; the VPS hy2/xray configs are inside the blocked catalog and were never observed. The presence of HMAC in the file format and the API signer does not prove connection authentication. |

## 7. Diff: repo C0 `.st` decoder vs new app-dir decoder

- Repo `decoders/Python/sentinel.py` (167 lines, C0 matrix row 237,
  bot `config_batch_registry` "sentinel" family): same STCF magic,
  same XOR+reverse transform, same no-password key
  (SHA-256(KEY || salt)), same HMAC verify, same AES-GCM, same
  `run(data) -> str|None` interface.
- **The difference is the password path.** Repo `_derive_key`: if
  `passwordHash` is present, it uses `base64(passwordHash)` AS the data
  key. Per §4 that value is PBKDF2(password, discarded salt) and can
  never be the data key — so **every password-protected `.st` fails**
  in the repo decoder (HMAC mismatch → `None`). The new decoder
  derives PBKDF2(password, salt) and ignores `passwordHash`.
- **Decision: (b) C8 override.** The new app-dir `file_decoder.py`
  takes priority for `.st`; the C0 matrix row is untouched and the C0
  decoder stays as the frozen record. The new decoder is verified
  14/14 (vs the repo decoder, verified only against the analyst's
  synthetic no-password path by construction). The bot's
  `config_batch_registry` "sentinel" entry should point at the new
  file too (fragment provided, conditional on this decision).
- No-password files decode identically under both decoders.
