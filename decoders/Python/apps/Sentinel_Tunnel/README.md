# Sentinel Tunnel 4.0.0 — SP-DECODE app decoder

- **App:** Sentinel Tunnel 4.0.0 (versionCode 64)
- **Package:** `online.zarray.sentineltunnel`
- **APK SHA-256:** `7fe89b60cd73c0f62d615e3020d6e6df1bb41f40851f372ec295e4acbcd659b4`
- **Status:** PARTIAL — files VERIFIED (synthetic round-trip), VPNGate
  catalog VERIFIED live, own-VPS catalog BLOCKED (see below).
- **Dossier:** `analysis/online.zarray.sentineltunnel/64/`

## Files

| File | Role |
| --- | --- |
| `file_decoder.py` | `.st` (STCF) file decoder. Engine contract: `run(data, password=None)`; CLI positional file + `--password`; stdin JSON credentials; exit 3 `{"workerError": "PASSWORD_REQUIRED"}` when a protected export arrives without a password. `--selftest` = 14 round-trips (7 types × with/without password) + tamper check + password-required check. |
| `server_catalog_decoder.py` | VPNGate catalog decoder. Bridge contract: `run(bytes) -> str` (VPNGate CSV bytes → catalog JSON string, no download APIs in the result, no network in `run()`). CLI takes a saved feed file only; the broker fetches the live feed. |
| `manifest.json` | App identity, targets, verification summary. |

## Catalog: two sources, one live

1. **Own VPS — BLOCKED, not delivered.** `GET https://api.zarray.online:2096/api/v2/configs/{type}`
   (9 types: version, ssh, ssl, ssl_ovpn, openvpn, ovpn_files, hy2, xray,
   dnstt) answers HTTP 401 `{"error":"unauthorized"}` on all 9 types
   (re-verified 2026-11-27: 8× 401 + 1 connection reset). The v2 API
   additionally requires an `X-Firebase-AppCheck` token (Play Integrity,
   minted on a real device running the app). No token, broker or key for
   it is invented here. Unlock needs a real App Check token from a phone
   running the app; then the analyst script
   (`sentinel_tunnel_catalog.py --appcheck-token`) downloads and decrypts
   all 9 types. No VPS key material lives in this directory.
2. **VPNGate — LIVE, this is the registered remote.** The app's own
   free-server browser (`VPNGateRepository`) fetches the public VPNGate
   feed; the broker registers that same feed:
   `GET https://www.vpngate.net/api/iphone/`, UA `SentinelTunnel/2.5`.
   98 servers on 2026-11-27 (JP 50, KR 32, TH 7, RU 3, VN 2, US 1, RO 1,
   PE 1, MM 1), 95 on a same-day re-run — the feed changes as volunteer
   servers come and go. All configs are OpenVPN in Base64. Parser fix vs
   the analyst script: numeric fields tolerate `"-"` (unmeasured Ping),
   which crashed the strict `int()` parser on the re-run feed.

## Files (.st)

STCF: magic `STCF` + v1 + JSON `ConfigExport`, XOR with the 32-byte
format key + reverse first 16 bytes of each 32-byte block. Payload
AES-256-GCM + HMAC-SHA256(`iv||ciphertext`) verified before decrypt.
No password: key = SHA-256(KEY || salt). With password:
PBKDF2-HmacSHA256(password, salt, 100000, 256-bit). The decoder ignores
`passwordHash` — verified app bug: it is PBKDF2(password, a second
random salt that is never stored), so the app itself can never open its
own password-protected exports; the data key is still correct and the
HMAC proves it.

This decoder replaces the frozen C0 route (`decoders/Python/sentinel.py`)
via a C8 override, because that decoder uses `base64(passwordHash)` as
the data key and therefore fails every password-protected `.st`. The
no-password path is identical in both. The C0 matrix is untouched.

No real `.st` sample exists yet — verification is synthetic round-trip
with realistic payloads from the app's data models. A real export is
still wanted to confirm against a genuine file.

## Texts

No own scheme (`sentinel://` does not exist). The app accepts standard
Xray links — `vless://`, `vmess://`, `trojan://`, `ss://` + raw Xray
JSON — already registered generically in SP-DECODE. No new text entries.

## Icon

`icon.png` (512×512, from `ic_launcher.webp`) — SHA-256
`4e9a4fca41322cacad9d81125f2ff01c88def7c82fb1b4ccda064e79d09e6dd6`.
Upload as `sentinel-tunnel.png` to `cloud/web/public/server-vpn-icons/`
(the icon file itself is never committed).
