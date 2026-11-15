# RESULTS — EUT VPN (xyz.eutvpn.app, versionCode 370)

Observed 2026-11-14/15. Environment for the dossier tests: Python 3.12.3 on this
VM (Linux x86_64), OpenSSL 3.0.13 as oracle, no network, no secrets.

## 1. Status per route

- **catalog**: PENDING — PENDING (NOT_AUTHORIZED): live download is blocked by Play Integrity — 400 missing_integrity_token without a token, 403 google_integrity_decode_failed with an invented token, 401 on get-all-resources without a valid Bearer. No live catalog data exists; nothing was invented. Requires an access_token from a session started on a real device with the Play-installed app; with that token the operational script downloads and decrypts the full catalog unchanged.
- **files**: VERIFIED — VERIFIED_SYNTHETIC: sza blob and eut-payload:// v1 sealing/opening verified with vectors and round-trips and against PyCryptodome as oracle; samples are synthetic (muestras/sample_settings.eut, muestras/sample_payload.txt). No real exported blob yet.
- **text**: VERIFIED — VERIFIED_SYNTHETIC: eut://, eut-settings:// and eut-payload:// v1 verified by construction and round-trip; no real link exported by the app yet.
- **export**: PENDING — PENDING: real catalog (needs a real device token), a real exported blob/link, a real cloud code, and opening the local SQLCipher database (needs sqlcipher, not stdlib).

Labels used here: VERIFIED_REAL = verified with a real live download or a
real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector or a
file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have (Play Integrity /
account); NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Live evidence (from the source TESTING.md, 2026-11-14)

- Catalog: BLOCKED by Play Integrity (honest result, not a failure of the method). The catalog method is complete and verified in the APK, and the app's exact request was replicated and probed live. But the live catalog cannot be downloaded without a real Play Integrity token: POST init-session without X-Integrity-Token -> 400 missing_integrity_token; with an invented token -> 403 google_integrity_decode_failed (the server verifies the token with Google); POST get-all-resources without Bearer -> 401 Missing token; with an invented Bearer -> 401 Invalid token. The token is only produced by a real device with the app installed from Play. It is not fabricated. Real server responses are in muestras/live_probes.json (2026-11-14). Flow (no download URLs reproduced here; exact requests live in the operational script): POST init-session with getParams() + {ts: millis} -> {access_token, expires_in: 900}; POST get-all-resources with getParams() and Authorization: Bearer <access_token> -> {flag, SERVER, PAYLOAD, GAMING_APP, BLOCKED_APP, SERVER_HEALTH_STATUS, COUNTRIES}. Each resource is {version_code, version_name, changelog, created_at, data} and data is an sza blob holding a JSONArray. SERVER_HEALTH_STATUS is an object (not an array) with the same data field. Server objects carry name, type, host, country, country_name, continent, region, city, isp, code, tags, s_ip, latitude, longitude, ovpn_port, openvpn_ssl_port, ovpn_udp_port, http_port, ssl_port, v2ray_vless_port, v2ray_transport, ws_openvpn_port, allow_torrent, unmetered, r_ip, r_port, privoxy, is_vip, is_vip_max, is_private, is_gaming, publish_app_package. Encrypted with sza: server_id (integer as text) and configuration (OpenVPN configuration text, sometimes with an encrypted private key). Public-server rule (iz3.s): not vip, not vip_max, not private, not gaming, publish_app_package != PRO, type not SPECIAL nor SUPREME. Payload objects carry name, network_code, server_id, type, code, request_method, method, protocol_mode, sni_host, route_host, target_host, host_header, target_port, payload_template, v2ray_transport, v2ray_proxy_host, v2ray_proxy_port, v2ray_proxy_payload_template, resolved_host.
- Operational self-tests: catalog script --self-test 18/18 OK (stdlib only); files script --self-test 19/19 OK (stdlib only)
- Timing: No timing issue recorded; the live calls are blocked before any crypto work (see catalog).

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 6 tests in 1.508s
- `python3 tools/verify.py`: exit 0
```
PASS sza round-trip (AES-128-CBC, key=first 16 chars, Base64(ct):Base64(iv))
PASS sza output uses Android Base64.DEFAULT 76-char wrap
PASS eut-payload:// v1 round-trip (PBKDF2-HMAC-SHA256 120k + AES-256-GCM)
PASS negative: tampered payload rejected
PASS negative: wrong version byte rejected
VERIFY OK
```

## 4. Fixture hashes (synthetic fixtures only)

- `payload_synthetic.json`: SHA-256 `b23b702f5bb7bb8a30082fbdeb59efe6dd8a4598a7eafd64aceb3d98daa970bf`
- `settings_synthetic.json`: SHA-256 `c019e5628f188baa3f14b7608bf37c7108c9bcee894fd22475c1e2b3674f9874`

No fixture contains a real credential, a real server with keys, or a real
user profile. All values are synthetic (TEST-NET addresses 198.51.100.0/24
and `TEST ...` names).

## 5. Independent-oracle checks

- Pure-Python AES in tools/crypto_pure.py: FIPS-197 AES-128 vector
  (key 000102...0f, plaintext 001122...ff -> 69c4e0d86a7b0430d8cdb78070b4c55a)
  and AES-256 vector (-> 8ea2b7ca516745bfeafc49904b496089); AES-CBC
  cross-checked against OpenSSL 3.0.13 in both directions; bad padding and
  a tampered GCM tag are rejected.
- XXTEA (deltas 0x9E3779B9, 0x85A92C1F, 0x7A56D3E1) and Threefish-256:
  encrypt/decrypt round-trips verified.
- The operational scripts were additionally verified against PyCryptodome
  4.4.0 during the research (see source TESTING.md); that oracle is not
  used by the dossier tests.

## 6. Pending (honest)

- Real live catalog: needs an access_token from a session started on a real device with the Play-installed app (Play Integrity). With that token, the operational script downloads and decrypts the full catalog without further changes.
- Real file exported by the app (an eut:// / eut-settings:// / eut-payload:// generated by the app, or a text file imported by it) to confirm the format end to end.
- Real cloud code (payload-share/get) to verify the code download with a real token.
- Local SQLCipher database: open it with sqlcipher (not stdlib) and confirm the stored data matches the server data.
- Re-verify when the app version rises (import rejects app_version_code > 370 and the server may change the catalog).
