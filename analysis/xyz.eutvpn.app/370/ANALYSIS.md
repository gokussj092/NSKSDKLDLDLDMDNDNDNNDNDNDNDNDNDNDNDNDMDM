# ANALYSIS — EUT VPN (xyz.eutvpn.app, versionCode 370)

- App: **EUT VPN** (`xyz.eutvpn.app`), version **2.4.1** (versionCode 370).
- Family: own API + sza envelope (libkeys.so).
- Observed: 2026-11-14/15 (live verification 2026-11-14; dossier written 2026-11-14/15).
- Source: APKPure XAPK (owner-supplied sample); live API probes 2026-11-14 (blocking responses recorded).
- Status: **PENDING** (see RESULTS.md for the per-route status).
- XAPK: EUT-VPN_2.4.1_arm64-v8a.xapk, SHA-256 c09c15573368c83f2bb2db1041d96477e1e8806175268046c348f3628eeabc5f (matches APKPure)
- Base APK SHA-256 (on disk): `6f7fea92c5ced6cab2267e8eef9119ea0631803ee49ccbc8bef17066f17b0270 is the arm64 split on disk; base APK hash not separately recorded — see unresolved questions. (The split hash is given only to identify the file on disk; it is not a catalog input.)`

## 1. Objective

Document, with reproducible evidence, how the catalog, the file format and
the text/link format of this build work, so the method can be integrated
into SP-DECODE without re-doing the research — and without ever storing a
key, token, credential or real user profile in this dossier. Keys live
ONLY in the operational scripts in `~/workspace/catalogs/eut/`
(`EUT_VPN.py`, `EUT_VPN_archivos.py`); this dossier describes the procedure, never the value.

## 2. How the sample was obtained

The XAPK came from APKPure (owner-supplied sample). Base APK + ABI splits
were extracted from the start (all native libraries live in the ABI split,
never in the base APK for these builds). The live catalog was downloaded
with the app's exact request, as implemented in the operational script;
the response was decrypted and verified as described below. No user data,
no real exported profile and no account credential was used.

## 3. Method — observation / hypothesis / verification

### Observation

- Catalog (live): BLOCKED by Play Integrity (honest result, not a failure of the method). The catalog method is complete and verified in the APK, and the app's exact request was replicated and probed live. But the live catalog cannot be downloaded without a real Play Integrity token: POST init-session without X-Integrity-Token -> 400 missing_integrity_token; with an invented token -> 403 google_integrity_decode_failed (the server verifies the token with Google); POST get-all-resources without Bearer -> 401 Missing token; with an invented Bearer -> 401 Invalid token. The token is only produced by a real device with the app installed from Play. It is not fabricated. Real server responses are in muestras/live_probes.json (2026-11-14). Flow (no download URLs reproduced here; exact requests live in the operational script): POST init-session with getParams() + {ts: millis} -> {access_token, expires_in: 900}; POST get-all-resources with getParams() and Authorization: Bearer <access_token> -> {flag, SERVER, PAYLOAD, GAMING_APP, BLOCKED_APP, SERVER_HEALTH_STATUS, COUNTRIES}. Each resource is {version_code, version_name, changelog, created_at, data} and data is an sza blob holding a JSONArray. SERVER_HEALTH_STATUS is an object (not an array) with the same data field. Server objects carry name, type, host, country, country_name, continent, region, city, isp, code, tags, s_ip, latitude, longitude, ovpn_port, openvpn_ssl_port, ovpn_udp_port, http_port, ssl_port, v2ray_vless_port, v2ray_transport, ws_openvpn_port, allow_torrent, unmetered, r_ip, r_port, privoxy, is_vip, is_vip_max, is_private, is_gaming, publish_app_package. Encrypted with sza: server_id (integer as text) and configuration (OpenVPN configuration text, sometimes with an encrypted private key). Public-server rule (iz3.s): not vip, not vip_max, not private, not gaming, publish_app_package != PRO, type not SPECIAL nor SUPREME. Payload objects carry name, network_code, server_id, type, code, request_method, method, protocol_mode, sni_host, route_host, target_host, host_header, target_port, payload_template, v2ray_transport, v2ray_proxy_host, v2ray_proxy_port, v2ray_proxy_payload_template, resolved_host.
- Files: The app has NO own file extension and NO file intent-filter. 'Import Config — QR, File, or Cloud Code' reads a text (QR, any file, or paste) and imports it with tx8.b(): (1) eut-payload:// v1 (custom payload): eut-payload:// + Base64URL-without-padding-without-line-breaks of 0x01 || salt16 || nonce12 || AES-256-GCM(ct||tag). Key derived with PBKDF2-HmacSHA256 (120,000 iterations, 256 bits). JSON: {v: 1, exported_at, expiration, locked, type: 'custom_payload', config: {name, details, requestMethod, protocolType, protocolMode, sniHost, targetHost, targetPort, hostHeader, routeHost, websocketHandshake, websocketPreflightMethod, wsPath, v2rayTransport, v2rayProxyHost, v2rayProxyPort, v2rayProxyPayloadTemplate, payloadTemplate, rawPayloadTemplate, uuid, message}, show_advanced, country, carrier, device_id, app_version_code}. Rules: app_version_code > 370 requires a newer app; empty or expired expiration is rejected. If the GCM envelope does not open, the app falls back to the sza path. (2) sza blob (eut://, eut-settings:// or no prefix): the decrypted JSON must carry qr_expiration (yyyy-MM-dd HH:mm:ss, Asia/Manila timezone; 1111-11-11 11:11:11 = never expires). The app stores ALL keys of the JSON in its encrypted preferences. If it carries main_server_ws_host / temp_server_ws_host -> 'GCP service imported!'; if type is custom_payload -> 'Custom payload imported!'; otherwise -> 'Configuration imported!'. Export of settings builds eut-settings:// + sza.c(json).
- Text / links: `eut://` / `eut-settings://` (sza blob) and `eut-payload://` v1 (GCM envelope) — both verified with vectors and round-trips; sealing of both is implemented in the file script.
- Cloud: Cloud by code: POST payload-share/create with {blob, expiration, is_community_submission} -> {code, expiration}; GET payload-share/get?code=<code> -> {blob, expiration}. Both require a Bearer token (without one: 401 Missing token). Other endpoints under the same API prefix (all with Bearer except init-session): get-resources-version, get-resource, get-gcp-services, get-app-settings, payload-share/create, payload-share/get, server-status, re-verify-subscription, get-purchase-status, verify-purchase, vip/bind-referral, vip/synchronize-credits, vip/leaderboards. Local data NOT opened in the script: the SQLCipher resource database (table resources; the password is in the APK but SQLCipher is not stdlib); the eutwifihotspot:// scheme only opens the hotspot, it does not import configs; standard v2ray links (vmess://, vless://, trojan://, ss://) are pasted into the app and already covered generically by SP-DECODE.

### Method (crypto layers)

getParams() (NativeKeys.resolveSecurityPayload, libkeys.so): agent = the package name; android_version = SDK_INT; version_code = 370; package = FREE (default key) or PRO; ihk = sza.c(KEY, IV, hash-magic key); dt = rooted? (boolean); dn = '<BRAND> <MODEL> (API <SDK>)'; di = sza.c(device-identity key, device-identity IV, android_id); ip = sza.c(KEY, IV, device IP); env = gms; cc / cn / cct = ISO country / carrier / Wi-Fi / Mobile Data / No Connection; ds = sza.c(KEY, IV, APK signature = Signature.toCharsString()). sza.c / sza.b (defpackage/sza.java): AES-128-CBC/PKCS5Padding, key = first 16 characters of the key string (ISO-8859-1), IV = 16 bytes of the IV string. Output: Base64(ct) + ':' + Base64(iv) with Android Base64 DEFAULT (line break every 76 characters). sza.b strips the ^eut(-settings|-payload)?:// prefix before decrypting. Session: token in access_token / access_token_expires_at; init-session returns access_token + expires_in, default 900 s. Attestation is Play Integrity (nonce = SHA-256 of the params JSON). Verified: FIPS-197 AES-128 and AES-256 vectors; CBC AES-128/256 against PyCryptodome 40/40 random; sza.c/sza.b against PyCryptodome both ways (4 texts); GCM (NIST case 2 + 15 random with/without AAD) against PyCryptodome. The research probe script (work/probe_api.py) is NOT copied into this dossier because it embeds the format key constants — those live only in the operational scripts.

### Deobfuscation / string recovery

No string-obfuscation layer reported; endpoints and getParams() read from jadx output (jadx-out2/, 10,806 files, 72 minor errors). All native libraries are in the arm64 split (libCrashGuard.so, libandroidx.graphics.path.so, libbarhopper_v3.so, libconscrypt_jni.so, libdatastore_shared_counter.so, libgojni.so (xray-core), libkeys.so, libovpncli.so, libsqlcipher.so, libtoolChecker.so); none in the base APK.

### Verification

- Operational self-tests: catalog script --self-test 18/18 OK (stdlib only); files script --self-test 19/19 OK (stdlib only)
- Cross-checks against an independent oracle (PyCryptodome / OpenSSL /
  Unicorn emulation) are recorded in RESULTS.md and in the source
  TESTING.md. The dossier's own tests use only synthetic vectors and the
  pure-Python helpers in tools/crypto_pure.py (verified against FIPS-197
  vectors and OpenSSL 3.0.13).
- Timing: No timing issue recorded; the live calls are blocked before any crypto work (see catalog).

## 4. Tools used, in order

1. XAPK extraction (base + ABI splits + manifest.json) and SHA-256 inventory.
2. jadx 1.5.3 — DEX decompilation (classes, manifest, intent-filters).
3. androguard 4.1.4 — DEX/APK inspection helpers (see tools/ research script).
4. Native analysis (.rodata / disassembly) of the crypto library named in
   the method section; Unicorn 2.1.4 emulation where a native KDF or gate
   had to be confirmed (Ac Tunnel, HTTP Tweak).
5. Operational scripts (`EUT_VPN.py`, `EUT_VPN_archivos.py`) — live download, decryption,
   self-tests. They are stdlib-only Python.
6. Verification oracles: PyCryptodome 4.4.0 and argon2-cffi 25.1.0 in the
   research venv (NOT part of the operational scripts).

## 5. Remote routes — evidence without sensitive endpoints

Per the owner's rule, catalog download APIs are NOT reproduced in this
dossier (result JSONs must contain catalog data only, fully decrypted).
The exact request (method, headers, body) lives in the operational script
and in the supplied-integrations registry. What is recorded here is the
evidence: HTTP status, response size, catalog version, server/network
counts and the decryption result — see RESULTS.md. No token, no
credential-bearing URL and no API key appears in this dossier.

## 6. Real scope

- What works is stated per route in RESULTS.md (VERIFIED_REAL vs
  VERIFIED_SYNTHETIC vs PENDING / NOT_AUTHORIZED).
- A synthetic fixture proves the implemented logic, NOT compatibility with
  a real app build or live connectivity.
- Pending items (real exported files, real links, re-verification on a new
  catalog version) are listed in MANIFEST.json `limitations` and in
  RESULTS.md; they are not hidden.

## 7. Changes vs previous builds

No previous build of this package is covered by an earlier dossier in this
patch; the comparison baseline is the repo's existing coverage (if any) as
recorded in the source NOTES.md. No regression test against an older build
was possible (no older sample was supplied).

## 8. HMAC / connection-authentication audit

See MANIFEST.json `connection_authentication`. Summary: No HMAC was observed in the sza envelope (AES-CBC, no MAC) or in the eut-payload:// v1 envelope (AES-GCM tag, AEAD — not an HMAC). Connection authentication here is Play Integrity attestation + a Bearer session token verified server-side by Google/the vendor; the token exchange was observed only as blocking responses (400/401/403), never as a successful attestation, so connection authentication stays UNCONFIRMED. VPN transport authentication was not researched.
