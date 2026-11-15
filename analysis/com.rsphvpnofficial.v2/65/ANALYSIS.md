# ANALYSIS — FMT VPN (com.rsphvpnofficial.v2, versionCode 65)

- App: **FMT VPN** (`com.rsphvpnofficial.v2`), version **65-16kb-page-size** (versionCode 65).
- Family: RENZ (com.tknetwork.tunnel, 'TK Network Tunnel'; fork of v2rayNG).
- Observed: 2026-11-14/15 (live verification 2026-11-14; dossier written 2026-11-14/15).
- Source: APKPure XAPK (owner-supplied sample); live catalog download 2026-11-14.
- Status: **PARTIAL** (see RESULTS.md for the per-route status).
- XAPK: FMT-VPN_65-16kb-page-size_arm64-v8a.xapk (79,270,690 B, SHA-256 38ead7c6... as recorded in TESTING.md, matches APKPure). Full XAPK hash was recorded only partially — see unresolved questions.
- Base APK SHA-256 (on disk): `362c0e24051fb4e4c11389b9c0c0a3451c308f3ebbfdc2012fa83ea0156a1fd8 (base APK on disk)`

## 1. Objective

Document, with reproducible evidence, how the catalog, the file format and
the text/link format of this build work, so the method can be integrated
into SP-DECODE without re-doing the research — and without ever storing a
key, token, credential or real user profile in this dossier. Keys live
ONLY in the operational scripts in `~/workspace/catalogs/fmt/`
(`FMT_VPN.py`, `FMT_VPN_archivos.py`); this dossier describes the procedure, never the value.

## 2. How the sample was obtained

The XAPK came from APKPure (owner-supplied sample). Base APK + ABI splits
were extracted from the start (all native libraries live in the ABI split,
never in the base APK for these builds). The live catalog was downloaded
with the app's exact request, as implemented in the operational script;
the response was decrypted and verified as described below. No user data,
no real exported profile and no account credential was used.

## 3. Method — observation / hypothesis / verification

### Observation

- Catalog (live): live v2026.181, 15 servers, 75 networks. Server types: 0 OpenVPN (5), 1 SSH (1), 2 (1), 3 VLESS (5), 4 UDP (1), 5 (1), 7 WireGuard (1). Networks: TunnelType 3 (51), 2 (10), 5 (7), 8 (2), 6 (2), 0 (2), 11 (1); payload_type ovpn 74, ssh 1; Payload present in 19/75, SNI in 68/75. Bundled fallback catalog (Tk.getConfig() native blob): v1.0, 1 server, 1 network. Kill-switch list consulted by the app (159 entries, 2026-11-14): FMT VPN is NOT on the list.
- Files: `.dtk`: UTF-8 text with a single Base64 value: Base64(AES-256-CBC(JSON)) with the same key and IV as the catalog. The clear JSON has two keys, each holding a JSON string: {"server": "<server JSON>", "network": "<network JSON>"}. On import the app re-encrypts each value and stores them as importedServer / importedNetwork. Export writes <name>.dtk with the same encryption. A legacy key (Parser.a(), for other stored values) is available in the file script via --key (value not reproduced here). No .sks decoder.
- Text / links: The app defines NO own text/URI scheme (no fmtvpn:// or similar in the manifest). Only the VIEW intent for .dtk files. The shared text is the .dtk file itself.
- Cloud: No code-based cloud share and no device registration for sharing configs. The catalog lives in a GitHub repo file and is downloaded with an embedded token. Accounts/login go through a separate auth endpoint (not part of the catalog). Firebase is present for notifications. HotshareActivity shares the VPN connection over a WiFi hotspot (proxy + tether), not cloud config sharing. The native library has an is_authorized anti-tamper check: on failure the JNI getters return an empty string; its exact check was not reversed and is not needed to read the catalog (values are read directly from .rodata).

### Method (crypto layers)

Catalog (same as AESHelper.decrypt): Base64 -> bytes -> AES-256-CBC, key = SHA-256 of the format key, IV = 16 zero bytes, PKCS#7 -> JSON with Version, Servers[], Networks[] (plus Username, Password, Notes, color_type, contactSupport, config_url, account_api, AdvanceSettings). The result JSON written by the script is CLEAN per the 2026-11-15 rule: config_url and account_api are removed (they are catalog/account APIs), no *_raw fields with the original Base64 are emitted, and unresolvable values are reported on stderr. Second layer, CJK substitution: the sensitive catalog fields (ServerIPHost, ServerCloudFrontHost, ServerHTTPHost, ServerUser, ServerPass, vaddress, vhost, etServerAddress, etEndpoint, etPublicKey, etPrivateKey, etPreSharedKey, etAllowedIPs, SNIHost, Payload, Squid, vsni) are themselves Base64 of the same AES-256-CBC with the same key and IV, and their plaintext carries a substitution of 25 CJK/hangul/kana characters for ASCII letters and digits (table _UNOBFUSCATE in the operational script; verified by alignment against known templates over hundreds of occurrences, including complete vless:// links and a full WireGuard config). PENDING: the character U+65E5 appears 5 times and its value could not be fixed (one character of a WireGuard public key in Base64, one Fastly host, one Squid host); the script passes it through as-is and warns on stderr. The Base64 value repeated in the vaddress/vhost/et* fields decrypts to an empty string: it is the encrypted empty-field marker, not a real value. Decryption verified twice (PyCryptodome and the script's pure-Python AES, byte-identical result). Catalog and keys live in the native libboyapper.so (arm64 split, not the base) and are read via JNI (Tk.getUrl/getConfig/getGitOwner/getGitRepo/getGitToken, UtilsKey.getSecretKey). Classes are not obfuscated; strings use two layers (StringFog and com.panda912.muddy.ObfuscatedString, java.util.Random seeded by the first long).

### Deobfuscation / string recovery

StringFog + Muddy ObfuscatedString (java.util.Random with the seed in the first long). No LSParanoid layer reported.

### Verification

- Operational self-tests: catalog script --self-test 12/12 OK (AES vector verified with PyCryptodome, test blob, CJK substitution on known cases, derived key; + 4 checks added 2026-11-15: all server fields open, the empty marker encrypts '' and decrypts '', cleaning drops APIs and *_raw, U+65E5 passes through and is flagged); files script --self-test 5/5 OK (included vector opens; seal and reopen; the legacy key does not open the vector)
- Cross-checks against an independent oracle (PyCryptodome / OpenSSL /
  Unicorn emulation) are recorded in RESULTS.md and in the source
  TESTING.md. The dossier's own tests use only synthetic vectors and the
  pure-Python helpers in tools/crypto_pure.py (verified against FIPS-197
  vectors and OpenSSL 3.0.13).
- Timing: Download ~0.9 s, catalog decrypt ~6.3 s (pure-Python AES), total ~9 s — under the 20 s cloud-worker limit.

## 4. Tools used, in order

1. XAPK extraction (base + ABI splits + manifest.json) and SHA-256 inventory.
2. jadx 1.5.3 — DEX decompilation (classes, manifest, intent-filters).
3. androguard 4.1.4 — DEX/APK inspection helpers (see tools/ research script).
4. Native analysis (.rodata / disassembly) of the crypto library named in
   the method section; Unicorn 2.1.4 emulation where a native KDF or gate
   had to be confirmed (Ac Tunnel, HTTP Tweak).
5. Operational scripts (`FMT_VPN.py`, `FMT_VPN_archivos.py`) — live download, decryption,
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

See MANIFEST.json `connection_authentication`. Summary: Catalog/file integrity rests on AES PKCS#7 padding, not on an HMAC. The native is_authorized anti-tamper check is not an HMAC and its exact check was not reversed. VPN transport and connection authentication were not researched for this build.
