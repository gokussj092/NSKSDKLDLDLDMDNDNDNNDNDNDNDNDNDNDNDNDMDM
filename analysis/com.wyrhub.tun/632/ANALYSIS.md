# ANALYSIS — HTTP Tweak (com.wyrhub.tun, versionCode 632)

- App: **HTTP Tweak** (`com.wyrhub.tun`), version **1.8.17** (versionCode 632).
- Family: WyrHub / v2rayNG fork (multi-tunnel client).
- Observed: 2026-11-14/15 (live verification 2026-11-14; dossier written 2026-11-14/15).
- Source: APKPure XAPK (owner-supplied sample); live catalog download 2026-11-14.
- Status: **VERIFIED** (see RESULTS.md for the per-route status).
- XAPK: HTTP-Tweak_1.8.17_arm64-v8a.xapk (59,078,628 B, SHA-256 9cc133a5c6d2ab6ad39deaa2cfabd6f0c8387bed5236a5f6d4037d885b688779)
- Base APK SHA-256 (on disk): `da556b6f01c8ac4b3a39e1e017552cb868dd47631df31fc5c24f0ce4cbe5f239 (base APK on disk)`

## 1. Objective

Document, with reproducible evidence, how the catalog, the file format and
the text/link format of this build work, so the method can be integrated
into SP-DECODE without re-doing the research — and without ever storing a
key, token, credential or real user profile in this dossier. Keys live
ONLY in the operational scripts in `~/workspace/catalogs/httptweak/`
(`HTTP_Tweak.py`, `HTTP_Tweak_archivos.py`); this dossier describes the procedure, never the value.

## 2. How the sample was obtained

The XAPK came from APKPure (owner-supplied sample). Base APK + ABI splits
were extracted from the start (all native libraries live in the ABI split,
never in the base APK for these builds). The live catalog was downloaded
with the app's exact request, as implemented in the operational script;
the response was decrypted and verified as described below. No user data,
no real exported profile and no account credential was used.

## 3. Method — observation / hypothesis / verification

### Observation

- Catalog (live): live public catalog: 5/5 servers online (atl-global Global SSH 15%, atl-global-cf Global SSH 20%, vb-pl-1 Poland V2Ray Shadowsocks 34%, vb-pl-2 Poland V2Ray Shadowsocks 45%, vb-ca-1 Canada V2Ray Shadowsocks 29%). Public tweaks endpoint returns {} (empty). Primary source is the public JSON the app itself reads from its GitHub repo (github.public_servers field of the decrypted config); fallback is the rendered web page with the same list (types only). The rest of the API (/v1/config/*, /v1/device/register, /v1/device/subscription, /v1/auth/*, /v1/challenge) requires device registration / a user API key and is NOT used for the public catalog. The paid/subscription catalog is not accessible without an account.
- Files: `.ht` / `.hts` / `.htb`: mode 2 (the format used by config.ht and by exported files): Base64(text) -> blob: byte[0] mode = 2, byte[1:17] a 16-byte key carried inside the file (changes per file), byte[17:] ciphertext, multiple of 16 bytes. Block decryption (CBC, IV = the file key for block 0, previous ciphertext after): WyrLib's own block cipher, 12 rounds (r=11..0); each round: t = state XOR roundkey[r], u = P_r(t), state = S_r(u) (one 256-byte S-box per round). The text is a zlib stream (78 da ...) + zero padding to a multiple of 16, decompressing to the config JSON. The tables (12 round keys, 12 S-boxes, 12 permutations) are FIXED for mode 2: they derive in the native library only from the mode and the resting internal state; they do not depend on the file or its key. They were extracted from the native oracle (Unicorn emulation of libcore.so, with the anti-emulation gate neutralized) and verified against real plaintext/ciphertext. Mode 6 (v6) NOT implemented: a second format exists (byte[4]==6, 4-byte tag verified with a pure function, native guard, zlib) but there is no real sample of that format, so the decoder rejects it with 'unsupported mode' instead of inventing one.
- Text / links: Link prefix confirmed in the decrypted config: link.config_prefix = 'httptweak://'. The exact format of the payload after the prefix is NOT confirmed: there is no intent-filter for that scheme in the manifest (only App Links https://httptweak.com/app and /app/*, and the HtFileHandlerActivity file handler with content/file and */*). No scheme is included in the scripts until a real link confirms it. The app also imports .ovpn and standard v2ray links by pasting (vmess://, vless://, trojan://, ss://); those are already covered by SP-DECODE and are not HTTP Tweak's own format.
- Cloud: Share by code: web routes /app/share and /app/import/ and API /v1/config/export|import|protected_export|protected_import|convert (see decrypted config). They require a registered account/device; no live code-share was verified (pending: a real link). Per-client catalog (/configs/{key}/servers|tweaks) requires a panel API key (X-API-Key header); not available offline.

### Method (crypto layers)

The native gate (why it was hard): every native WyrLib method in libcore.so first goes through a helper that only returns 1 when a flag is 0, a guard byte is 1 and a splitmix32 hash of the guard matches. In emulation the flag stayed 0xaa and the guard 0, so everything returned NULL. The way out was twofold: patch the BL to the helper to MOV w0,#1 in emulated memory, and force the flag to 0 (the state the real app reaches at startup) before calling the decryptor; with that the full flow runs and the config opens. The JNI harness also had GetByteArrayRegion/SetByteArrayRegion (indices 200/208) swapped; without fixing that, the Base64 arrived as zeros. Detail in TESTING.md and in the earlier dossier ~/workspace/http-custom-update/spdecode/analysis/com.wyrhub.tun/632/. File verification: the script decrypts the real asset config.ht (1156 B Base64 from the APK) and the remote config.ht from GitHub (1197 B, 2026-08-08); re-encryption reproduces the real ciphertext byte for byte. Clean output (2026-11-15 rule): the result JSON carries only the configuration data, without the catalog download APIs — clean_result() removes the base, api, source and github fields when writing JSON (the CLI applies it by default). The raw config is still fully decrypted (the self-test checks on base/api verify the decryption is exact) and re-encryption uses the raw config, because that is what the app encrypts. Provenance (where config.ht was downloaded from and the remote catalog URLs) is documented in TESTING.md, not in the result JSON.

### Deobfuscation / string recovery

DEX strings obfuscated with Lr64;->e (XOR with a key byte array); resolved with work/deob_r64.py (Dalvik abstract interpretation per method, fill-array-data payloads).

### Verification

- Operational self-tests: catalog script --self-test OK (5 servers, 5 online; types ssh, v2ray_ss; public_tweaks.json responds empty); files script --self-test OK (real config.ht decrypts to valid JSON, 11 root keys, 9 after cleaning APIs; re-encryption byte-identical to the original; round-trip OK)
- Cross-checks against an independent oracle (PyCryptodome / OpenSSL /
  Unicorn emulation) are recorded in RESULTS.md and in the source
  TESTING.md. The dossier's own tests use only synthetic vectors and the
  pure-Python helpers in tools/crypto_pure.py (verified against FIPS-197
  vectors and OpenSSL 3.0.13).
- Timing: No timing issue recorded for the public catalog or .ht files.

## 4. Tools used, in order

1. XAPK extraction (base + ABI splits + manifest.json) and SHA-256 inventory.
2. jadx 1.5.3 — DEX decompilation (classes, manifest, intent-filters).
3. androguard 4.1.4 — DEX/APK inspection helpers (see tools/ research script).
4. Native analysis (.rodata / disassembly) of the crypto library named in
   the method section; Unicorn 2.1.4 emulation where a native KDF or gate
   had to be confirmed (Ac Tunnel, HTTP Tweak).
5. Operational scripts (`HTTP_Tweak.py`, `HTTP_Tweak_archivos.py`) — live download, decryption,
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

See MANIFEST.json `connection_authentication`. Summary: Mode 2 has no MAC; mode 6 (v6) has a 4-byte tag verified by a pure function (not an HMAC) and no sample exists. The mere presence of a hash helper in libcore.so proves nothing about connection authentication. VPN transport and connection authentication were not researched for this build.
