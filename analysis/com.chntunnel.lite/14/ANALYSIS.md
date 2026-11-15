# ANALYSIS — CHN TUNNEL LITE (com.chntunnel.lite, versionCode 14)

- App: **CHN TUNNEL LITE** (`com.chntunnel.lite`), version **1.4** (versionCode 14).
- Family: RENZ.
- Observed: 2026-11-14/15 (live verification 2026-11-14; dossier written 2026-11-14/15).
- Source: APKPure XAPK (owner-supplied sample); live catalog download 2026-11-14.
- Status: **VERIFIED** (see RESULTS.md for the per-route status).
- XAPK: CHN-TUNNEL-LITE_1.4_arm64-v8a.xapk (57,684,825 B, SHA-256 21e3061f5be4467f046eba04ef81e8a09e704a19f65e0300bdb55c026364d5ef, matches APKPure)
- Base APK SHA-256 (on disk): `f1ecc3a6fa6e54544f6adad4be8a9b36fa69f646ded373641a962b3c601f510b (base APK on disk)`

## 1. Objective

Document, with reproducible evidence, how the catalog, the file format and
the text/link format of this build work, so the method can be integrated
into SP-DECODE without re-doing the research — and without ever storing a
key, token, credential or real user profile in this dossier. Keys live
ONLY in the operational scripts in `~/workspace/catalogs/chn/`
(`CHN_Tunnel_Lite.py`, `CHN_Tunnel_Lite_archivos.py`); this dossier describes the procedure, never the value.

## 2. How the sample was obtained

The XAPK came from APKPure (owner-supplied sample). Base APK + ABI splits
were extracted from the start (all native libraries live in the ABI split,
never in the base APK for these builds). The live catalog was downloaded
with the app's exact request, as implemented in the operational script;
the response was decrypted and verified as described below. No user data,
no real exported profile and no account credential was used.

## 3. Method — observation / hypothesis / verification

### Observation

- Catalog (live): live v1.49, 5 servers, 44 networks, 12 distinct payloads, 23 distinct SNI (two live downloads, byte-identical body)
- Files: `.js` / `.rj` (mode-0 catalog blob), `custom_payload.json` (mode-0 JSONArray of imported networks), `classes.dex` zip with `a.rlb`
- Text / links: `chntunnellite://` + mode-0 ciphertext of a single Network JSON object (paste-only; no intent-filter in the manifest)
- Cloud: No code-based cloud share, no device registration. Only cloud service is the catalog download. Firebase only for push (FCM).

### Method (crypto layers)

RENZ 3-mode crypto in libovpn3.so (JNI RenzUtils.decrypt). Mode 0: Base64 -> AES-128-CBC (key = SHA-256 of the seed, fixed IV) -> XXTEA variant delta 0x85A92C1F, negated sums, last word = plaintext length. Mode 1: Base64 -> Threefish-256 blocks of 32 B (key = HKDF-SHA256 of salt+seed, tweak (i, 192*i)) -> strip trailing NULs -> AES-128-CBC (16 B HKDF key, same IV). Mode 2: invisible characters (ZWSP=0, ZWNJ=1; ZWJ ignored; 8 tokens = 1 byte, adjacent-bit swap, XOR 0x5A) -> XXTEA (key = first 16 B of PBKDF2-HmacSHA256(seed, salt, 100000)) -> IV (16 B) + AES-256-CBC (full PBKDF2 key). Seed, salt and IV live in libovpn3.so .rodata and are embedded only in the operational scripts, never in this dossier.

### Deobfuscation / string recovery

LSParanoid-style strings via vq.a/t0.L, reimplemented in pure Python from Dalvik disassembly (work/decode_vq.py); 1,854 call sites decoded.

### Verification

- Operational self-tests: catalog script --self-test 15/15; files script --self-test 14/14
- Cross-checks against an independent oracle (PyCryptodome / OpenSSL /
  Unicorn emulation) are recorded in RESULTS.md and in the source
  TESTING.md. The dossier's own tests use only synthetic vectors and the
  pure-Python helpers in tools/crypto_pure.py (verified against FIPS-197
  vectors and OpenSSL 3.0.13).
- Timing: Live catalog download + full decrypt inside the 20 s cloud-worker budget (exact seconds not recorded; no timeout issue reported).

## 4. Tools used, in order

1. XAPK extraction (base + ABI splits + manifest.json) and SHA-256 inventory.
2. jadx 1.5.3 — DEX decompilation (classes, manifest, intent-filters).
3. androguard 4.1.4 — DEX/APK inspection helpers (see tools/ research script).
4. Native analysis (.rodata / disassembly) of the crypto library named in
   the method section; Unicorn 2.1.4 emulation where a native KDF or gate
   had to be confirmed (Ac Tunnel, HTTP Tweak).
5. Operational scripts (`CHN_Tunnel_Lite.py`, `CHN_Tunnel_Lite_archivos.py`) — live download, decryption,
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

See MANIFEST.json `connection_authentication`. Summary: Catalog/file integrity rests on the XXTEA length word and AES PKCS#7 padding, not on an HMAC. No HMAC library call was traced to a connection-authentication purpose. VPN transport and connection authentication were not researched for this build.
