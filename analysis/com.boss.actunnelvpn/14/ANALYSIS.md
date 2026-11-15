# ANALYSIS — Ac Tunnel VPN (com.boss.actunnelvpn, versionCode 14)

- App: **Ac Tunnel VPN** (`com.boss.actunnelvpn`), version **1.4** (versionCode 14).
- Family: RENZ.
- Observed: 2026-11-14/15 (live verification 2026-11-14; dossier written 2026-11-14/15).
- Source: APKPure XAPK (owner-supplied sample); live catalog download 2026-11-14.
- Status: **VERIFIED** (see RESULTS.md for the per-route status).
- XAPK: AC TUNNEL VPN 1.4 arm64-v8a XAPK (total_size 63,030,900 B per manifest.json; SHA-256 of the XAPK file itself not recorded in TESTING.md — see unresolved questions)
- Base APK SHA-256 (on disk): `4a537ae26ec1c60dfeba02e33e2f8502cd7f5a06c75887ca2bb768685e0c0b56 (base APK on disk)`

## 1. Objective

Document, with reproducible evidence, how the catalog, the file format and
the text/link format of this build work, so the method can be integrated
into SP-DECODE without re-doing the research — and without ever storing a
key, token, credential or real user profile in this dossier. Keys live
ONLY in the operational scripts in `~/workspace/catalogs/actunnel/`
(`Ac_Tunnel.py`, `Ac_Tunnel_archivos.py`); this dossier describes the procedure, never the value.

## 2. How the sample was obtained

The XAPK came from APKPure (owner-supplied sample). Base APK + ABI splits
were extracted from the start (all native libraries live in the ABI split,
never in the base APK for these builds). The live catalog was downloaded
with the app's exact request, as implemented in the operational script;
the response was decrypted and verified as described below. No user data,
no real exported profile and no account credential was used.

## 3. Method — observation / hypothesis / verification

### Observation

- Catalog (live): live v22.242, 22 servers (12 with Username/Password), 1,227 networks (607 with Payload, 563 with SNIHost), 6,169 fields decrypted (only Version and Notes are clear text)
- Files: `.actun` (actunnelvpn:// + Base64(mode-0(JSON of one profile))), `.js` / `.rj` (full catalog blob, mode 0)
- Text / links: `actunnelvpn://` + Base64(mode-0(JSON of one profile)); same format as .actun
- Cloud: No code-based cloud share, no device registration. The 'cloud' is the catalog itself, downloaded and stored locally. Telegram channel exists but is not a config-share API.

### Method (crypto layers)

RENZ 3-mode crypto in libovpn3.so (32-bit ARM, class RenzUtils). Mode 0 (catalog body and most fields): Base64 -> AES-128-CBC(SHA-256(seed)[:16], IV) -> strip PKCS#7 -> XXTEA (delta 0x7A56D3E1, not the standard 0x9E3779B9) -> subtract 2 from each byte. Mode 1 (ServerIPHost, Payload, SNIHost, CustomV2RAYConfig, V2RayHost, PATH): Base64 -> Threefish-256 (HKDF-SHA256 key, tweak counter [block_index, 0]) -> AES-128-CBC(HKDF16, IV) -> strip PKCS#7 (the app strips trailing NULs before AES; the script tries the variants and keeps the one with valid padding). Mode 2 (Username, Password): Base64 -> XXTEA (key = first 16 B of PBKDF2-HMAC-SHA256(seed, FIXED_SALT, 100000, 32)) -> [IV 16 B][ciphertext] -> AES-256-CBC(PBKDF2, IV) -> strip PKCS#7. Seed, IV and FIXED_SALT live in libovpn3.so .rodata and are embedded only in the operational scripts, never in this dossier. The native KDF was validated by emulating libovpn3.so with Unicorn (32-bit ARM); the XXTEA delta was confirmed in the disassembly of xxtea_decrypt (total = (6 + 52/n) * delta).

### Deobfuscation / string recovery

DEX strings obfuscated with LSParanoid; 1,983/1,983 resolved with the reference tool paranoid-deobfuscator 3.0.2 (the batch-2 Python port of LSParanoid does NOT reproduce correct results and was not used).

### Verification

- Operational self-tests: catalog script --self-test 12 checks (FIPS-197 AES-128/256 vectors, XXTEA and Threefish-256 round-trips, real live-catalog field vectors for modes 0/1/2); files script --self-test 9 checks (actunnelvpn:// open, .js/.rj open, seal .actun + reopen, seal .js + reopen)
- Cross-checks against an independent oracle (PyCryptodome / OpenSSL /
  Unicorn emulation) are recorded in RESULTS.md and in the source
  TESTING.md. The dossier's own tests use only synthetic vectors and the
  pure-Python helpers in tools/crypto_pure.py (verified against FIPS-197
  vectors and OpenSSL 3.0.13).
- Timing: Live download + full decrypt ~9.5 s — inside the 20 s cloud-worker limit.

## 4. Tools used, in order

1. XAPK extraction (base + ABI splits + manifest.json) and SHA-256 inventory.
2. jadx 1.5.3 — DEX decompilation (classes, manifest, intent-filters).
3. androguard 4.1.4 — DEX/APK inspection helpers (see tools/ research script).
4. Native analysis (.rodata / disassembly) of the crypto library named in
   the method section; Unicorn 2.1.4 emulation where a native KDF or gate
   had to be confirmed (Ac Tunnel, HTTP Tweak).
5. Operational scripts (`Ac_Tunnel.py`, `Ac_Tunnel_archivos.py`) — live download, decryption,
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

See MANIFEST.json `connection_authentication`. Summary: Catalog/file integrity rests on AES PKCS#7 padding and the XXTEA length word, not on an HMAC. No HMAC was traced to a connection-authentication purpose. VPN transport and connection authentication were not researched for this build.
