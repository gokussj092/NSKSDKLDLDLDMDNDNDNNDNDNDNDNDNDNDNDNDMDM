# ANALYSIS — ZIVPN Tunnel (com.zi.zivpn, versionCode 184)

- App: **ZIVPN Tunnel** (`com.zi.zivpn`), version **2.2.5** (versionCode 184).
- Family: Psiphon / own LF1 envelope.
- Observed: 2026-11-14/15 (live verification 2026-11-14; dossier written 2026-11-14/15).
- Source: APKPure XAPK (owner-supplied sample); live catalog download 2026-11-14.
- Status: **PARTIAL** (see RESULTS.md for the per-route status).
- XAPK: ZIVPN 2.2.5 arm64-v8a XAPK, SHA-256 ae6cdb7e... (partial hash as recorded in TESTING.md; verified against APKPure). Full XAPK hash was not recorded — see unresolved questions.
- Base APK SHA-256 (on disk): `f3e973b2bb21025426888a1662631cc4f27f48907f849f753f10c1ed14507f97 (base APK on disk)`

## 1. Objective

Document, with reproducible evidence, how the catalog, the file format and
the text/link format of this build work, so the method can be integrated
into SP-DECODE without re-doing the research — and without ever storing a
key, token, credential or real user profile in this dossier. Keys live
ONLY in the operational scripts in `~/workspace/catalogs/zivpn/`
(`ZIVPN.py`, `ZIVPN_archivos.py`); this dossier describes the procedure, never the value.

## 2. How the sample was obtained

The XAPK came from APKPure (owner-supplied sample). Base APK + ABI splits
were extracted from the start (all native libraries live in the ABI split,
never in the base APK for these builds). The live catalog was downloaded
with the app's exact request, as implemented in the operational script;
the response was decrypted and verified as described below. No user data,
no real exported profile and no account credential was used.

## 3. Method — observation / hypothesis / verification

### Observation

- Catalog (live): live: JSON of 971 B with a single key -> Base64 of 704 B -> decrypted XML of java.util.Properties: tunnelType 4 = psiphontunnel, local SSH port 1080, file.appVersionCode 24. There is no server list or HTTP payload list in this endpoint: the 'catalog' is one remote configuration the app stores as remote_<name>. Bundled Psiphon servers live in assets zifile (225 servers) and zifile2 (41 servers) — hex of concatenated JSON documents, not a downloadable catalog.
- Files: `.ziv`: Base64(salt) '.' Base64(iv) '.' Base64(ct+tag). Outer LF1 layer (library 'secure', BouncyCastle): random 32 B salt, random 12 B iv, AES key = PBKDF2-HMAC-SHA256(password, salt, 1000 iterations, 16 B), AES-128-GCM without AAD. Inner layer: DES/ECB/PKCS5Padding, 8 B DESKeySpec. Interior: XML of java.util.Properties with ~50 keys (tunnelType, sshServer, udpserver, proxyPayload, sniHost, psiprotocol, v2rayprofile, file.appVersionCode, file.askLogin, file.askHwid, file.hwids, alpha, beta, gamma, ...). Tunnel types: 1 sshProxy, 2 sshSslTunnel, 3 udptunnel, 4 psiphontunnel, 5 v2raytunnel, 6 litevpntunnel, 7 sshDirect. REAL ASYMMETRY in 2.2.5: export (Lq1/a::a) encrypts with LF1 only; import (Lq1/a::c) applies LF1 and then DES. A file exported by the app itself does not pass its own import DES step. open_ziv() retries without DES when DES fails; seal_ziv() can seal in both styles (--legacy = import format, --export-style = as the app exports).
- Text / links: No own URI scheme (zivpn:// does not exist; the manifest declares no scheme). Import is by file (VIEW .*\.ziv) or by pasting a link (Dropbox/Google Drive normalized to direct download). Standard V2Ray links (vmess://, vless://, trojan://, ss://) are generic and already covered by SP-DECODE.
- Cloud: Remote config (profiles.json, verified live). RestoreAccess (rewards flow): POST with {appUserId, username} and an Authorization header to a per-server host — NOT verified live (needs a real account/credentials). Share-by-code / device registration: no share-by-code endpoint found in the APK; device registration is the rewards flow above (pending live capture).

### Method (crypto layers)

Catalog value cipher (com.zi.common.a::a(String, String)): AES-256-CBC, key = SHA-256 of the app key, IV = 16 zero bytes, PKCS5Padding. .ziv outer layer verified in bytecode: Lx1/b (iterations 1000, digest SHA-256, salt 32, key 128 bits, AES enum) and the SHA-256 H constants in LJ2/c::reset. Verified against PyCryptodome as oracle: AES-128-GCM (PBKDF2-SHA256 key) identical both ways; DES-ECB identical both ways, FIPS 46-3 vector 133457799BBCDFF1/0123456789ABCDEF -> 85E813540F0AB405; AES-128 and AES-256 block identical; FIPS-197 AES-128 vector verified. Note: during development the pure-Python AES decryption applied InvMixColumns before AddRoundKey; it was fixed (AddRoundKey first) and re-verified against the oracle for AES-128 and AES-256.

### Deobfuscation / string recovery

No string-obfuscation layer reported; classes read from the decompiled DEX (classes.dex .. classes5.dex). Native libraries are in the arm64 split.

### Verification

- Operational self-tests: catalog script --self-test OK (1 configuration, Global UDP, Psiphon); files script --self-test OK (DES/AES vectors, golden .ziv, round-trips, XML, zifile)
- Cross-checks against an independent oracle (PyCryptodome / OpenSSL /
  Unicorn emulation) are recorded in RESULTS.md and in the source
  TESTING.md. The dossier's own tests use only synthetic vectors and the
  pure-Python helpers in tools/crypto_pure.py (verified against FIPS-197
  vectors and OpenSSL 3.0.13).
- Timing: No timing issue recorded; GCM/PBKDF2 work is small (single config / single file).

## 4. Tools used, in order

1. XAPK extraction (base + ABI splits + manifest.json) and SHA-256 inventory.
2. jadx 1.5.3 — DEX decompilation (classes, manifest, intent-filters).
3. androguard 4.1.4 — DEX/APK inspection helpers (see tools/ research script).
4. Native analysis (.rodata / disassembly) of the crypto library named in
   the method section; Unicorn 2.1.4 emulation where a native KDF or gate
   had to be confirmed (Ac Tunnel, HTTP Tweak).
5. Operational scripts (`ZIVPN.py`, `ZIVPN_archivos.py`) — live download, decryption,
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

See MANIFEST.json `connection_authentication`. Summary: Integrity in .ziv is provided by the AES-GCM tag (AEAD), not by an HMAC; the catalog value has no MAC (AES-CBC + XML parse). No HMAC was traced to a connection-authentication purpose. The RestoreAccess Authorization header was not observed live, so connection authentication stays UNCONFIRMED.
