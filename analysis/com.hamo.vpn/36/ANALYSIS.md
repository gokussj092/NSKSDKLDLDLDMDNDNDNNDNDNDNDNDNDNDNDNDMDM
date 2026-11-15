# ANALYSIS — MNR TUNNEL PLUS (com.hamo.vpn, versionCode 36)

- App: **MNR TUNNEL PLUS** (`com.hamo.vpn`), version **3.6** (versionCode 36).
- Family: ISVSoft / demondevs (own tunnel protocol, Go core).
- Observed: 2026-11-14/15 (live verification 2026-11-14; dossier written 2026-11-14/15).
- Source: APKPure XAPK (owner-supplied sample); live catalog download 2026-11-14.
- Status: **PARTIAL** (see RESULTS.md for the per-route status).
- XAPK: MNR-TUNNEL-PLUS_3.6_arm64-v8a.xapk (50,517,459 B, SHA-256 e99417252757404e6ea9db4f11b10d48cfa1c498ce56034a509c80f5dc593101, matches APKPure)
- Base APK SHA-256 (on disk): `3ff36eecddfb47051cc19ba813deb154160f8558e384bf833baae1f3a77cc50e (base APK on disk; split config.arm64_v8a.apk 4e587a3fa19b1e0e8797c1b40f6e18d672ef2d2de1b13d249605e36db3669bcc)`

## 1. Objective

Document, with reproducible evidence, how the catalog, the file format and
the text/link format of this build work, so the method can be integrated
into SP-DECODE without re-doing the research — and without ever storing a
key, token, credential or real user profile in this dossier. Keys live
ONLY in the operational scripts in `~/workspace/catalogs/mnr/`
(`MNR_Tunnel_Plus.py`, `MNR_Tunnel_Plus_archivos.py`); this dossier describes the procedure, never the value.

## 2. How the sample was obtained

The XAPK came from APKPure (owner-supplied sample). Base APK + ABI splits
were extracted from the start (all native libraries live in the ABI split,
never in the base APK for these builds). The live catalog was downloaded
with the app's exact request, as implemented in the operational script;
the response was decrypted and verified as described below. No user data,
no real exported profile and no account credential was used.

## 3. Method — observation / hypothesis / verification

### Observation

- Catalog (live): live v16.6, 30 servers, 98 networks; bundled asset v13.9, 13 servers, 94 networks; 14 servers carry vless:// links; version check endpoint returns clear JSON (versionCode 35, versionName 3.5)
- Files: `.stp` (file variant G5/f) and `.sky` (cloud variant G5/h, same envelope): JSON encrypted with the F5/a.c envelope; import checks MyPass (if isPassON), ExpireDate and DeviceID (MD5-uppercase of Build data)
- Text / links: No own URI scheme for import in the manifest (only the .stp file association). The catalog's vless:// links are standard links for pasting, not an app scheme. Cloud link is mnrtunneludp:// + 10 random alphanumeric characters (Firebase Storage object code, not a system deep link).
- Cloud: Share by code: 'Uploading to cloud' generates mnrtunneludp:// + 10 random alphanumeric characters (SecureRandom) and uploads the ciphertext to Firebase Storage as <code>.sky. Downloading a .sky needs Firebase; the file script decrypts the content once obtained. No device registration on a vendor server for the catalog (public GitHub raw file).

### Method (crypto layers)

Envelope (F5/a.b / F5/a.c): 16-character carrier (each pair of characters = one byte, high nibble first) -> those bytes are Base64 text -> AES-256-CBC, key = SHA-256 of the UPPERCASE hexadecimal of the format password, IV = 16 zero bytes, PKCS7 -> JSON with Version, ReleaseNotes, UseTimer, ImportantNotes, Servers, Networks. Field cipher (F5/g.b): same structure with a U+2000..U+200F carrier (in order) and a different format constant recovered from the app (class G4/f). Encrypted fields: Servers ServerIP, ServerUser, ServerPass, v2rayurl, UdpIP, Obfs_Str, Auth_Str, chaveKey, serverNameKey, XudpProfile, XudpPublicKey; Networks Payload, SNI, ProxyIP, dnsKey, PREFIX, DNS_RESOLVER_MANUAL. The rest (Name, FLAG, ServerPort, sInfo, booleans) is clear text. File envelope uses a different format password than the catalog envelope; both passwords live only in the operational scripts, never in this dossier. Cross-check: the same live catalog decrypted with PyCryptodome and with the script's pure-Python AES is identical (0 differences), for the live and the bundled catalog.

### Deobfuscation / string recovery

No LSParanoid layer reported; classes F5/G5/vagol read directly from the decompiled DEX. All native libraries live in the config.arm64_v8a split (libgojni.so with the v2ray core, libdns.so, libskyudp.so, libhysteria2.so, libovpncli.so, libtun2socks.so); none in the base APK.

### Verification

- Operational self-tests: catalog script --self-test OK (real field vector, envelope round-trip, field round-trip, FIPS-197 AES-256 vector); files script --self-test OK (.stp envelope round-trip, clear JSON, encrypted field, separate passwords)
- Cross-checks against an independent oracle (PyCryptodome / OpenSSL /
  Unicorn emulation) are recorded in RESULTS.md and in the source
  TESTING.md. The dossier's own tests use only synthetic vectors and the
  pure-Python helpers in tools/crypto_pure.py (verified against FIPS-197
  vectors and OpenSSL 3.0.13).
- Timing: Pure-Python AES: decrypting the live catalog takes ~23 s locally (~1 min with download + double validation). That EXCEEDS the 20 s cloud-worker limit when run as-is — the method needs a fast AES path (e.g. argon2-cffi/PyCryptodome in the worker) or a higher worker cap before cloud use. Recorded here as a LIMIT, not as a pass.

## 4. Tools used, in order

1. XAPK extraction (base + ABI splits + manifest.json) and SHA-256 inventory.
2. jadx 1.5.3 — DEX decompilation (classes, manifest, intent-filters).
3. androguard 4.1.4 — DEX/APK inspection helpers (see tools/ research script).
4. Native analysis (.rodata / disassembly) of the crypto library named in
   the method section; Unicorn 2.1.4 emulation where a native KDF or gate
   had to be confirmed (Ac Tunnel, HTTP Tweak).
5. Operational scripts (`MNR_Tunnel_Plus.py`, `MNR_Tunnel_Plus_archivos.py`) — live download, decryption,
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

See MANIFEST.json `connection_authentication`. Summary: Catalog/file integrity rests on AES PKCS#7 padding, not on an HMAC. The app's own live UDP tunnel protocol (ECDH P-256 + HKDF + AES-256-GCM, markers MNR-DATA-V2 / MNR-HANDSHAKE-V2, core in libgojni.so) is AEAD, not HMAC, and was observed only in code — it is NOT part of the catalog/file method and was not verified live. Connection authentication was not researched.
