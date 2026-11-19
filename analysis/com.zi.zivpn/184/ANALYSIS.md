# ANALYSIS — ZIVPN Tunnel (com.zi.zivpn, versionCode 184) — OFFLINE app

- App: **ZIVPN Tunnel** (`com.zi.zivpn`), version **2.2.5** (versionCode 184).
- Family: Psiphon / own LF1 envelope.
- Observed: 2026-11-18/19 (Play listing verified 2026-11-19 00:11 UTC;
  implementation + host verification 2026-11-18/19).
- Source: Google Play listing via AppBrain mirror; server-side reference
  decoders and the 2026-11-14/15 dossier from the online branch (read-only);
  synthetic fixtures sealed by this dossier's oracle.
- Status: **PARTIAL** (see RESULTS.md for the per-route status).
- Scope of THIS dossier: the **offline** Android app only — `.ziv` files
  and `zivpn://` text. The remote catalog is OUT OF SCOPE (no catalog is
  added to the offline app); the server-side catalog decoder (`ZIVPN.py`)
  stays online-branch only.

## 1. Objective

Implement, with reproducible evidence, the `.ziv` file decoder and the
`zivpn://` text decoder in the OFFLINE native engine (`liboffdecode`),
so the offline app opens ZIVPN configs without any network — and without
ever storing a key, token, credential or real user profile in this
dossier. Method constants live ONLY as code constants in the production
decoder and the test oracle, as they already do in the repo's reference
decoders; this dossier describes the procedure, never the value.

## 2. How the version was confirmed

The Play listing was checked on 2026-11-19 00:11 UTC (AppBrain mirror of
the Google Play page, fetched as page text): ZIVPN Tunnel (SSH/DNS/UDP)
VPN by ZI Applications, latest version **2.2.5**, last update
**2026-10-26**, 1,000,000+ installs, 49.00 MB, Android 7.0+. That is the
same version the 2026-11-14/15 dossier covers (2.2.5 / 184), so no format
change is indicated and **no APK was downloaded** for this work. No real
`.ziv` file and no real `zivpn://` link was supplied.

## 3. Method — observation / hypothesis / verification

### Observation

- Files: `.ziv`: Base64(salt) '.' Base64(iv) '.' Base64(ct+tag). Outer LF1
  layer: random 32 B salt, random 12 B iv, AES key =
  PBKDF2-HMAC-SHA256(password, salt, 1000 iterations, 16 B), AES-128-GCM
  without AAD. Inner layer: DES/ECB/PKCS5Padding, DESKeySpec of 11 bytes
  (first 8 used). Interior: XML of java.util.Properties with ~50 keys
  (tunnelType, sshServer, udpserver, proxyPayload, sniHost, psiprotocol,
  v2rayprofile, file.appVersionCode, file.askLogin, file.askHwid,
  file.hwids, alpha, beta, gamma, ...). Tunnel types: 1 sshProxy,
  2 sshSslTunnel, 3 udptunnel, 4 psiphontunnel, 5 v2raytunnel,
  6 litevpntunnel, 7 sshDirect. REAL ASYMMETRY in 2.2.5: export encrypts
  with LF1 only; import applies LF1 and then DES. A file exported by the
  app itself does not pass its own import DES step. The native decoder
  therefore tries DES first and falls back to the raw inner bytes.
- Two LF1 password candidates are tried (GCM authentication decides):
  the current fixed password from the reference, then the legacy password
  kept by `decoders/Python/ziv.py`. Only these two known passwords are
  ever tried; there is no guessing between unrelated formats.
- Text / links: `zivpn://` + Base64(AES-256-CBC(key = SHA-256 of the text
  password, IV = 16 zero bytes, PKCS7) of the Properties XML (or JSON)
  plaintext). Provenance warning: this scheme comes from the legacy text
  handlers (66.py lineage, `text_legacy_protocols.py::decode_zivpn`); the
  2026-11-14/15 dossier found **no own URI scheme in the APK manifest**
  (import is by file or by pasting a cloud-drive link). No real `zivpn://`
  link has been observed, so the text route is synthetic-verified only.
- What the offline branch already had (and what was wrong): the legacy
  Kotlin `ZivPort` (`src/main/java/.../parity/ZivPort.kt`) decodes the
  LF1/GCM layer only — it has **no DES inner layer**, so every legacy
  (DES-layered) `.ziv` fails there (the GCM output is DES ciphertext,
  not UTF-8 XML). It is NOT compiled into the offline APK (the offline
  build uses `src/offlineNative` + JNI only), so it was left untouched;
  the native decoder is the offline implementation. The Kotlin
  `TextProtocolDecoder` already handled `zivpn://` (synthetic test only);
  it is likewise not part of the offline APK. The offline APK's text
  route is `MainActivity.beginText` → JNI `decodeNative`.

### Method (crypto layers)

- `.ziv` outer: PBKDF2-HMAC-SHA256, 1000 iterations, 16 B key;
  AES-128-GCM auth-decrypt, 12 B nonce, 16 B tag, no AAD.
- `.ziv` inner: DES/ECB, PKCS5 unpad, first 8 bytes of the DESKeySpec.
- `zivpn://`: SHA-256 of the text password (32 B key), AES-256-CBC,
  zero IV, strict PKCS7 unpad.
- Output: the Properties entries as a flat JSON object (all entries,
  unfiltered — no label mapping, no dropped `0`/empty values), or the
  decoded JSON itself for `zivpn://` JSON plaintext, or
  `{"decodedText": ...}` for other plaintext. `MainActivity` requires
  the native output to parse as JSON; that is why the text decoder
  wraps non-JSON plaintext instead of returning it raw.

### Verification

- Cross-checks against the independent online references:
  `tools/zivpn_reference.py` (PyCryptodome oracle) reproduces the
  online reference's frozen golden `.ziv` **byte-for-byte** and opens
  its fixtures identically; it decodes `zivpn://` tokens identically to
  `text_legacy_protocols.decode_zivpn`.
- Host harness (`tools/host_zivpn_test.cpp`, production
  `spdecode_zivpn.cpp` compiled unchanged, `-Wall -Wextra -Werror`):
  21/21 checks against Mbed TLS 3.6.7 (the Android pin) and 21/21
  against Mbed TLS 2.28.8 (the CI host-parity line, built with
  `-Wno-error=deprecated-declarations` — see RESULTS.md §4 for the
  pre-existing `sha256()` deprecation warning), including FIPS
  46-3 DES and FIPS 197 AES-128 known answers.
- Repo parity (`tests/test_offline_zivpn_native_parity.py` via
  `tests/native_zivpn_cli.cpp`): 13/13 tests on both Mbed TLS lines,
  with fixtures sealed by the independent PyCryptodome oracle.
- Dossier tests (`tests/test_method.py` + `tools/verify.py`): 9/9
  unittest tests, including the OpenSSL FIPS oracle checks.
- A real `.ziv` exported by the app (2,778 B, export-style LF1-only)
  now opens in the native decoder and the oracle (47 properties, full
  agreement); its `file.msg` emoji exposed the surrogate-pair issue,
  fixed in `xmlUnescape` and in the oracle (RESULTS.md §9).
- NOT verified: the Gradle/Android build (no SDK/NDK in this VM), an
  emulator/device run, a real `zivpn://` link.
  The Gradle build is covered by the `offline-native-apk` CI workflow
  (new `zivpn-cpp-parity` job added; the APK `build` job needs it).

## 4. Tools used, in order

1. Play listing check (browser search + AppBrain page text fetch).
2. Read of the online reference decoders and dossier (read-only).
3. Dossier oracle `tools/zivpn_reference.py` (PyCryptodome 4.5.0).
4. Fixture generator `tools/make_fixtures.py` (fixed salt/iv).
5. Production decoder `android/app/src/main/cpp/spdecode_zivpn.cpp`
   (Mbed TLS 3.6.7 / 2.28.8, nlohmann json 3.11.3).
6. Host harness `tools/host_zivpn_test.cpp` +
   `tools/build_host_harness.sh` (pinned downloads, SHA-256 verified).
7. Repo parity CLI + differential test (same pattern as Dark Tunnel).
8. Verification oracles: PyCryptodome 4.5.0 and OpenSSL 3.0.13
   (FIPS vectors; DES via the legacy provider).

## 5. Remote routes — none

The offline decoders make no network calls. No download endpoint is
reproduced in this dossier. The remote catalog (`profiles.json`) is out
of scope; see the 2026-11-14/15 dossier for its live evidence.

## 6. Real scope

- What works is stated per route in RESULTS.md (VERIFIED_REAL /
  VERIFIED_SYNTHETIC vs PENDING / OUT_OF_SCOPE).
- A synthetic fixture proves the implemented logic, NOT compatibility
  with a real app build. The golden vector is the strongest synthetic
  evidence available: it is the online reference's frozen vector,
  reproduced byte-for-byte by this dossier's oracle and opened by the
  native decoder. Real-app compatibility for `.ziv` files is now
  confirmed separately by the real export (RESULTS.md §1, §9); the real
  file itself is kept out of the repo (user credentials).
- Pending items (real `zivpn://` link, device QA) are listed
  in MANIFEST.json `limitations` and in RESULTS.md; they are not hidden.

## 7. Changes vs previous builds

No previous build of this package is covered by an earlier offline
dossier; the comparison baseline is the 2026-11-14/15 online dossier
(same version 2.2.5 / 184, no format change indicated by the Play
listing). The offline branch previously had no native ZIVPN decoder at
all: `.ziv` was not in `supportedFiles` and `zivpn://` was not a text
route in the offline app.

## 8. HMAC / connection-authentication audit

See MANIFEST.json `connection_authentication`. Summary: integrity in
`.ziv` is provided by the AES-GCM tag (AEAD), not by an HMAC; the
`zivpn://` link has no MAC (AES-CBC + XML/JSON parse). PBKDF2-HMAC-SHA256
is a local key derivation, not connection authentication. No HMAC was
traced to a connection-authentication purpose in the material reviewed.
`connection_authentication` stays NOT_OBSERVED per policy §2.2 — that
describes only the coverage reviewed, not a universal absence.
