# RESULTS — ZIVPN Tunnel (com.zi.zivpn, versionCode 184) — OFFLINE

Observed 2026-11-18/19. Environment for the dossier tests: Python 3.12.3,
g++ 13.3.0, CMake 3.28.3, OpenSSL 3.0.13, PyCryptodome 4.5.0, Linux
x86_64. No network except the pinned downloads for the host harness
(Mbed TLS 3.6.7 + nlohmann json 3.11.3, both SHA-256 verified).

## 1. Status per route

- **files (.ziv)**: VERIFIED_REAL — a real `.ziv` exported by the app
  (supplied 2026-11-18, 2,778 B, export-style LF1-only, no DES layer)
  now opens in the native decoder: 47 properties, oracle and native
  agree on every key and value. The first attempt failed with
  `ZIV_INVALID_XML`: the app's `file.msg` entry holds emoji written by
  `java.util.Properties` as UTF-16 surrogate-pair numeric references
  (`&#55356;&#56808;` = U+1F1E8, `&#55356;&#56818;` = U+1F1F2), which
  strict XML 1.0 rejects. Fixed in `xmlUnescape` (native) and in the
  oracle: an adjacent high+low surrogate pair combines into the single
  code point; a lone surrogate still fails. The real file is NOT stored
  in the repo (it contains user credentials); only its property-key list
  was recorded. Synthetic coverage: 21/21 host-harness checks and
  13/13 repo parity tests, including a new emoji fixture
  (`ziv-emoji.ziv`) and a lone-surrogate negative
  (`ziv-lone-surrogate.ziv`).
- **text (zivpn://)**: VERIFIED_SYNTHETIC — native decoder opens XML and
  JSON links and bare tokens; 21/21 host-harness checks and 13/13 repo
  parity tests. No real `zivpn://` link observed; the scheme comes from
  the legacy text handlers, not from the app manifest.
- **catalog**: OUT_OF_SCOPE — no remote catalog is added to the offline app.
- **export**: PARTIAL — a real `.ziv` exported by app 2.2.5 now opens
  (see files above); a real `zivpn://` link is still missing.

Labels used here: VERIFIED_REAL = verified with a real live download or
a real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector
or a file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have;
NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Play listing evidence (2026-11-19 00:11 UTC)

- AppBrain mirror of the Google Play page, fetched as page text:
  ZIVPN Tunnel (SSH/DNS/UDP) VPN, ZI Applications, latest version
  **2.2.5**, last update **2026-10-26**, 1,000,000+ installs, 49.00 MB,
  Android 7.0+. Same version as the 2026-11-14/15 dossier; no format
  change indicated, so no APK was downloaded.

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 9 tests
- `python3 tools/verify.py`: `VERIFY OK`
```
PASS FIPS 46-3 DES-ECB vector (openssl oracle)
PASS FIPS 197 AES-128 vector (openssl oracle)
PASS .ziv round-trip legacy=True
PASS .ziv round-trip legacy=False
PASS .ziv round-trip legacy password
PASS zivpn:// round-trip (XML)
PASS zivpn:// round-trip (JSON)
PASS fixture ziv-legacy.ziv des_layer=True
PASS fixture ziv-export.ziv des_layer=False
PASS fixture ziv-legacy-password.ziv des_layer=False
PASS fixture ziv-golden.ziv des_layer=True
PASS fixture ziv-emoji.ziv des_layer=False
PASS fixture ziv-plain.xml
PASS fixture zivpn-link.txt
PASS fixture zivpn-json-link.txt
PASS negative: wrong password rejected
PASS negative: tampered GCM tag rejected
PASS negative: two-part envelope rejected
PASS negative: bad base64 rejected
PASS negative: lone surrogate rejected
PASS negative: bad zivpn token rejected
VERIFY OK
```

## 4. Host harness (production C++ unchanged)

- `bash tools/build_host_harness.sh`: `host_zivpn_test: 21 passed, 0 failed`
  (Mbed TLS 3.6.7, the Android pin).
- Same harness binary rebuilt against Mbed TLS 2.28.8 (the CI
  host-parity line): `21 passed, 0 failed` — built with
  `-Wno-error=deprecated-declarations`: the untouched `sha256()` helper
  calls the deprecated `mbedtls_sha256` on the 2.28 line, so a strict
  `-Werror` build fails there. The pristine file fails identically, so
  this predates the surrogate-pair fix; the Android pin (3.6.7) builds
  clean with `-Werror`.
```
PASS FIPS 46-3 DES-ECB vector
PASS FIPS 197 AES-128 vector
PASS file ziv-legacy.ziv
PASS file ziv-export.ziv
PASS file ziv-legacy-password.ziv
PASS file ziv-golden.ziv
PASS file ziv-plain.xml
PASS file ziv-emoji.ziv
PASS text zivpn-link.txt
PASS text zivpn-json-link.txt
PASS text zivpn-link bare token
PASS negative file wrong password
PASS negative file tampered GCM tag
PASS negative file lone surrogate
PASS negative file empty
PASS negative file not a profile
PASS negative file two parts
PASS negative file bad base64
PASS negative text empty
PASS negative text not base64
PASS negative text short block
```

## 5. Repo parity test

- `python3 tests/test_offline_zivpn_native_parity.py <cli>`: `Ran 13 tests ... OK`
  on both the Mbed TLS 3.6.7 CLI and the Mbed TLS 2.28.8 CLI (fixtures
  sealed by the independent PyCryptodome oracle, including the dossier's
  golden fixture and the new emoji / lone-surrogate cases).

## 6. Fixture hashes (synthetic fixtures only)

- `tests/fixtures/ziv-legacy.ziv`: SHA-256 `8f92408e1de95a62bc0210096c0650227ba70c21cf4c0ae513815c7cb48d6ae9`
- `tests/fixtures/ziv-legacy.expected.json`: SHA-256 `4d6179c6e0b9b0ce9c7e4d8a57b261ef9e52b80c91c0f40c7e4c6b9821336ec4`
- `tests/fixtures/ziv-export.ziv`: SHA-256 `bdee08a3ebefa0154a6ae44eb82531faf5bdeee3e54707baf5ea4b64d2b9aba1`
- `tests/fixtures/ziv-export.expected.json`: SHA-256 `4d6179c6e0b9b0ce9c7e4d8a57b261ef9e52b80c91c0f40c7e4c6b9821336ec4`
- `tests/fixtures/ziv-legacy-password.ziv`: SHA-256 `f3b4db63d995f5d9a60b034acfedbe65eb091f8e127ff496725924d11f0b49a1`
- `tests/fixtures/ziv-legacy-password.expected.json`: SHA-256 `4d6179c6e0b9b0ce9c7e4d8a57b261ef9e52b80c91c0f40c7e4c6b9821336ec4`
- `tests/fixtures/ziv-golden.ziv`: SHA-256 `5691c1acf4473e2bb367a774c87b47bc47617e76f04fe9e7294c0ed439399484`
- `tests/fixtures/ziv-golden.expected.json`: SHA-256 `c0d7ed9136f26ebd8ef3936e752265f2852fe4534f9ceb1cd7d634e25e464d97`
- `tests/fixtures/ziv-plain.xml`: SHA-256 `c98fb7111990cba0e50902faef16c1864ec4ede7796c2e20829420dcb12b7173`
- `tests/fixtures/ziv-plain.expected.json`: SHA-256 `4d6179c6e0b9b0ce9c7e4d8a57b261ef9e52b80c91c0f40c7e4c6b9821336ec4`
- `tests/fixtures/zivpn-link.txt`: SHA-256 `074bfe1c0ccce0e39c86572c25725bf1a1232f690c88415be0ee8fd2353f6a36`
- `tests/fixtures/zivpn-link.expected.json`: SHA-256 `4d6179c6e0b9b0ce9c7e4d8a57b261ef9e52b80c91c0f40c7e4c6b9821336ec4`
- `tests/fixtures/zivpn-json-link.txt`: SHA-256 `038d426c62ca8933727925c8cf49ee8057af9dd95ce52abd05af2d5be0818665`
- `tests/fixtures/zivpn-json-link.expected.json`: SHA-256 `529d51f458d5d100484dcd6208b343427bb8de289df36b2a0df9a08d4087e44d`
- `tests/fixtures/ziv-emoji.ziv`: SHA-256 `ee4e7b8393c4ed29201117e427b5a4f7ef96721863884ac77c21319feca900fa`
- `tests/fixtures/ziv-emoji.expected.json`: SHA-256 `9a4adcc5886c512c92cbeba49773754a6fe944e2871ac27760d1e1a6fa7ae51a`
- `tests/fixtures/ziv-lone-surrogate.ziv`: SHA-256 `95a82e736ca213c99a9fb1d1198d5eecf533eaca636ec487a2173426d2aabc9a`
- `tests/fixtures/ziv-wrong-password.ziv`: SHA-256 `9de2dc08a212b3a4311fc3e4472a25888622a814cd65de31b42eb8310b3947e3`
- `tests/fixtures/ziv-tampered-tag.ziv`: SHA-256 `8ba76e004cdae85c80d56058d702c81c9f6956ee1888991de532887e201b98e5`

No fixture contains a real credential, a real server with keys, or a
real user profile. All values are synthetic (TEST / `.example` domains),
except the frozen golden vector, whose one vendor hostname
(`udpsg1.zivpn.com`) comes from the online reference's golden vector
(reproduced byte-for-byte by this dossier's oracle).

## 7. Independent-oracle checks

- The dossier oracle (`tools/zivpn_reference.py`, PyCryptodome 4.5.0)
  reproduces the online reference's frozen golden `.ziv` byte-for-byte
  (same properties, same fixed salt/iv, legacy style) and opens the
  online reference's fixtures identically; it decodes `zivpn://` tokens
  identically to `text_legacy_protocols.decode_zivpn`.
- OpenSSL 3.0.13 as oracle: FIPS 46-3 DES vector
  (133457799BBCDFF1 / 0123456789ABCDEF -> 85E813540F0AB405) and FIPS 197
  AES-128 vector (key 000102...0f, plaintext 001122...ff ->
  69c4e0d86a7b0430d8cdb78070b4c55a).
- The production C++ was additionally verified against Mbed TLS itself
  (FIPS vectors in the host harness, both 3.6.7 and 2.28.8).

## 8. Pending (honest)

- Real `zivpn://` link (confirms the text scheme exists in the wild).
- Gradle/Android build + emulator/device run of the offline APK with a
  real `.ziv` import and a `zivpn://` paste (CI covers the build; the
  device QA is still pending).
- Legacy Kotlin `ZivPort` still lacks the DES layer (non-distributed
  baseline only; not part of the offline APK).

## 9. Surrogate-pair fix (2026-11-19, branch `offline/zivpn-surrogates`)

A real `.ziv` exported by the app failed in the offline decoder with
`ZIV_INVALID_XML` (and `ZIV_XML` in the oracle) although the crypto
opened fine (LF1 password index 0, AES-128-GCM OK, 2,021 B of
Properties XML inside). Root cause: the app's `file.msg` entry holds
emoji written by `java.util.Properties` as UTF-16 surrogate-pair
numeric references (`&#55356;&#56808;` = U+1F1E8,
`&#55356;&#56818;` = U+1F1F2 — regional indicators). References to
surrogates (0xD800–0xDFFF) are invalid in strict XML 1.0, so the old
`xmlUnescape` rejected them outright and ElementTree did too.

Fix, in both the native decoder (`spdecode_zivpn.cpp`, `xmlUnescape`)
and the oracle (`zivpn_reference.py`, `_combine_surrogate_pairs`):
when a numeric reference is a high surrogate (0xD800–0xDBFF) and is
followed immediately by a numeric reference to a low surrogate
(0xDC00–0xDFFF), combine them into the single code point
(0x10000 + ((hi − 0xD800) << 10) + (lo − 0xDC00)) and emit its UTF-8.
A lone surrogate (high without a low partner, or a low on its own)
still fails. The real file now opens (47 properties; oracle and native
agree on every key and value) and a synthetic emoji fixture
(`ziv-emoji.ziv`, export-style, `file.msg` with the same two regional
indicators written as surrogate-pair references) is part of the suites,
plus a lone-surrogate negative fixture. The real file itself is kept
out of the repo: it contains user credentials.
