# HTTP Custom build 934 — n15 in the OFFLINE Android app (native C++)

## Objective

Port the verified HCCFG 12/n15 decoder (HTTP Custom 8.0.22 Patch 2, build 934)
into the SP-DECODE **offline** Android app (`offline/hc-n15`, base `0d3a20d7`
on `feat/version-offline-apk`), in the native C++ engine
(`android/app/src/main/cpp/spdecode_http_custom.cpp`), keeping n11/n12 and
all legacy schedules byte-identical.

Reference (read-only, server branch): `decoders/Python/apps/HTTP_Custom/codec.py`
(`_derive_n15`, `derive`, `decrypt`) and `crypto.py`
(`native_fold_n15`, `N15_INNER_STATE`/`N15_OUTER_STATE`, `CERT_SHA256`),
plus the revised reader `HttpCustom_934_revisado.py`
(SHA-256 `50ef2777a1e03b0ff9176b3de509bdb5606ceb450ac07e8207764cb42efaad5e`)
and `REVISION_N15_2026_11_16.md`.

## Method (observed, not guessed)

- HCX4 outer envelope unchanged: same outer key/AAD as n11/n12.
- n15 = envelope `b=12`, `e="n15"`. Content key:
  - `AAD = "HCCFG|12|XCHACHA20P1305|NATIVE-HKDF-SHA256|n15|xyz.easypro.httpcustom|1|"
    + features + protection_aad + "|" + build`
    (`protection_aad` is `"|0"`, or `"|1|ARGON2ID13|<ops>|<mem>"` when protected).
  - `content = native_fold_n15(AAD)`: SHA-256 continued from the n15
    HMAC-prestates over `0xf1 || CERT_SHA256 || AAD`.
  - If protected (`h=1`): Argon2id password key via `_pw_kdf`
    (ops = envelope `l`, memory = envelope `m`; bounds ops 1–10,
    memory 8192..256 MiB; real samples use l=2, m=67108864), then
    `key = HKDF(content + password_key, seed, "hc-config-content-v12")` —
    the Argon2id key is concatenated **before** the content HKDF.
  - No HWID slot exists in n15. A protected file without a password fails
    cleanly with `PASSWORD_REQUIRED`.
- Every section key derives from the content key:
  `skey(label, extra) = HKDF(key, "hc-config-part-v12", aad + 0x00 + label + extra)`.
  Main and profile sections use `skey(label)`; an HPR1 inner layer uses
  `skey(label, ":r")`; a sidecar uses `skey(label, ":x")`. Both AEAD layers
  must authenticate; there is no stream-only fallback.
- `app_version` for build 934 is `"8.0.22 Patch 2 (934)"`, matching the
  Python codec.

## What changed in the native code

`android/app/src/main/cpp/spdecode_http_custom.cpp` only:

1. `N15_INNER_STATE` / `N15_OUTER_STATE` constants (verified against
   `crypto.py`) and `nativeFoldN15()` (0xf1 prefix + `CERT_SHA256`, reusing
   the existing `fromState()` SHA-256 continuation).
2. `deriveN15()` implementing `_derive_n15` exactly, including the
   `PASSWORD_REQUIRED` / Argon2 bounds / `HC_MISSING_BUILD` failures.
3. `derive()` dispatches to `deriveN15()` for modern envelopes with
   `b=12, e="n15"`, and rejects any other modern schema up front with
   `HC_UNSUPPORTED_SCHEMA` — so b=9/b=13/n16 files fail cleanly instead of
   hitting a misleading missing-member error. The n11/n12 and legacy paths
   are untouched.
4. `Material` gains an `n15` flag; `decryptParsed()` derives per-section
   keys through a `partKey(label, extra)` helper that returns the content
   key unchanged for non-n15 schedules, so n11/n12/legacy output is
   byte-identical. HPR1 and sidecar layers use the `:r` / `:x` keys.
5. Version string for build 934.

No new dependencies: the existing pinned Argon2 reference
(`spdecode_argon2_ref`, P-H-C/phc-winner-argon2 `62358ba2`,
`ARGON2_NO_THREADS`), Mbed TLS 3.6.7 and nlohmann/json are reused.

## Password flow (checked, no change needed)

- Offline flavor: `.hc` imports go through JNI
  (`NativeOffline.decodeNative` → `decodeHttpCustom`) and the offline
  `MainActivity.decodeAttempt()` already maps `PASSWORD_REQUIRED` /
  `HWID_REQUIRED` / `HWID_PASSWORD_REQUIRED` to its credential prompt and
  retries with the supplied password. The C++ throws the same strings.
- Main (cloud) flavor: `.hc` imports go through the Kotlin-only router
  (`AndroidOfflineDecoderRouter` → `HcPort`/`HcHccfgPort`, n1/n2/n7/n8
  only). Porting n15 there would need a pure-Kotlin SHA-256-from-state
  implementation (Android `MessageDigest` cannot resume from arbitrary
  states). That is **pending future work, not attempted here**; the
  protected-import dialog was deliberately left untouched so it does not
  prompt for a password the Kotlin path cannot use. See RESULTS.md.

## HMAC audit (§2.2)

- **File/catalog**: observed. XChaCha20-Poly1305 AEAD tags authenticate the
  outer HCX4 envelope, the main section, every profile section, the HPR1
  inner layer and sidecars. The n15 content key folds the AAD through the
  n15 HMAC-prestate SHA-256 states. All tags verified by the harness
  against real samples.
- **Transport integrity**: NOT_OBSERVED — no VPN transport was exercised;
  this work decodes exported files only.
- **Connection authentication**: NOT_OBSERVED — no evidence that any HMAC
  authorizes a VPN connection. No connection was established and no
  verifier was observed.

## Out of scope by design (closed offline by proof)

- n16 (`Test bloqueo password y hwid.hc`, b=12/n16): `HC_UNSUPPORTED_SCHEMA`.
- n17 (`Test password.hc`, b=13/n17) / n18 (`Test hwid.hc`, b=13/n18):
  Extra Protection needs the server key: `HC_UNSUPPORTED_SCHEMA`.
- b=9 (`Test bloqueo ID de acceso.hc`, RSA-2048 access-ID wrapper, needs the
  original recipient private key): `HC_UNSUPPORTED_SCHEMA`.
- No live-capture / Frida material was prepared or offered.

## Regression scope

n11/n12/legacy behaviour is preserved by construction (the new code path is
only entered for `b=12/e=n15`; `partKey` is the identity for older
schedules) and is covered by the harness comparison for the real samples
plus the pre-existing repo HC tests (see RESULTS.md for what was actually
run).
