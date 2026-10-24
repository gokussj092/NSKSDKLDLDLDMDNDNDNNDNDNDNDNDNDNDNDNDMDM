# Cloud preproduction — QA, tests and distribution (phase 4 follow-up)

Changes remain on branch `feat/austroplus-vpn-13-0-1-decoders`, PR #96.
No merge, no Play AAB, no VPS deployment, no public GitHub Release.

## Client and error handling

- The Android Cloud JNI transport recognizes the fixed server-vpn decode
  endpoint for MKK Hyper and allows up to 96 MiB for the JSON envelope.
  Other routes retain the 6 MiB wire limit. Kotlin enforces 32 MiB
  UTF-8 `rawText` for MKK only and checks its four-source JSON structure.
  Other decoders retain the 4 MiB result limit. These are resource budgets,
  not arbitrary truncation or unlimited transfers.
- NPVS v5 app-key remains handled by the current server script. The worker
  inspects only the nonsecret format header. If a valid v5 envelope explicitly
  selects a different protection method it reports the stable code
  `NPVS_PROTECTION_UNSUPPORTED`. Android displays a localized explanation
  that password/public-key protection is not integrated. Generic corrupt or
  unrelated files are never claimed to have private-key protection.
- Existing HTTP Custom and NPVS cryptography, white-box tables, private
  keys, scripts and Python dependencies are unchanged.
- User-visible Cloud-build explanations in 14 locales no longer claim
  that the user-facing decoder operates offline. Existing legacy native
  routes and contracts remain untouched.

## Regression repairs

- Align language resourceConfiguration with all 14 locale folders and
  refresh stale instrumented language-registry expectations.
- Update baseline hashes only for explicitly authorized UI changes;
  never disable the C0 integrity verification.
- Preserve separate error translation keys and password prompt keys.
- Adapt C8 tests to the now intentional Server VPN search field, MKK
  45 MiB internal transport budget and 32 MiB output quota.
- Python MKK integration tests requiring PyCryptodome skip the
  dependency-free C1 stub job when Crypto is absent. The decoder,
  production worker dependencies and actual decryption are untouched.

## Private preproduction workflow

`.github/workflows/cloud-private-preproduction-apk.yml` uses the existing
permanent Actions keystore, checks its SHA-256 against the pinned original,
builds `:app:assembleRelease` with real `https://api.spdecode.xyz`,
validates the package and immutable `1.1.6 (27)` identifiers, and uploads
only a private, temporary Actions artifact. No AAB, Google Play submission,
tag or public release. It runs once when the workflow file is added to the
feature branch; subsequent updates require manual dispatch.

**Installation warning:** the external APK signer must match the installed
APK signer. Play App Signing can differ from the original/upload signer.
Same versionCode=27 also cannot overwrite an installed binary that has a
higher versionCode, and an identical versionCode may not update cleanly.
Preserve encrypted history before replacing any installed build.

**Server compatibility:** remote decoding requires a working API and
appropriate authorized admission (Play Integrity or configured beta access);
a successful APK build does not prove live server readiness or that all
file formats decode successfully.
