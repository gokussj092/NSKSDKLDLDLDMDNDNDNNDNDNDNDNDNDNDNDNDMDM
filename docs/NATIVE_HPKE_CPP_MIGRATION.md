# SP-DECODE — Native HPKE migration (isolated validation branch)

Branch: `security/hpke-native-cpp-migration`; base: `security/v2-hpke-x25519-encrypted-transport`.

## Non-negotiable compatibility

The production-compatible server stays unchanged during this client refactor.
The X25519 recipient public pin is unchanged and held in two obfuscated byte
shares in `spdecode_transport.cpp`. **The recipient private key is VPS-only.**
No fallback to legacy plaintext V2, no replacement signing keystore, and no
new network endpoints.

## What runs natively

- `spdecode_hpke.cpp/.h`: RFC 9180 DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256 key schedule and exporter, AES-256-GCM request encryption,
  response tag validation and decryption, random message IDs and state.
- `spdecode_transport.cpp`: JNI methods for HPKE prepare, authenticated
  response open, state discard, and previously established native HTTPS.
- `libspdecode.so`: builds Mbed TLS **3.6.7** statically from the official
  release archive, whose SHA-256 is pinned in CMake. Only `JNI_OnLoad`
  is intentionally exported.
- `V2HpkeEnvelope.kt`: JSON encoding and opaque native state handle only.
  No Bouncy Castle, HKDF, Cipher, raw key bytes or HPKE cryptography in this
  Kotlin facade. Plaintext results necessarily reach Kotlin for UI display.

The ephemeral reply key and nonce stay in native protected state, bounded to
64 pending requests. A request handle is one-use: even a rejected reply
consumes the native state. `discard()` can be called again safely.

## Remaining Android platform security work

`spdecode_security.cpp` constructs the V2 PoP canonical proof, produces
cryptographically random Base64URL request nonces, calculates request hashes,
and derives the Play Integrity nonce. `spdecode_transport.cpp` verifies
the local package and allowed certificate fingerprints using Android
PackageManager APIs via JNI, including its previous basic debugger check.
The native bridge invokes the official Android Keystore JCA signer for
ECDSA proofs, without exporting the non-exportable P-256 private key.

`CloudRequestProof.kt` now delegates public-key lookup, bearer-bound key
selection and enrollment to the native Keystore orchestrator. The new
`CloudKeystorePlatform.kt` is an intentionally small adapter that calls
Android's real `AndroidKeyStore`, JCA and KeyGenParameterSpec APIs.
The non-exportable private signing keys remain entirely managed by Android.
`CloudDecodeClient.kt` still invokes the official Play Integrity SDK and
handles Android coroutines. The short-lived process-only bearer cache,
30-second renewal margin, action-integrity flag, token format/TTL checks and
expiry now live in thread-safe `spdecode_session.cpp`. The transport exposes
five registered JNI methods: `nativeCacheSession`, `nativeGetSession`,
`nativeRequiresActionIntegrity`, `nativeClearSession`, and
`nativeInvalidateSession`. HTTP 401 evicts only the matching bearer so a late
401 from an old request cannot clear a newer cached session. A temporary
Kotlin String is still needed to deliver bearer authorization and PoP; this
migration does not make tokens invisible to an attacker controlling the process.
These platform services and lifecycle contracts are **not** fully moved to
C++, and the app still has inspectable DEX code. Server-side Play Integrity
and hardware-attestation verification remain authoritative; native-only
checks are defense in depth.

Native code does not turn the public recipient key into a secret. A determined
analyst with full process access may inspect calls, memory and ciphertext
after decryption; backend access controls and Play attestation remain essential.

## Session migration (new, requires verification)

- C++ session state is process-local only; no tokens are persisted.
- Native cache uses a monotonic clock, synchronized access, 30-second renewal
  margin, bounded TTL and string format, and Mbed TLS zeroization on eviction.
- Added a host regression suite at `tests/native_session_contract.cpp` for
  expiry, input rejection, stale-401 safety and concurrency. It runs within
  the pre-existing native interop workflow on this isolated branch.
- Host and Android release builds passed for the Keystore migration
  (`41148188691` and `41148188746`) and for the current catalog/security
  head (`41149344926` and `41149344918`). Real-device Keystore/Play
  session validation remains pending.
- No backend routes, HPKE keys or VPS configurations have changed.
- Recovery: revert the native session commit on this branch and rebuild;
  preserve the original preproduction APK and server in place.

## Play Integrity guards and dependency review

- The client-side format checks for Classic challenge, Standard challenge,
  and Classic nonce are implemented in `spdecode_security.cpp` behind
  three new JNI methods. The official Android Play SDK is still mandatory.
  The VPS alone evaluates actual Play Integrity verdicts and admission.
- The Cloud-only source set excludes original parity decoders. Bouncy Castle
  1.86 remains a dependency of legacy/offline builds, but it is excluded
  from the Cloud variant, which uses native Mbed TLS for HPKE.
- Host contract cases cover accepted and rejected formats. The Android
  compilation workflow also runs Cloud source-isolation tests and verifies
  obsolete Bouncy Castle X509 resources do not appear in the release APK.
- Host + Android CI passed for the current native migration; **real-device**
  admission, security level and UX validation are still required.

## Android Keystore migration, branch-only

- `spdecode_keystore.cpp`: native process mutex protects alias state; retains
  `spdecode.transport.v2` and existing `spdecode.transport.v3.*` keys.
  Selects the newest enrolled alias after process restart. For signed bearer
  requests, extracts the server-issued `key` reference using Android's standard
  JSON parser invoked from JNI, and rejects an unavailable referenced key.
- Key generation runs using `AndroidKeyStore` and `secp256r1` through
  `CloudKeystorePlatform.kt`; private keys are **never** copied into C++.
  All signatures still run with the platform's `SHA256withECDSA` API.
- Native policy caps managed aliases at eight after pruning stale, inactive
  enrollment keys older than ten minutes, including malformed inactive legacy
  aliases to avoid permanent enrollment-limit exhaustion. It preserves the active alias and
  never replaces a required StrongBox attestation with a TEE fallback.
  On systems without StrongBox, a TEE fallback is allowed **only** for a
  challenge permitting TEE, as in the previous implementation.
- Native attestation returns real certificate-chain DER encodings from
  Android's KeyStore and requires 2..8 certificates. The backend still validates
  real certificate chains and hardware security level.
- Retired obsolete Kotlin-to-native direct-Key and alias-suffix wrappers;
  the private key is selected by the native orchestrator from a bearer hint,
  and the wrapper now registers exactly 19 native methods.
- PoP proof construction and Keystore-backed ECDSA signing now execute through
  one registered `nativeSignRequestProof` call. Canonical proof message strings
  are not returned to Kotlin; its adapter only receives timestamp, nonce and
  Base64URL signature. The platform JCA signer still consumes a temporary
  Java byte array; this cannot be eliminated without replacing Keystore.
- Session Standard Integrity policy is queried for the **exact bearer**,
  rejecting an accidental relaxed policy from a newer concurrent session.
  Absent server policy defaults to action-integrity required.
- Added `tests/native_jni_contract.py` as a cheap pre-build check of all
  Kotlin method descriptors versus `RegisterNatives`, including bridge existence.
- New tests: host `native_keystore_policy_contract.cpp` and Android
  `CloudTransportProofInstrumentedTest.kt` updated for enrolled aliases and
  non-exportable keys. The instrumented tests **require an actual Android
  device**; GitHub runner release compilation does not run them.
- If CI or device validation fails, revert this Keystore migration commit in
  this isolated branch only. Keep previous production APK and VPS unchanged.
- Known limitation: Play SDK token requests, provider caching and Android
  coroutine scheduling remain in Kotlin, and native code cannot prevent
  extraction of public keys or temporary data from a fully compromised process.

## Security ownership inventory (audited October 30, 2026)

| Component | Current classification | Security boundary |
| --- | --- | --- |
| `spdecode_hpke.cpp`, `spdecode_security.cpp`, `spdecode_session.cpp` | Native C++ | HPKE, proof framing, nonce format, short-lived bearer cache |
| `spdecode_transport.cpp` | Native C++ with Android JNI | HTTPS policy, responses, signer checks, Keystore signing |
| `V2HpkeEnvelope.kt` | Interface adapter | JSON and opaque native handle, not key schedule |
| `CatalogEnvelope.kt` | Crypto migrated; Android adapter | Ephemeral JCA P-256 key generation, GZIP inflate, JSON |
| `spdecode_catalog.cpp` | Native C++ | Catalog/icon ECDH, HKDF-SHA256, AES-256-GCM authentication |
| `CloudNativeTransport.kt` | JNI/platform adapter | Temporary strings/bytes are still visible during system calls |
| `ReleaseIntegrity.kt` | JNI adapter | Local APK signer check only; not authoritative admission |
| `CloudRequestProof.kt` | Native-oriented facade | PoP and certificate JSON marshaling only |
| `spdecode_keystore.cpp` and policy | Native C++ with JNI | Alias selection, legacy compatibility, session-key matching, enrollment, expiry and StrongBox/TEE fallback policy |
| `CloudKeystorePlatform.kt` | Required platform bridge | AndroidKeyStore entry access, key generation, encoded certificates; no key export |
| `CloudDecodeClient.kt` | Partly native, **remaining platform code** | Official Play SDK, coroutines, provider lifecycle and JSON composition |
| `NpvsIdentityVault.kt`, `ServerVpnSecureCache.kt` | Android Keystore/platform dependent | Local encrypted data; not a substitute for Cloud session admission |
| App screens, dialogs, catalog rendering | Kotlin UI | Do not move merely for DEX size |

A successful host build does not test StrongBox/TEE, live Play Integrity, or
on-device key migration. Those require a real Android handset and unchanged
production-compatible backend. Native storage reduces Kotlin cache exposure
but cannot hide a bearer already delivered to the Java HTTPS APIs.

## Catalog envelope crypto migration

- The existing catalog/icon wire format and Node.js server implementation
  are unchanged. New `spdecode_catalog.cpp` uses pinned native Mbed TLS for
  strict, canonical base64url, P-256 SPKI/PKCS#8 parsing, ECDH, HKDF-SHA256
  and AES-256-GCM response authentication.
- The native routine authenticates the purpose, recipient and server SPKI,
  plaintext size, salt, IV and ciphertext/tag. It rejects malformed P-256
  points and never returns unauthenticated payload bytes.
- `CatalogEnvelope.kt` retains platform-generated ephemeral JCA keypairs
  (not the non-exportable Keystore installation signing key), the unchanged
  4 MiB GZIP output bound and JSON UI composition. PKCS#8 bytes are erased
  on the Kotlin side after the native call; native copies are zeroized.
  Full native ownership of ephemeral key generation would be a further
  improvement, not claimed here.
- Added `native_catalog_cli.cpp` and `native_catalog_roundtrip.mjs` to
  test the unchanged Node.js backend against actual C++ decryption and
  reject modified keys, purpose, length, tags and ciphertext. The
  cross-runtime test passed in workflow `41149344926`.
- On-device catalog/icon flow and legacy compressed cache compatibility still
  require real Android device validation before considering a signed release.

## Verified branch status and release decision (October 30–31, 2026)

Latest validated migration commit: `0c8cd7a1e962576067e38d67ac00177791e13dc2`.

| Verification | GitHub Actions | Outcome |
| --- | --- | --- |
| Mbed TLS host C++ / HPKE ↔ Node.js, native proof/session/Keystore policy | `41149344926` | **SUCCESS** |
| Catalog/icon P-256 ECDH, HKDF and authenticated AES-GCM ↔ unchanged Node.js; modified tag/purpose/length/key rejection | `41149344926` | **SUCCESS** |
| Kotlin ↔ JNI descriptor/name/count gate | `41149344918` | **SUCCESS** (20 methods registered in source) |
| Android NDK 27, SDK 36, release R8, APK+AAB compilation, 4 ABI ELF, HPKE library/static APK audit | `41149344918` | **SUCCESS** |
| AAB locales, Cloud-only source isolation, obsolete Bouncy Castle resources absent | `41149344918` | **SUCCESS** |
| Release APK/AAB signed with original keystore | — | **NOT RUN** |
| StrongBox, TEE, server-side hardware attestation / live Play Integrity, cloud decoding and catalog rendering on physical Android | — | **NOT RUN** |

Builds in this document are static release compilation artifacts, **unsigned**, not evidence
of correct execution on a handset. The current `versionCode` in the branch is
still 35; this is not eligible for a new version after previously signed build 37.
Choose an unused code **greater than 37** only when generating the later signed
preproduction build.

### Diagnostic history

- `511d9b3` host tests passed but Android NDK build failed: obsolete
  `requiresActionIntegrity()` JNI use after native API change. Fixed by
  bearer-specific `requiresActionIntegrityFor(bearer)` in `e8f6166`.
- `e8f6166` host+Android compile initially failed on old Mbed TLS
  `mbedtls_ecp_keypair.grp/Q/d` member access. `1083807` added Mbed TLS
  private-access macros, then `0c8cd7a` corrected the public `ecp_group.id`
  field. Both workflows passed afterward.
- No change to VPS, HPKE recipient keys, API paths, server admission controls,
  production signing config, or `main`.

### Remaining intentional Android and presentation boundaries

- Kotlin invokes the official Classic/Standard Play Integrity SDK, manages
  asynchronous token-provider lifetime and Android coroutines; C++ controls
  request/challenge format and bearer-associated policy, **the backend** verifies
  the real verdict. This is not a local-only bypass.
- `CloudKeystorePlatform.kt` invokes Android's secure non-exportable signing
  keys, StrongBox/TEE generation and X.509 certificate extraction; native C++
  owns alias/policy decisions and uses JCA through JNI.
- `CatalogEnvelope.kt` still requests **ephemeral** P-256 key generation
  through JCA, passes a temporary PKCS#8 encoding to JNI (immediately scrubbed
  on the Kotlin copy), performs bounded GZIP inflation and JSON display parsing.
  The cryptographic ECDH/HKDF/AEAD itself now executes natively. Further native
  management of ephemeral keys is optional hardening, not a missing private
  server secret.
- `NpvsIdentityVault.kt` and `ServerVpnSecureCache.kt` deliberately use
  Android Keystore AES-GCM for local user identities/cache. Removing Keystore to
  reduce DEX code would risk exposing persistent keys. Their platform adapters
  are distinct from the Cloud request admission path.
- No runtime RASP/instrumentation protections added in this phase: false
  positives, Play compatibility and device behavior require a separate trial.

### Physical Android verification gates

1. Install a **new signed preproduction artifact** with the original upload
   keystore and appropriate release signer fingerprints; verify first launch,
   exact package, no crash, 14 locales and all supported ABIs.
2. Test old installed KeyStore `v2` alias, new `v3` hardware enrollment,
   TEE-only device, StrongBox-supported device, StrongBox-required rejection,
   app restart and concurrent requests.
3. Test authenticated HPKE Cloud session, Classic admission, Standard
   action integrity, 401 renewal, replay/modified response rejection and
   cancellation; confirm server-side attestation and Play verdicts.
4. Fetch server/provider catalog and icons, decode sample files, validate
   encrypted cache legacy SVC1 and current SVC2, and check export gating.
5. Capture sanitized nonsecret logs, classify any device-specific regressions
   before any Play deployment.

This branch is **ready for a device test planning gate**, not yet a production
release certification. Signed artifact generation and device validation
remain separate work.

## Validation gates

1. Run `.github/workflows/native-hpke-interoperability.yml` and verify
   host C++ seal -> Node.js server open -> Node.js seal -> C++ authenticated open.
2. Build `.github/workflows/native-hpke-android-compile.yml` to verify
   Android API 36, NDK 27, 4 ABIs, R8, AAB locales and native symbols.
3. Test invalid HPKE keys, modified request/response tags, replay,
   malformed packets, response/status mismatch, no downgrade.
4. Validate true Android installation and cloud session against the VPS
   using the unchanged original signing key. Test with and without Play
   distribution policy as applicable.
5. With CI green, create a **preproduction-only signed** APK/AAB using the
   original upload keystore and an unused versionCode greater than 37.
   Test that artifact on a physical Android handset before considering a merge.
   Never publish to production without device security and functionality approval.

Do not execute any Android/Next.js build on the limited VPS, do not change
`CLOUD_V2_HPKE_ONLY` or rotate the HPKE keys as part of this migration.

## Recovery

Keep v1.1.24 build 36 and original `security/v2-hpke-x25519-encrypted-transport`
branch as the known-good baseline. No VPS deployment or backend change is
required for the native crypto migration.
