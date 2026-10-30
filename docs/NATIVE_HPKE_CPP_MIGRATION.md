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

`CloudRequestProof.kt` still uses **Android Keystore** to create and rotate
protected signing keys and retrieve hardware attestation certificates;
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
- Release R8, ABI, HPKE regression and real-device Keystore/Play session
  results are **pending** until the workflows/device checks have completed.
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
- All new changes need CI confirmation and real-device validation.

## Security ownership inventory (audited October 30, 2026)

| Component | Current classification | Security boundary |
| --- | --- | --- |
| `spdecode_hpke.cpp`, `spdecode_security.cpp`, `spdecode_session.cpp` | Native C++ | HPKE, proof framing, nonce format, short-lived bearer cache |
| `spdecode_transport.cpp` | Native C++ with Android JNI | HTTPS policy, responses, signer checks, Keystore signing |
| `V2HpkeEnvelope.kt` | Interface adapter | JSON and opaque native handle, not key schedule |
| `CloudNativeTransport.kt` | JNI/platform adapter | Temporary strings/bytes are still visible during system calls |
| `ReleaseIntegrity.kt` | JNI adapter | Local APK signer check only; not authoritative admission |
| `CloudRequestProof.kt` | Partly native, **remaining migration** | Android Keystore aliases, key generation, rotation, certificate chains, hardware attestation |
| `CloudDecodeClient.kt` | Partly native, **remaining platform code** | Official Play SDK, coroutines, provider lifecycle and JSON composition |
| `NpvsIdentityVault.kt`, `ServerVpnSecureCache.kt` | Android Keystore/platform dependent | Local encrypted data; not a substitute for Cloud session admission |
| App screens, dialogs, catalog rendering | Kotlin UI | Do not move merely for DEX size |

A successful host build does not test StrongBox/TEE, live Play Integrity, or
on-device key migration. Those require a real Android handset and unchanged
production-compatible backend. Native storage reduces Kotlin cache exposure
but cannot hide a bearer already delivered to the Java HTTPS APIs.

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
5. Only after physical device approval, create separately signed APK/AAB
   with an unused versionCode, then consider merging this branch.

Do not execute any Android/Next.js build on the limited VPS, do not change
`CLOUD_V2_HPKE_ONLY` or rotate the HPKE keys as part of this migration.

## Recovery

Keep v1.1.24 build 36 and original `security/v2-hpke-x25519-encrypted-transport`
branch as the known-good baseline. No VPS deployment or backend change is
required for the native crypto migration.
