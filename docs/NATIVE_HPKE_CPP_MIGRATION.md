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
`CloudDecodeClient.kt` still invokes the official Play Integrity SDK,
manages short-lived sessions and handles Android coroutines.
These platform services and lifecycle contracts are **not** fully moved to
C++, and the app still has inspectable DEX code. Server-side Play Integrity
and hardware-attestation verification remain authoritative; native-only
checks are defense in depth.

Native code does not turn the public recipient key into a secret. A determined
analyst with full process access may inspect calls, memory and ciphertext
after decryption; backend access controls and Play attestation remain essential.

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
