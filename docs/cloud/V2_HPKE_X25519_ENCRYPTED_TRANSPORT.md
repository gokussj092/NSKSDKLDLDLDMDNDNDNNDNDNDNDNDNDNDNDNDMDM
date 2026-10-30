# SP-DECODE V2 — encrypted transport work branch

Versioning: this modifies **V2**; public V1 stays untouched. Do not build APK/AAB,
deploy to VPS, or publish before opt-in manual validation.

## Proposed cryptography
RFC 9180 HPKE base mode: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
AES-256-GCM. Request envelope: four ASCII bytes SP2Q, then 32-byte
encapsulated X25519 key, then ciphertext and a 16-byte tag.
Encrypted response: SP2R, then ciphertext and 16-byte tag. Independent
reply key and nonce are derived from the HPKE exporter, bound to the
request ciphertext, authenticated context and HTTP status.

Operation 1 challenge is public metadata delivered over HTTPS; operations
2 and 4–17 must be encrypted when V2 encryption is enabled.
Hardware ECDSA request proofs and server-configured Play Integrity checks
are retained. Disabling the Play Integrity policy omits Google tokens,
NOT hardware attestation or encryption.

The server's 32-byte X25519 recipient seed is stored only in the VPS
environment as CLOUD_V2_HPKE_PRIVATE_KEY (canonical base64url).
No private transport key is embedded in Android. Never log the seed.
Old V2 clients must be rejected when encrypted transport is required.
V1 remains unchanged.

## Caveats
- The VPS must decrypt for the worker. This is not zero-knowledge E2EE.
- The initial iteration retains JSON Base64 for file contents inside the
  encrypted envelope; there is NO bandwidth reduction until a later
  raw-file binary payload path is implemented.
- Existing Native JNI test harness must be adapted to the new binary method.
- This branch has not been compiled, deployed or validated against a phone.
- Do not merge before passing cryptographic cross-language tests and Android
  and worker integration checks.

## Reserved future export encryption
The user's preferred separate export-file design is hybrid HPKE using
ML-KEM-768 + X25519 (post-quantum + classical). This is NOT network V2.
Future export formats should have versioned recipient keys, authenticated
metadata and careful key lifecycle. Do not include a universal private
decryption key inside the APK.
