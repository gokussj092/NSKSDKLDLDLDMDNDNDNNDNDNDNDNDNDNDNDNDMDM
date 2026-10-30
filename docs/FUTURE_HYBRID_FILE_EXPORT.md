# Reference design only — hybrid post-quantum encrypted exports

**Not used by SP-DECODE V2.** This is an independent design for an unrelated future app feature, not code to include in SP-DECODE transport.

Goal: author produces an encrypted export file that only an authorized destination can recover, even if the file is copied. Encrypt the file using randomly generated per-file AEAD content-encryption key and an authenticated recipient envelope. A file itself cannot enforce UI permission or authorization: actual access control relies on protected recipient private key and service policies.

## Hybrid key establishment

Choose a standardised hybrid design combining X25519 classical ECDH and ML-KEM-768 post-quantum KEM. Avoid naïve concatenation as a standalone scheme: prefer a reviewed IETF hybrid KEM profile/composite HPKE suite *once standardised and supported by audited libraries*. Hybrid input key material must be bound by context/version/recipient/public-key identities and a reviewed combiner/HKDF construction; implement neither an original KEM nor a proprietary mixing function.

Use a 256-bit randomly generated file-content encryption key and AES-256-GCM with fresh 96-bit nonces, content boundaries, version, algorithm suite, recipient ID, file ID, exporter ID, and any visible metadata authenticated as AAD. Multi-gigabyte exports should use an audited chunked AEAD format with a monotonic nonce/record counter, per-file salt and terminal record/length authentication, not a single gigantic plaintext buffer. Authenticate any detached index, format hints or manifest.

For multiple recipients, wrap the independent content key under each recipient's hybrid encapsulation context (distinct key derivation labels), never reuse one AEAD key and nonce between different recipients. Key rotations add recipient envelopes to newly exported files; recovering historical encrypted files requires the correct historical private key until deliberate rewrapping. Server-side authorization checks identities, audit access, short-lived permissions and revoked recipient IDs **before** releasing any protected private-key operation. No permanent private key in export payload, mobile APK or source code. Recovery keys should be stored in enterprise KMS/HSM where possible, with explicit backup, escrow and key-destruction policies.

## Security properties and release criteria

AES-GCM detects alterations; it does not prevent an attacker deleting/denying access to a file. Recipient key compromise breaks confidentiality for files encrypted to that key. ML-KEM-768 offers post-quantum IND-CCA KEM properties; X25519 is not post-quantum, so the combiner must preserve security while at least one constituent remains secure. There is no inherent revocation of an already decrypted offline file. If revocation is required, force decryption through an online authorized service rather than embedding secrets in export software.

Before implementation, verify current NIST FIPS 203 and applicable IETF HPKE/hybrid KEM drafts, mature audited libraries for Android/Node/other recipients, test vectors, identity and signer binding, misuse resistance, key rotation, performance, size overhead, and cross-platform tests. This document is a study-only architectural reservation, not a statement of formal interoperability or production security.
