# SP-DECODE V2 — HPKE application transport (preproduction)

**State:** code integration for the isolated `security/v2-hpke-x25519-encrypted-transport` branch; DEBUG and unsigned R8 artifacts were compiled before native pin integration. Native pin bridge requires a fresh build and device interoperability test; no production deployment. Do not activate in production until all release gates pass. **V1 is unchanged.** No V3.

## Scope and trust

HTTPS remains mandatory. RFC 9180 base mode DHKEM(X25519, HKDF-SHA256) **KEM 0x0020**, HKDF-SHA256 **KDF 0x0001**, AES-256-GCM **AEAD 0x0002**. Android encrypts with Bouncy Castle's HPKE implementation, Node 22 with `@hpke/core@1.9.0`. Base-mode HPKE authenticates the *server* only through a pinned, authentic X25519 public key. It does NOT authenticate the Android client by itself: hardware-backed ECDSA PoP, certificate/key attestation, session JWTs, Google Play Integrity and request limits retain their independent roles.

This is application-level client-server encryption, not end-to-end encryption excluding the VPS operator. The server intentionally decrypts to invoke the worker. The private HPKE recipient key never belongs in APK, Kotlin, native .so, GitHub Actions artifacts, code or logs.

## Binary request, network byte order

`Content-Type: application/octet-stream`; URL remains the native-controlled `/api/v2/transport`.

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `SPH2` |
| 4 | 1 | envelope version, exactly 1 |
| 5 | 2 | KEM = `0x0020` |
| 7 | 2 | KDF = `0x0001` |
| 9 | 2 | AEAD = `0x0002` |
| 11 | 8 | key ID: first eight SHA-256 bytes of raw recipient public key |
| 19 | 16 | random message ID (Redis anti-replay) |
| 35 | 32 | HPKE encapsulation `enc` |
| 67 | 4 | AEAD ciphertext length including 16-byte tag |
| 71 | variable | HPKE ciphertext and tag |

HPKE `info` UTF-8/ASCII is exactly `SPDECODE-V2-HPKE-TRANSPORT-1`.
HPKE AAD is the full 71-byte header **followed by one byte of operation ID**. The operation remains a public `X-SP-Operation` header, but substitution invalidates HPKE AAD and the ECDSA proof. No opaque provider URLs or secret metadata are in the external header.

Decoded plaintext layout: `u32be metadata JSON UTF-8 byte length | metadata JSON | optional raw file bytes`. The binary tail is **only** valid for operation 5 and must be 1..8 MiB. The server converts it to the existing worker's `dataBase64` field **internally**, so Decoder Worker contracts, per-format validation and timeouts remain unchanged. Request wire maximum is 11 MiB, metadata 1 MiB. Current implementation buffers complete requests and responses in memory; streaming/chunking is an explicit follow-up, not a claimed optimization.

Initial challenge (1), session (2), metadata, notifications (17), catalog and all other V2 operations use the same envelope, with empty binary tail. Bearer and action integrity token remain HTTP headers; these headers remain TLS protected but are **not HPKE-encrypted**. For complete metadata/token ciphertext protection, relocating sensitive headers *inside* the signed encrypted body is an outstanding release blocker; do not claim that every credential/token is HPKE-protected until this is addressed. IP/proxy metadata and message length also remain visible to TLS termination.

## Binary response

`Content-Type: application/octet-stream`. The response plaintext is the original JSON response, including `rawText`, `dataBase64`, catalog or notices, but only the ciphertext is transmitted.

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `SPR2` |
| 4 | 1 | envelope version 1 |
| 5 | 2 | HTTP status, unsigned |
| 7 | 16 | matching request message ID |
| 23 | 4 | response ciphertext length including tag |
| 27 | variable | AES-256-GCM ciphertext + 16-byte authentication tag |

After HPKE request open/seal, both endpoints call the **RFC 9180 HPKE exporter** using `SPDECODE-V2-HPKE-RESPONSE-KEY-NONCE-1`, requesting 44 bytes. Bytes 0..31 are a distinct AES-256 response key and bytes 32..43 the 96-bit nonce. A new HPKE ephemeral encapsulation is generated for *every* request; never reuse an exporter-derived response key/nonce for a second response. Response AAD is `SPDECODE-V2-HPKE-RESPONSE-AAD-1 | SHA256(full request wire) | full 27-byte response header`.

Android validates ciphertext tag, response status and request ID *before* parsing the JSON. No successful plaintext JSON responses are allowed for the new client. Rejections prior to HPKE authentication may be generic, non-sensitive JSON errors. Sensitive application data and `rawText` must never appear in such errors.

## Proof, session and Play Integrity

The preexisting ECDSA proof string remains `SPDECODE-POP-V2\nPOST\n<operation>\n<version>\n<timestamp>\n<nonce>\nSHA256(bearer)\nSHA256(exact request wire)`. For both challenge and session bootstrap, use the same exact binary wire hash. Proof nonces are still unique in Redis. The challenge Redis record stores the HPKE boolean; op 2 must match it. Newly admitted JWT sessions carry `hpke:true`; the JSON transport is rejected for such sessions even during coexistence. The rollout flag `CLOUD_V2_HPKE_ONLY=true` disables *all* JSON V2 at cutover. There is never a fallback to V1.

Action challenge (op 16) receives the SHA-256 of the **already prepared, final encrypted wire**; Standard Integrity requestHash is derived from it. After receiving its token, Android transmits that exact prepared ciphertext. The server verifies the same hash. When Play Integrity is disabled by the independent server policy, no Play token is requested for session or protected actions; HPKE, ECDSA and hardware policy remain enforced.

**Attention:** Action token and bearer are currently HTTP headers and therefore not encrypted by HPKE (although protected by HTTPS). Complete the protocol migration to HPKE-encrypted authenticated metadata before claiming universal HPKE protection of these fields.

## Keys and rotation

The Android PUBLIC X25519 pin is embedded as two masked byte shares in `spdecode_transport.cpp`, compiled into `libspdecode.so` and returned through JNI as 8 identifier bytes followed by 32 public-key bytes. No plaintext Base64 pin is stored in Kotlin, BuildConfig or application resources. This is reversible obfuscation of a PUBLIC trust anchor, not secret encryption. Key rotation requires a reviewed native pin update and a newly signed Android build. The server's PRIVATE recipient key stays on the VPS, never in the APK/AAB.

On a secured operator machine, **outside the repository**, run:
```sh
cd cloud/web
node scripts/v2-hpke-keygen.mjs /absolute/secure/path/v2-hpke-keyring.json
```
Output is only the PUBLIC Android pin; private key JSON is created with mode 0600, refusing overwrite or a destination under the working repository. Configure the VPS secret `CLOUD_V2_HPKE_KEYRING` with the exact file's JSON content using the existing secrets mechanism, *without* printing or committing it. It accepts 1..3 keys; retain previous private key during overlapping app updates. Restrict file and runtime secret access; protect VPS backups and prevent secret leakage via observability.

Use a new generated key before revoking the previous key. Publish an updated signed Android app with its new public pin, verify it on real devices, then select the new active pin. Revoke the retired key only after old clients expire; provide an app update instead of key fallback to a random remote public key. On a compromised private key, immediately disable HPKE traffic/publish emergency client policy; do not silently downgrade.

## Activation and rollback (NOT run)

- `CLOUD_V2_HPKE_ENABLED=false` by default in code. V1 and the old JSON private V2 remain unchanged.
- After Android+server test vectors, integration, hardware/Play beta tests and independent code audit, provision HPKE keyring on staging, set `CLOUD_V2_HPKE_ENABLED=true`, keep `CLOUD_V2_HPKE_ONLY=false` during coexistence, route beta testers to new Android build.
- Monitor CPU, resident set size, accepted/rejected sessions, replay rejects and p95 latency **without plaintext logs**.
- After old V2 clients migrate, set `CLOUD_V2_HPKE_ONLY=true`, then observe 401/426 rates. Do not remove V1 handlers.
- On failures *before full cutover*, disable admission of new HPKE sessions while keeping existing V1 untouched; if security is compromised, block affected sessions and require a fixed APK, **never downgrade an already HPKE-bound session to JSON or V1**.
- Roll back code/config in a controlled staging/production release only following authorization; this branch itself must not deploy to VPS.

## Performance and outstanding release gates

Raw binary saves about 33% Base64 transport expansion for file bytes, *before* fixed envelope overhead, but does NOT eliminate Base64 inside the legacy worker hop. HPKE adds one X25519 encapsulation+decapsulation and symmetric authenticated encryption per request, plus one AES-GCM operation per response. Actual CPU/RAM, network throughput and APK size must be measured with representative files/cellular latency. No compression of secret-bearing plaintext; legacy catalog envelope is retained until semantic equivalence and performance are measured.

**Required later:** build Android API24..36, verify BC vs Node exact interoperability, validate ASN/JWK import formats, run RFC9180 vectors and tamper/replay/rotation tests, compare error/status semantics, baseline load + quotas and live dev attestation. Address request/response memory buffering, encrypted sensitive request headers, proof/session policy races, app signer/Play Integrity policy variation, keyring secret injection and FCM notice delivery. Do not authorize production with these unverified.
