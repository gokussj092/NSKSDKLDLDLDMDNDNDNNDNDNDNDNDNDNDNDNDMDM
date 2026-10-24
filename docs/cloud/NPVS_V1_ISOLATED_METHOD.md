# Isolated historical NPVS v1 support in Cloud — PR #96

## Route selection
`npvs_bridge.py` chooses solely by the NPVS version marker after the
`NPVS` magic: version 1 → `decoders/Python/npvs_v1.py`; versions 5 and
6 → `decoders/Python/npvs.py` unchanged; unknown versions return
`NPVS_PROTECTION_UNSUPPORTED`. Failed v1 authentication never falls back
to v5, and v5/v6 are not decrypted with the historic white-box asset.

The new v1 module is server-side ONLY, uses five supplied historical
white-box assets, validates raw ECDSA-P256 signatures and complete
envelope boundaries, and decrypts with authenticated ChaCha20-Poly1305.
No Telegram logic, network access, Android tables, UI changes or VPS updates.
Credentials remain supplied via the existing isolated stdin channel.

## Status / verified limits
A synthetic signed v1 export generated with the historical
`_npvs_custodian_kdks` successfully exercises the whole worker; v1
passphrase mode validates `PASSWORD_REQUIRED`, `AUTH_FAILED` and JSON.
The user's real RJO2 export is **not yet verified compatible**:
running the user-supplied, unmodified legacy KDF against RJO2 produced
no authenticated document key with either white-box variant.
This is an actual unresolved key-generation variation, not evidence
of a password or recipient lock.

Do not claim that this commit opens RJO2 without a successful authenticated
real-file test. Do not commit the real RJO2 fixture, decoded JSON or
credentials. A signed but unsupported app-key generation is returned as
`NPVS_PROTECTION_UNSUPPORTED`, not fabricated success or generic failure.

## Deployment
After validation, `spdecode update worker feat/austroplus-vpn-13-0-1-decoders`
rebuilds the Docker worker. No changes to API responses, Play distribution
or Android app are required.

## Explicit embedded-field second stage (2026-10-23)

The user verified that RJO2 now authenticates/decrypts in production but its
`v2rayProfile` includes values such as `npvs1:Umpv`. These are prefixed,
Base64-encoded strings, NOT a second password or an ECDH private-key lock.

After a successful NPVS v1 signature, key unwrapping and document AEAD,
`decode_npvs_v1_complete` applies the existing v5 `_decode_embedded_npvs1`
postprocessor to the complete JSON tree. It recursively unwraps explicit
`npvs1:` values, UTF-8 text, nested JSON documents and repeated tagged
layers, with the existing 64-level nesting and field-size limits. Native JSON
booleans, numbers, null and ordinary untagged Base64 strings remain unchanged.
Malformed explicit tagged values fail closed: never return a partial or
fabricated JSON. No changes to v5/v6 decryptors, API, Android, password
contract or the worker process sandbox. Test the end-to-end worker with
synthetic, non-secret prefixed fields; do not commit real VPN credentials.
