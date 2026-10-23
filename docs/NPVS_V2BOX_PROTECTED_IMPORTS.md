# V2Box password imports and NPVS app-key classification

**Scope:** PR #96, no changes to existing V2Box fixed-key algorithm or NPVS key derivation.

## Real local inspection (2026-10-23)

| Private sample (not stored in Git) | Bytes | Format | Observed |
| --- | ---: | --- | --- |
| BOYYZZX VIP. TEST.v2box | 2,997 | V2Box export v1, no password | AES-256-GCM tag authenticated; full JSON object recovered |
| 21 Freesurf Orange 18h-22H.v2box | 4,205 | V2Box export v1, password-protected | Empty and deliberately incorrect test passwords fail GCM tag; valid password not supplied |
| lukas gaming21.1.npvs | 2,835 | NPVS v5, compact mode 2 app-key, 0 recipients | Header lengths consistent; creator's ECDSA-P256 signature independently verified |

The NPVS attachment **is not v6 recipient/public-private-key protection**.
This framing does not need a password or a recipient's private key. It has not
been confirmed that this particular ciphertext decrypts using the currently
supported app-key material; do not advertise real plaintext recovery.

## Implemented

- Android offline V2Box: inspect well-formed password-protected export, open
  one-shot password dialog, derive SHA-256 of UTF-8 password, AES-GCM verify tag,
  preserve existing fixed-key path for unprotected exports. No password stored.
- Cloud V2Box: allow password on existing file route and pass it on worker stdin
  to a dedicated isolated bridge. No binary/secret in telemetry.
- Wrong password: `AUTH_FAILED`, existing single informational notice, manual
  re-import for another attempt. A modified ciphertext/tag is cryptographically
  indistinguishable from a wrong password and must not be called a proven guess.
- NPVS: maintain explicit recipient v5/v6 detection. Signed v5 mode 2 app-key
  tag failures at document-key unwrap now return `NPVS_APPKEY_AUTH_FAILED`.
  Explain possible unsupported variant or altered ciphertext without asking
  for password or private key. Messages in all 14 locales.
- Historical NPVS methods, white-box tables, unrelated formats, and Android
  history retention stay unchanged.

## Verification

- Local independently implemented AES-GCM parity: normal V2Box export opened,
  wrong-password protected case rejected, and authenticated JSON recovered.
- Local NPVS binary inspection, header/body/descriptor lengths, and independent
  ECDSA signature verification passed.
- Synthetic Python tests: `python -m unittest tests/test_v2box_password.py`
  (requires PyCryptodome in the repository test environment).
- Android instrumented structural classification:
  `CloudC8InputRoutesTest.protectedV2BoxAndNpvsAppKeyAreClassifiedSeparately`.
- Full Android Gradle, Linux cloud suites and deployed worker verification were
  not run locally in this environment. GitHub CI runs separately.

## Safety and limitations

Do not commit real files, passwords, signatures, plaintext configurations,
device private keys or diagnostic request payloads. A V2Box password is not
recoverable from these files without a valid secret. NPVS signed mode 2 may
use an unrecognized app-key variant or tampered ciphertext even when its outer
ECDSA signature is valid; only full authenticated decryption can certify
support. Never retry recipient-private-key methods using guessed passwords.
