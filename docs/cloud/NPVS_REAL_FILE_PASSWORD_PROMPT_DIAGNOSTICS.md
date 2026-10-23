# NPVS protected imports: verified real-file diagnosis and fallback

The source file was supplied privately by the user for local diagnosis.
**Do not commit the real fixture or password**, copy either into logs or
add them to any APK. The private fixture must remain local to the session.

Findings from the user-provided binary:
- NPVS signature checked successfully with ECDSA P-256.
- Binary NPVS version 5, method 1 (passphrase), zero recipients.
- PBKDF2-SHA256 count 600000; the supplied password successfully unwraps
  the 32-byte document key with ChaCha20-Poly1305.
- Authenticated metadata also decrypts; a deliberately wrong password
  fails authentication. The filename and secret are not recorded here.

Root cause of missing prompt on an incompatible deployment:
Android previously waited exclusively for the `PASSWORD_REQUIRED` Cloud
error. A pre-update server may return `NPVS_PROTECTION_UNSUPPORTED`
or `DECODE_FAILED` before the current NPVS v5 password worker runs.
The latest GitHub code cannot prove which backend revision is running on
the user's VPS without checking deployment.

Fix:
- In Android's existing single-file SAF path, the native client checks
  bounded **framing metadata only** (version 5, mode 1, header/descriptor/
  body bounds and iteration limits) and opens the current
  `CloudPasswordDialog` before contacting Cloud.
- In batch imports, a matching passphrase header can also trigger the
  same dialog when a stale server returns an older generic error.
- The UI, password field, dialogs, data storage and exported JSON formats
  are not changed.
- A local header is not authenticated: the worker still performs signature
  verification, password authentication and full JSON decoding. Never
  reinterpret an authentication failure by trying a legacy decoder.
- Until the VPS has the corresponding NPVS Cloud worker, providing a
  password cannot make an old engine decrypt a new protected format.

Validation: `NpvsPasswordProbeInstrumentedTest` tests the format gate;
the existing `tests.test_npvs_protected` suite validates signed v5,
passphrase failures and worker codes using reproducible synthetic data.
