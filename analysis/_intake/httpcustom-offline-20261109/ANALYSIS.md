# HTTP Custom offline parity correction

The owner supplied a 36,840-byte private `.hc` file, SHA-256
`e109884b00889e85eb850b655b5f5f40b1a8be33f3cde860f000b6e5c0abdddd`.
Its decrypted outer structure has `cfg.content` and `verCfg:57`. This is a
format revision, **not** an observed Android versionCode. No original APK
was inspected. The intake location deliberately avoids inventing a build.

Observed with base commit 0992bf21648f92643d070e8b1eac0468a0b73134:

- Python `HCDecryptor.execute` and `HTTPCUSTOM.run` recognize the file.
- Native `decodeHttpCustom` returns `HC_UNRECOGNIZED_FORMAT`.
- The local diagnostic copy of the legacy translation unit exposed a
  nlohmann UTF-8 serialization failure. Its catch-all was hiding the cause.
- The content uses the legacy ChaCha fallback, not RST AES. Python removes
  invalid UTF-8 bytes from candidate plaintext **before** classification;
  C++ evaluated arbitrary bytes, counted high bytes as printable and accepted
  a candidate that could not be serialized. It was not a missing cipher key.

The fix mirrors `decode('utf-8',errors='ignore')` only in the historical
ChaCha/RST paths and numeric credentials. Classification uses code points
and generated Python Unicode 15.0.0 printable/alphanumeric ranges, avoiding
locale-dependent or byte-based guesses. JKL still requires valid UTF-8 and
its second Base64 layer requires the padding the Python reader requires.
Authenticated modern HCCFG/HCX4 UTF-8 and tag checks remain strict.

The corrected native result equals the complete captured Python dictionary:
17 configuration fields and one protection. The private probe never prints
their values. A synthetic malformed-UTF-8 field reproduces this class of
failure without retaining private sample bytes.

HMAC audit: historical exports do not authenticate the discarded legacy
16-byte suffix. HCCFG/HCX4 use the existing HMAC/HKDF/native folding for local
format key derivation and AEAD for section integrity. This is not evidence
of HMAC authorizing a VPN connection. No service connection, session material
or authentication hook was inspected or captured.
