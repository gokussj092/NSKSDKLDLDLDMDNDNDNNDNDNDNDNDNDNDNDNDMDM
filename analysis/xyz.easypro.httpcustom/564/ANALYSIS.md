# HTTP Custom 4.10.16: record loss and revision-57 field layers

The owner provided an APKM and the private `test.hc`. Binary AndroidManifest
parsing confirms `xyz.easypro.httpcustom`, version 4.10.16, versionCode 564.
The private export declares `verCfg:57` and `cfg.verApp:565`. These facts are
separate: that field alone does not prove which installed APK produced it.
The original APK is not silently relabeled as build 565.

## What was actually incomplete

The earlier Offline fix compared against the repository's Python decoder.
Both agreed on 17 Config fields, but that was parity with an incomplete
reference, **not evidence of completeness against the original application**.
The original record has 32 positional fields and additional envelope/config
metadata. The old reader skipped indices 22/24, dropped empty fields and
remaining hex tokens, and could mistake a 16-byte opaque seal for arbitrary
seven-character Base64/XOR output. It entirely omitted the V2Ray JSON.

The corrected real-file trace is:

1. The binary carrier, XOR/hex envelope and content layers are opened with
   the original 64-bit-nonce ChaCha20-Poly1305 construction.
2. Its MAC is `aad || LE64(len(aad)) || ciphertext || LE64(len(ciphertext))`.
   This differs from the padded IETF construction. The supplied ELF's native
   libsodium routine at 0x173c0 shows that order; trusted host libsodium
   1.0.18 independently verifies the sample's outer/content/field tags.
3. V2Ray field 26 authenticates with the existing format key schedule and
   embedded nonce material. Its 1,824-byte plaintext is a Base64 carrier.
4. Base64 -> 1,368 bytes -> the observed 20-byte revision-565 XOR pattern ->
   Base64 -> 1,026-byte valid JSON with inbounds/outbounds/policy.
5. The full string is preserved, not summarized, reinterpreted or truncated.

## Original native primitive evidence

JADX 1.5.6 finds the serialized models x8/a (`cfg`, `verCfg`) and x8/b
(`content`, `verApp`, protection/option members). Most application logic is
native; JADX reported 34 method errors, so Java decompilation alone is not
treated as complete application analysis.

Read-only ELF relocation inspection identifies Easypro.jkl at 0xfe6c and its
registered signature. The build-564 library contains native algorithm 2/3/4
XOR/Base64 primitives at the observed code/data offsets. A bounded ARM64
oracle freezes three deterministic synthetic encode/decode roundtrips from
that **actual library**. It never calls JNI_OnLoad, the application lifecycle,
VPN code, file/network APIs, or authentication hooks; unknown imports stop it.
Only narrow memory/libc and String/byte-array JNI shims are provided.

The build-564 native primitive and the private export's double-Base64 pattern
are distinct evidence. The latter is also verified by complete JSON recovery
and exact reversible field framing in the authorized export. We do not claim
a full real build-564 export/import roundtrip or device certification.

An initial attempt to select native representations by printable output
failed an independent JNI vector: two masks produced readable but different
strings. The implementation now chooses the observed representation by the
declared record version; it never selects a field cipher by readable guesses.
The failed IETF-tag, old masks, known AES candidates and bounded native AES
probes did not resolve historical slot 17 and are retained in recipes/tools.

## Remaining value and truthful output

The real sample's historical field 17 (called psiphon by the existing token
map) still has an unrecognized 16-byte value. No recovered plaintext is
invented. Its exact original value stays in Config and UnresolvedFields
identifies the limitation. The Cloud worker sets isPartial and a warning;
Offline shows a localized notice, including when opening saved history.
All 32 fields and all observed metadata remain available for copy/export.

## HMAC scope

The revised file path uses ChaCha20/Poly1305, not HMAC authentication of a VPN
connection. Existing modern HCCFG/HCX4 derivations remain isolated. No VPN
service, session, account authentication, hooks or connection keys were
inspected, captured or exercised. Only local format constants are used.
