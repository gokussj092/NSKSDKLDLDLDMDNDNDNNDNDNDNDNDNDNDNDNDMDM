# Results

Completeness interpretation superseded by `analysis/xyz.easypro.httpcustom/564/`:
the 17-field equality below was agreement with the then-incomplete server
reader, not a full original-application comparison. Original APK research now
retains 32 fields, recovers the missing V2Ray JSON and explicitly preserves one
unresolved historical field. The initial UTF-8 crash correction remains valid.

- VERIFIED_REAL_SAMPLE: native C++ now decodes the supplied file; complete
  JSON equality with the repository's Python server method, 17 Config fields
  and one Protections field. Before the correction: native exit 2.
- VERIFIED_SYNTHETIC: 98 differential HC cases, including HCCFG schemas
  1/2/5/7, n1/n2/n7/n8 schedules, HCX4 schema 10 n11/n12, password/HWID/both,
  carriers, tag alterations, legacy RST/ChaCha/JKL/Braille/numeric credentials,
  malformed inputs and the new invalid-UTF-8 field.
- Unknown schema 11/n13 and unobserved exporter builds are not certified.
- Android build and device UI QA are tracked separately. At initial local
  verification, SDK/NDK and a physical Android device were unavailable.
- User file bytes, recovered JSON and credentials are intentionally absent.
