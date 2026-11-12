# Results and limits

- VERIFIED_REAL: authorized 36,840-byte `test.hc`; full C++/Python/isolated
  Cloud worker JSON equality after retaining all 32 fields and metadata.
  The formerly absent V2Ray JSON is 1,026 bytes, fully valid and preserved.
- PARTIAL_REAL: slot 17 remains encrypted/unrecognized and is preserved
  verbatim with an explicit unresolved entry. The worker reports partial;
  neither the UI nor this dossier describes that value as decrypted.
- VERIFIED_ORIGINAL_PRIMITIVES: three ASCII synthetic roundtrips against
  the supplied build-564 ARM64 Easypro.jkl, independently of the port.
- VERIFIED_SYNTHETIC: 15 frozen libsodium cases; 52 new native carrier,
  complete-field and negative checks plus the 98 existing HC checks: 150
  native cases. Positive coverage includes empty seals, plain hex notes,
  metadata/reserved slots, Unicode, carrier depths 0/1/2/5 and both declared
  representations. Negative cases include each tag layer, unsupported
  versions, metadata-tag tampering, invalid JSON and invalid UTF-8.
- Python: 21 focused HC/CLI/worker/Offline UI-import tests passed; the eight
  TunnelDOOM regression tests passed after correcting their stale expected
  URL to the downloader's existing URL. Its production method was unchanged.
- Broker integration: the revision-57 exception is bound to the exact partial
  schema and matching complete JSON. Truncation and arbitrary partial responses
  remain rejected. The 45 combined C3/HC/HTTP Conexión/SpeiGo tests passed,
  including 11 malformed partial responses. The actual private worker output
  also passes the broker gate with HTTP 200. Online Android compilation is
  tracked separately from Offline.
- Android compilation/signing and physical-device behavior are separate
  checks. The existing Offline pipeline runs the new server suite and full
  native parity before release; CI run links are available per source commit.
- APK 564 identity and export verApp 565 are both recorded; no original
  build-565 APK or full export from every protocol was supplied. Unknown
  records and HCX4 schema 11/n13 are not certified by these synthetic tests.

No private profile bytes, recovered JSON, private identifiers or APK binaries
are in Git. generated/private_sample_summary.json contains only sanitized
counts, input hashes, JSON key names and the explicit remaining limitation.
