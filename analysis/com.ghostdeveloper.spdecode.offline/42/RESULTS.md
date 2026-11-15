# Verification

## Revision-57 correction, 2026-11-10

The [original HTTP Custom build-564 investigation](../../xyz.easypro.httpcustom/564/RESULTS.md)
supersedes the historical 17-field comparison below: both old implementations
omitted data. The new C++/server outputs retain all 32 fields and metadata,
recover the 1,026-byte V2Ray JSON, and flag the still-encrypted field 17 as
partial. The HC regression suite now has 150 native cases. APK identity 564
and the export's declared verApp 565 are recorded separately in that dossier.

## Earlier UTF-8 and JSON viewer checks

Local: 98 HC native cases; exact JSON equality against the then-existing Python reference for the authorized
36,840-byte HC sample; 85 NPV cases; 9 Python tests/17 subtests; 7 Offline
UI/import contracts. Real HC output is 17 Config fields and one Protections
field; no values are recorded.

Host tests passed with the dependencies pinned in dependencies.lock.json.
Android Actions compilation/signing is tracked independently. Physical
Android line/selection/theme checks and actual NPV link QA remain pending.
Source-only UI checks do not certify those device behaviors.
