# HMAC audit — Speicers and HTTP Injector

Scope requested for the current review: Speicers Pro netfree.mx.store104.1.20/build123, downloaded from the documented distribution, and the uploaded HTTP Injector6.5.0/build244. No other VPN application was analyzed in this review.

| Input | Verified observation | Connection-authentication conclusion |
| --- | --- | --- |
| Speicers Pro123 | Base APK hash matches the previous analysis;41622 visible DEX methods;5 Mac.getInstance,4 Mac.init,5 Mac.doFinal references | UNCONFIRMED. Prior catalog/file HMAC evidence does not establish service authentication. |
| HTTP Injector244 | Uploaded ZIP/APKS identity verified;82 visible DEX methods; algorithm markers in native libraries | UNCONFIRMED. Visible DEX surface and native string markers do not establish the behavior of the complete application. |

The reports contain only identity, hashes, fixed algorithm markers, aggregate counts and uncertainty. They do not include key values, per-function input/output, tokens, VPN profiles or reproducible impersonation generators. No APK/native code was executed; no VPN/authentication endpoint was contacted. Actual service authentication keys were not extracted.

AGENTS.md and METHOD_EVIDENCE_POLICY.md section2.2 now require auditing HMAC use separately for files/catalogs, protocol transport integrity and connection authentication, including provenance categories and evidence limits. This is a documented investigation rule plus an isolated static inventory tool; it does not enable an F7 runtime adapter or an additional automatic CI gate.

[Speicers dossier](../../analysis/netfree.mx.store/123/ANALYSIS.md), [HTTP Injector dossier](../../analysis/com.evozi.injector/244/ANALYSIS.md), [owned audit tools](../../analysis/_intake/hmac-auth-audit-2026-11-09/tools).

Verification: two scanner privacy/identity boundary tests and two offline report-schema tests passed. Fictional secret-looking strings in test input never appear in audit stdout/reports. Original upload/APK/native bytes remain outside Git; no new decoder compatibility or successful service authentication is claimed.
