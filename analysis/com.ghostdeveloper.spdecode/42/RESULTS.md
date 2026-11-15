# F7 APK QA results and unresolved tests

**NOT CERTIFIED / CI BLOCKED.** GitHub Actions run `42403333789` (new QA integration), `42403333472` (P06 evidence), `42403333506` (Validate) and `42403333606` (P08) each concluded FAILURE within seconds without usable steps or logs. Because old unrelated workflows exhibit the same behavior, this is not proof the new code compiled or failed. All code paths are staged only. The previous P08 validated 79 Python and 69 Node cases on `42340438190` before this new feature. **PENDING:** QA service 13 synthetic lifecycle tests, Cloud 11 gateway tests, native JNI/Android compile, actual owner-signed APK scanner and physical device→private VPS E2E. No paid feature, credit, admin account or third-party APK is certified.

## Account/store staging, 2026-11-10

The owner authorized the public Google/store implementation. Its independent scope, SQL/PSP contracts, Android drawer, optional Unity SDK and explicit deployment/credential/device limits are recorded in [the commerce dossier](../../../docs/STORE_GOOGLE_PAYMENTS_2026_11_10.md). This does not certify the older APK QA target or any third-party VPN method. Live payment flags default OFF.

## Payment mode isolation review — 2026-11-10

Orders and entitlements persist a sandbox/live discriminator. Verified payment events must match the order mode; key reveal, rotation and commercial API use require the current deployment mode. Switching to live mode rejects previously issued sandbox keys. Web account receipts mark test purchases. Local SQL/semantic contracts and the Next build pass (712 web tests passed, 3 skipped). Remote PostgreSQL concurrency and Android release/optional Unity compilation passed for source 9772084; the mode-isolation extension requires its own PostgreSQL CI pass. This changes commerce fulfillment only and does not alter VPN decoder algorithms, catalogs or worker outputs.
