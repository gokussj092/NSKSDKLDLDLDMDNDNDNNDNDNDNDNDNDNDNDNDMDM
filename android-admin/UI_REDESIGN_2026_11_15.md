# Admin UI refresh (2026-11-15)

Target: `ci/unity-ads-online-qa`, module `android-admin` only. Shared surfaces and record cards were refreshed, dashboard navigation duplication reduced, directory and ticket cards use existing server records, user detail is grouped, and appearance/about have dedicated routes. Foreground support polling no longer takes the mutation busy lock; outdated responses are dropped and the composer remains editable. The drawer structure, server authorization, JNI routes, signing configuration and R8 were not changed. Avatar display accepts bounded inline PNG/JPEG/WebP and Google image hosts; initials are the fallback.

Pending: full screen-by-screen redesign, server-side filters, real dashboard commerce/activity aggregates, admin FCM token registration and event fanout, translated string resources and language screen, complete device QA, and signed APK validation. No preview data was introduced. Source changes are not a successful build claim.

Follow-up: section headers for secondary modules, actual decode metric tiles, page-local directory filters and ticket filters, screen-specific list positions, avatar disk-cache disabled, plus a unit test for chat auto-follow. Directory filters cover the loaded page only. No device QA result yet.

## Second pass — module-specific layouts
Dashboard now reads existing capability-scoped API counts and separates totals by currency. Transactions, licenses, API, credits, products, gifts, staff, audit, notices and catalog use structured summaries with details on demand. Directory profiles have record-level summaries; chat drafts are retained in memory (cleared on logout), polling failures have a non-destructive indicator, and accepted ticket status is applied before reload. No backend, online client, decoder, signing or workflow changes. Global filters are not claimed: search operates on the loaded page. Admin push and localization remain pending, as does validation of this revision.
