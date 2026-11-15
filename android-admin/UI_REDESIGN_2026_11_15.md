# Admin UI refresh (2026-11-15)

Target: `ci/unity-ads-online-qa`, module `android-admin` only. Shared surfaces and record cards were refreshed, dashboard navigation duplication reduced, directory and ticket cards use existing server records, user detail is grouped, and appearance/about have dedicated routes. Foreground support polling no longer takes the mutation busy lock; outdated responses are dropped and the composer remains editable. The drawer structure, server authorization, JNI routes, signing configuration and R8 were not changed. Avatar display accepts bounded inline PNG/JPEG/WebP and Google image hosts; initials are the fallback.

Pending: full screen-by-screen redesign, server-side filters, real dashboard commerce/activity aggregates, admin FCM token registration and event fanout, translated string resources and language screen, complete device QA, and signed APK validation. No preview data was introduced. Source changes are not a successful build claim.
