# C11 — Online What's New (versioned API)

The Android Cloud dialog is now populated from `POST /api/v1/whats-new`, not bundled announcements tied to `versionCode`.

## Content and localization

The canonical editorial catalog is `cloud/web/content/whats-new.json`. It is JSON only, not executable HTML. Each publication has a strictly increasing integer `version`, date, a short title and subtitle, and 1–12 user-facing entries with categories `feature`, `support`, `improvement`, or `fix`.

Initial editorial content is available in English and Spanish. All 9 supported app language codes are accepted; missing translations fall back to **English**. Add `ar`, `fa`, `fr`, `id`, `ru`, `de` or `pt-BR` inside each localized field when reviewed, without shipping another APK.

Example new publication:

```json
{
  "schemaVersion": 1,
  "version": 2,
  "publishedAt": "2026-10-20",
  "title": {"en": "SP-DECODE Cloud updates"},
  "subtitle": {"en": "Latest improvements and compatibility updates."},
  "items": [
    {
      "id": "fix-service",
      "type": "fix",
      "title": {"en": "Cloud service improvements"},
      "description": {"en": "Improved handling of supported configuration files."}
    }
  ]
}
```

Update `cloud/web/content/whats-new.json` and deploy **only the web/API**; **or** supply a complete validated JSON document through `CLOUD_WHATS_NEW_JSON` in the private VPS environment and restart the web service. The Compose file exposes that server-only variable. Either option updates every connected Cloud APK without recompilation. Always increment `version`; existing clients only show higher, unseen versions.

## Client behavior and privacy

- Version-only request includes `knownVersion` and the selected language. No account, HWID, file, credential, history or tracking identifier is submitted.
- For unchanged or already viewed publications, no announcement body is downloaded or dialog shown.
- Full text is validated, stored using Android Keystore AES-256-GCM device-bound encrypted storage, and shown once per published version. When offline, an unacknowledged validated cached publication can be shown.
- The legacy static install notice stays intact for non-Cloud builds. Cloud builds no longer display stale static notices when offline.
- After Cloud consent, Android fetches on opening/resuming. A failed request must never block decoding. Dismissal records `last_seen_cloud_news_version` locally, separately from the APK version.
- Content must describe actual released user-visible functions. Never publish secret endpoints, credentials, internal deployment instructions, or unverified file-format claims.
- The configured publication is server-side content; deploying the Cloud API and Android client together is required once to enable the new feature. Later publications require only changes to the VPS-side document or environment.

## QA

Run `cd cloud/web && npm test`, the Next.js production build, Android Cloud compile, and C0 snapshot parity. Test English, Spanish, another language falling back to English, a new higher publication, unchanged response, offline cached notice, failed downloads and repeated app launches.
