# C11 — Online What's New (versioned API)

> [Procedimiento obligatorio de futuras actualizaciones: Server VPN y novedades](CATALOGS_UPDATE_RUNBOOK.md)

The Android Cloud dialog is now populated from `POST /api/v1/whats-new`, not bundled announcements tied to `versionCode`.

## Content and localization

The canonical editorial catalog is `cloud/web/content/whats-new.json`. It is JSON only, not executable HTML. Each publication has a strictly increasing integer `version`, date, a short title and subtitle, and 1–12 user-facing entries with categories `feature`, `support`, `improvement`, or `fix`.

Publication **v2 (2026-10-20)** is translated into all nine supported app languages: `en`, `es`, `ar`, `fa`, `fr`, `id`, `ru`, `de`, and `pt-BR`. Any unrecognized or missing translation falls back to **English**. No new APK is required for server-side releases.

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

## Publication v2 — server news (three items only)

The October 20 server-side notice is version **2**. It intentionally contains
only the three changes first introduced with this update, in all nine supported
languages:

- **✅ KSH VPN** — new Server VPN provider with compatible catalog decoding
- **✅ DTunnel Mod** — listed with the confirmed icon; remote decoding remains
  disabled until authorized provider access is configured
- **🛠️ MKK Hyper VPN** — fixes incomplete output by reporting each catalog
  source separately and explicitly identifying errors

Previous announcements for HTTP Custom, HA Tunnel, the cloud architecture and
Google Play are **not repeated** in this publication. The text is short, and
all three entries use the existing API categories `feature` or `fix`.

Version 2 succeeds version 1 independently of the Android `versionCode`.
The Android client checks on open/resume after Cloud consent and displays a
versioned **in-app announcement**, not an OS-level push notification.
Users see it on a subsequent successful online check; dismissing it records
the seen version locally.

**Important VPS override:** `loadNews()` prioritizes `CLOUD_WHATS_NEW_JSON`
over `cloud/web/content/whats-new.json`. Before deployment check whether
the private `/etc/spdecode/cloud.env` contains a nonempty override. If so,
either remove it to use this repository's v2 notice or update it to the same
three-item content. A stale override can prevent the new notice from appearing.
Never expose values from `cloud.env` in public logs.

After updating the VPS, verify `POST /api/v1/whats-new` with
`knownVersion: 1` and `locale: es`, expecting localized version 2 with
exactly three entries. With `knownVersion: 2`, expect `unchanged: true`.
No Android recompilation is required.

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
