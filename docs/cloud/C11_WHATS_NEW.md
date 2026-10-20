# C11 — Online What's New (versioned API)

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

## Publication v2 — cloud/server changes

The October 20 server-side update uses `cloud/web/content/whats-new.json`
with `version: 2`, `publishedAt: 2026-10-20`, six items and all nine
translations. Its public notices include:

- HTTP Custom 7.11.28 compatibility for supported protected `.hc` files
- HA Tunnel `.hat` decoding compatibility and complete JSON handling
- MKK Hyper VPN catalogs from individually identified sources, reporting failures
- New KSH VPN remote catalog decoding
- DTunnel Mod listing and icon; **remote decoding is not yet enabled**
- Google Play **Coming soon** on the public website

Version 2 succeeds version 1 independently of the Android `versionCode`.
The Android client checks on open/resume after Cloud consent; it displays a
versioned **in-app notice**, not an OS-level push notification. A device
receives it when next online, and dismissing it records the seen version.

**Important VPS override:** `loadNews()` prioritizes `CLOUD_WHATS_NEW_JSON`
over `cloud/web/content/whats-new.json`. Before deployment check whether
the private `/etc/spdecode/cloud.env` contains a nonempty override. If so,
either remove that override (to use the version-controlled v2 document)
or replace it with the fully translated v2 JSON. A stale override can
prevent v2 from reaching users. Never expose `cloud.env` values publicly.

Update the existing VPS branch, confirm the web/API container was rebuilt
and restarted, then check `POST /api/v1/whats-new` from an authorized
test client with `knownVersion: 1` and `locale: es` and again with
`knownVersion: 2`. Expected results: v2 content, followed by
`unchanged: true`. There is no need to publish a new APK.

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
