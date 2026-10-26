# C11 — Online What's New (versioned API)

> [Procedimiento obligatorio de futuras actualizaciones: Server VPN y novedades](CATALOGS_UPDATE_RUNBOOK.md)

The Android Cloud dialog is now populated from `POST /api/v1/whats-new`, not bundled announcements tied to `versionCode`.

## Content and localization

The canonical editorial catalog is `cloud/web/content/whats-new.json`. It is JSON only, not executable HTML. Each publication has a strictly increasing integer `version`, date, a short title and subtitle, and 1–12 user-facing entries with categories `feature`, `support`, `improvement`, or `fix`.

Publication **v3 (2026-10-22)** is translated into all 14 languages currently listed in the app: `en`, `es`, `ar`, `fa`, `fr`, `id`, `ru`, `de`, `pt-BR`, `tr`, `vi`, `hi`, `ja`, and `it`. Any unrecognized or missing translation falls back to **English**. The release notes are deployed server-side without a new APK; however, **previous APKs whose CloudWhatsNewRepository only requests nine languages continue to receive English for Turkish, Vietnamese, Hindi, Japanese, and Italian**. The expanded Android locale allowlist takes effect only in subsequent Android builds.

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

## Publication v3 — new Server VPN catalog (2026-10-22)

- **Version:** 3 (up from 2); publishedAt: 2026-10-22; schemaVersion stays 1.
- **List:** 14 added providers from V2ray Tunnel Plus through UT Loop Pro VPN, each shown with a check mark. The 14 names are grouped into two multi-line entries (7 + 7) to respect the existing 12-item limit, 320-character descriptions, 16 KiB JSON cap and the scrollable Android dialogue.
- **Message:** the updated Server VPN catalog can be downloaded; users with automatic catalog updates disabled can choose the manual refresh button.
- **Availability disclaimer:** EUT VPN, ProNeet VPN and UT Loop Pro VPN are visible but their remote downloads remain unavailable, and no provider is promised functionality without its official broker. The server VPN catalog minimum stays at 31 / 33 cards; the separate editorial news version increments to 3.
- **Delivery:** when deployed to the VPS, eligible Cloud clients with consent receive the new in-app notice on their next online open/resume, once per version. This is **not an Android OS push** and cannot reach clients that never open or reconnect.
- **VPS override:** if `CLOUD_WHATS_NEW_JSON` is set in `/etc/spdecode/cloud.env`, the override replaces the bundled v3 JSON. Clear or update it securely before deployment; `spdecode config set` does not support this key. Do not print private environment values.
- **Verification:** `POST /api/v1/whats-new` with `{"knownVersion":2,"locale":"es"}` must return localized version 3 and three entries. Request version 3 to confirm `unchanged:true`. Also confirm all 14 locale tags on the API.

## Publication v2 — historical server news (three items only)

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


## Actualización editorial v5 — 26 de octubre de 2026

Publicación preparada en `cloud/web/content/whats-new.json` para los **14 idiomas**
(`en,es,ar,fa,fr,id,ru,de,pt-BR,tr,vi,hi,ja,it`), `version:5`,
independiente de `CATALOG_VERSION:54`.

Contiene tres avisos breves: (1) lectura más completa de archivos históricos
`.hat` con catálogo remoto HA aún pendiente; (2) HTTP Custom Cloud con
referencias `hccloud://` para el editor de textos de APK antiguos y límites
para enlaces caducados/credenciales; (3) actualización a **SP-DECODE 1.1.20**,
descarga para usuarios del canal `https://t.me/GhostDeve/377`, actualización
para testers desde Google Play Store y **sin reinstalar** cuando ya usan 1.1.20.

Los enlaces se publican como **texto simple** dentro de las descripciones, no
como HTML ni como destinos ejecutables configurados por el servidor. La
versión antigua de Android interpreta solamente texto localizado.

**Importante al desplegar:** `CLOUD_WHATS_NEW_JSON` tiene prioridad sobre el
archivo. Si existe un override con notas v4, actualizarlo a v5 o desactivarlo;
de otro modo los usuarios seguirán recibiendo novedades obsoletas pese a que
el repositorio tenga v5. Verificar que `POST /api/v1/whats-new` con
`{"knownVersion":4,"locale":"es"}` devuelve la versión 5. No subir la
versión en producción hasta que los métodos Cloud anunciados estén
desplegados y validados.
