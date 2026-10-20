# C10 — Server VPN catalog updates (planned deployment)

## What the implementation does

The existing `POST /api/v1/server-vpn/catalog` remains the **authoritative version and metadata endpoint**. Responses are delivered over the already configured HTTPS native C++ transport, with original PNG SHA-256 validation and encrypted device cache; vendor URLs and decryption secrets are never sent in push payloads.

**Primary signal (optional):** a private `catalog-push` Docker service reads the server's monotonically increasing `CLOUD_SERVER_VPN_CATALOG_VERSION` every five minutes. It publishes `{type:"catalog_update",catalogVersion:"N"}` with FCM HTTP v1 to a single topic. It stores only the last advertised version in Redis, not individual device tokens. This is metadata notification, **not a user-visible notification**; no `POST_NOTIFICATIONS` permission is needed.

**Android:** subscribes to the topic only after a separate opt-in for catalog update notifications. A Firebase data message schedules a constrained WorkManager job. The worker reads the version and downloads the new catalog **only if the server's version is newer**; new icons are SHA-256 checked before atomic cache activation. No push message can provide a URL or inject catalog content.

**Missed update recovery:** if a push is delayed, blocked by system battery policy, or dropped, an infrequent WorkManager fallback checks the small version response while notifications are opted in. Opening the app/Server VPN additionally checks versions under a short rate limit. The catalog is **not downloaded every 24 hours**. Neither push nor WorkManager guarantees an exact execution time.

## Setup (not completed by this commit)

1. Create a Firebase project and Android app for the **exact SP-DECODE package** and configure Cloud Messaging. The Firebase project ID, Android App ID, API key and Sender ID are **public client identifiers**, not an authorization secret. Build Cloud Android with `SPDECODE_FCM_PROJECT_ID`, `SPDECODE_FCM_APP_ID`, `SPDECODE_FCM_API_KEY`, `SPDECODE_FCM_SENDER_ID`. QA/test builds without these values run the normal foreground version check, with push disabled.
2. Create an **FCM sender service account** with minimum required Firebase Messaging send permission; supply its JSON privately as `CLOUD_FCM_SERVICE_ACCOUNT_JSON` only to server containers, with `CLOUD_FCM_PROJECT_ID` and `CLOUD_FCM_ENABLED=true`. Do **not** commit or bundle service-account JSON.
3. Deploy web and start the watcher with `docker compose --profile catalog-push up -d --build`. Check the watcher service health and safe logs. The watcher exits without touching Redis if FCM is unconfigured.
4. Increment `CLOUD_SERVER_VPN_CATALOG_VERSION` monotonically when the provider roster, icon or availability metadata changes; redeploy with the new value. Never increment the env version before the corresponding web metadata is live. The watcher publishes the new version within its next scheduled check. The admin-only `POST /api/admin/catalog-push` can manually retry the same publication, with CSRF and admin-session checks.
5. Test two Android devices (one online, one offline), message delay/Doze, opt-in and opt-out, stale version, rollback, invalid icon digest, app relaunch and device reboot. Verify no secrets, raw tokens, source files or HWIDs are stored on your SP-DECODE server.

### Operational constraints

FCM delivery depends on Google Play services, user consent, Google networking and device restrictions. It is not guaranteed in all regions. The only channel that works without Firebase setup is foreground/background recovery against the version endpoint. First ensure the new privacy notice accurately explains the optional Google Cloud Messaging integration. The C10 CI tests simulate push and recovery; **they are not evidence of a live FCM delivery to a physical phone**.

If Google Play devices are blocked from FCM in a region, the version-check recovery path remains available, not immediate server-initiated delivery.
