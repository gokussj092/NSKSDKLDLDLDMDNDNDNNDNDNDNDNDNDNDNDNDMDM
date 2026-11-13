# C10 — Server VPN catalog updates using only the SP-DECODE VPS

> **Futura revisión C-V2 (solo documentación):** [Especificación integral de descarga fragmentada/reanudable, total real, motor nativo JSON y doble versionado](CATALOG_SERVER_VPN_RESUMABLE_NATIVE_ENGINE_PLAN_2026_11_04.md). El contrato C10 actual sigue vigente para APKs publicadas.

## Architecture (no Firebase or accounts)

- On each foreground entry Android performs one version-only POST to the VPS watch endpoint using `knownVersion=0`, causing an immediate response. This works without the opt-in background-sync toggle after cloud legal consent. It does not download the catalog or its icons. Active sessions use bounded VPS HTTPS long-poll so the server replies when a newer version is deployed. The optional 24-hour WorkManager recovery remains gated by the user's background-sync preference.
- The dialog offers **Update now** or **Cancel**; cancelling requires a second warning about missing new catalog capabilities. A cancelled version is deferred for 24 hours, not hidden forever, and a newer version can be offered immediately. The two screens are localized in all 14 Android languages.
- Network delivery is not a zero-request remote push to a closed phone. The server signals through an active HTTPS long-poll; a fresh app opening checks the VPS version once to recover a missed change. No Firebase is used for catalog alerts.

- The own VPS endpoint `POST /api/v1/server-vpn/watch` holds a bounded HTTPS request (up to 12 seconds), accepts only `{"knownVersion":N}`, and returns only the current public version and whether it changed. One application instance watches only **while visible and cloud legal consent is active**. Concurrent requests are capped server-side, and the client applies a delay/backoff. No raw device identifier, FCM token, file, password or provider URL is required.
- Existing `POST /api/v1/server-vpn/catalog` remains authoritative. It responds with `unchanged:true` if the version matches, avoiding full catalog download.
- After the version increases, the client fetches catalog metadata and any changed icons over native C++ HTTPS, checks PNG SHA-256 hashes, prevents rollback, and activates only the verified encrypted cache snapshot.
- In the background **no permanent socket is held**. Opted-in users receive a 24-hour network-constrained WorkManager recovery check. With automatic updates enabled, opening the app or entering Server VPN checks/downloads updates and the visible VPS watch reacts to new versions. Without background opt-in, opening/resuming checks **only the catalog version** over foreground HTTPS and reads the verified encrypted cache; downloaded data still requires explicit confirmation. OS restrictions may defer the periodic job.
- The Android Settings toggle controls 24-hour background catalog recovery; foreground version checks and visible VPS long-poll run after cloud legal consent independently of that background setting. It defaults off and can be revoked. Without opt-in, the manual refresh button in the Server VPN header checks **version only** using the VPS watch endpoint with knownVersion=0 (immediate response); if newer, the user explicitly confirms the download. No version change displays an up-to-date notice; failures preserve the verified encrypted cache. Language copies and privacy notices have been updated.
- The administrative catalog page can record the currently deployed monotonic version for auditing. It does **not** claim to deliver messages to closed devices. There is no external push gateway, paid service, Redis client-token registry or Firebase credential.

## VPS deployment

1. Deploy the updated Cloud web and Android application using the existing VPS Docker Compose setup. There is no `catalog-push` container and **no FCM configuration**. Use the same HTTPS domain already configured for the Cloud API.
2. When provider metadata or icons change, increment `CLOUD_SERVER_VPN_CATALOG_VERSION` monotonically and deploy the matching web application and metadata together. Never announce a version before its metadata is live.
3. Confirm POST `/api/v1/server-vpn/watch` returns a version immediately for a stale `knownVersion` and a bounded unchanged response when current. Test malformed bodies, disconnects and concurrent client cap.
4. Test a connected device with the app open, background scheduling enabled/disabled, offline recovery, Doze mode, reboot, HTTPS errors, invalid icon SHA-256, version rollback and cancellation on leaving the app. Actual background timing is controlled by Android.
5. Confirm Privacy Policy and Play Console Data safety information reflects real HTTPS/server request processing. No device messaging tokens are collected by SP-DECODE.

## Limitations

Direct VPS HTTP long-poll is a real-time signal for **active clients**. It cannot wake an arbitrary Android app that has been terminated or force-stopped. WorkManager and app-resume checks repair missed updates; no guarantee of instant system notifications when closed. This method introduces no additional commercial messaging service.
