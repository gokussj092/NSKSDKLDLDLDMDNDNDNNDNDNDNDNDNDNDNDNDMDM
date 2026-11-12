# SP-DECODE Online QA: native account, store and API IP provisioning

Date: 2026-11-12. **Authoritative source branch: `ci/unity-ads-online-qa`.**
Build: Android Online QA APK v1.1.27 (42), Unity LevelPlay ads and permanent signing key preserved. This work is not part of the separate `feat/nuevas-integraciones` integration workflow.

## UI implemented
- Native `AccountDrawer` goes to `NativeCommerceScreens`, not a WebView/website.
- `NativeStoreCatalog.kt` performs a bounded GET to the server's public `/api/store/catalog`. Only `plans[].prices.USD` integer cents are displayed, and server `available` gates add-to-cart. Missing or failed catalog fetch means no invented price. The server re-quotes any final payment.
- Products exposed: APK analysis credit packages, commercial API, and $1/30-day ad removal preview only. No Offline license in the mobile store.
- The $1 ad-removal **purchase is disabled**, because the server lacks a fully verified ad-free product/entitlement. No false entitlement is created.
- API detail lists: file decoding, text decoding, online methods and catalog decoding. APK/APKS **application analysis is excluded**.
- Native Android store/account/login surfaces use `CommerceI18n`/ `CommerceLanguageData`, including all locales shipped in `android/app/src/main/res/values*/strings.xml`: en, es, pt, fr, de, it, ru, tr, ar, fa, hi, ja, id, vi.
- IP input placeholder `195.233.233.12` is an **example** of a public VPS IPv4. It is editable, accepts general public IPv4/IPv6, and rejects private/malformed addresses; not limited to `8.8.8.8` or `1.1.1.1`.
- API may be placed in cart without an IP. Purchased API **cannot be claimed/used** until a public IP is bound to the entitlement. Account holder may update the IP afterwards; old IP loses authorization immediately.

## Server source contract, not deployed by this GitHub commit
- `cloud/web/lib/commerce/catalog.mjs`: optional `allowedIp` for API purchase, strictly checked if supplied.
- `cloud/web/lib/commerce/orders.mjs`: `claim()` refuses to mint unrestricted API key; `updateApiAllowedIp()` changes authorized IP for authenticated owner, checks license state/expiry/payment mode, and audits.
- `PATCH /api/account/api-ip`: requires valid `Origin`, **fresh** Better Auth session, and entitlement owner.
- `cloud/web/lib/commerce/auth.mjs`: Better Auth Bearer plugin allows API session authentication; Google signed ID token flow used by Android Credential Manager.
- `GET /api/auth/native-config` exposes only public Google OAuth Web Client ID when accounts configured. Google **client secret is never shipped to the app**.
- Android `NativeCommerceAuth.kt` obtains an ID token with Google Credential Manager, submits it via the Better Auth social endpoint, and stores returned bearer token encrypted using Android Keystore AES-GCM; no WebView, injected Google form or local raw API key.
- User must explicitly accept localized Terms and Privacy Policy (with legal document access) before a login request can be sent.

## Existing feature gaps; do not misrepresent as production-ready
1. No backend deployment has occurred in this QA code task; the running VPS may still use older auth/store routes. Test deployment must happen separately with database backup and migrations checked.
2. No successful real signed-in user-device end-to-end tests, no provider payment test checkout, and no confirmed fulfillment webhook from this session.
3. Current commercial `POST /api/commercial/v1/decode` routes **file** processing. The UI promises prospective text/online/catalog API services, but those commercial operations still require separate server implementation and tests before being advertised as fully functional.
4. A password-based account flow is deliberately **disabled** (`emailAndPassword.enabled=false`). Secure password creation for Google accounts needs verified-email ownership, account linking, password resets, abuse controls and audit logs. Do not silently turn it on.
5. UI cart still has checkout deliberately disabled. Server product availability, payment provider, taxes, customer consent and quote must all be revalidated at the time of purchase. USD is the Android display currency, no implicit FX conversion.
6. Ad removal is **preview only** until server grants an authenticated 30-day entitlement and the Android ad-load checks honor that entitlement in Unity LevelPlay. No purchase of ads waiver may be offered before that is tested.

## Required QA for launch
- Confirm exact Android package name and certificate fingerprints used for Google OAuth Android credential selection; issue server-audience ID tokens to the configured Web OAuth Client ID.
- Configure server env: `SPDECODE_ACCOUNTS_ENABLED`, database URL/schema, `BETTER_AUTH_SECRET` (>=32 bytes), `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `CLOUD_SITE_PUBLIC_ORIGIN`, correct HTTPS routes/proxies.
- Test `sign-in/social` with verified ID token, bearer `set-auth-token` issuance, authenticated `GET /api/account`, `sign-out`, and expired/revoked tokens.
- Verify the user can buy API **without IP** in test payment mode, but cannot claim/use before binding a public IP; after binding, rotate IP and confirm old IP rejected and new IP accepted; invalid IPs must be rejected server-side.
- Check the public USD catalog from Android with absent products, disabled products, tampered prices and network failures; all must fail closed.
- Test all 14 selected languages, input on Android keyboard, orientation restoration, app reopen, and current Unity Ads behavior.
- Keep release APK signed with the persistent keystore, **without** Play-update AAB marker, and test actual device before shipping to end users.

Official references: https://better-auth.com/docs/authentication/google ; https://better-auth.com/docs/plugins/bearer ; https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation
