# SP-DECODE Online — Google native sign-in audit (2026-11-20)

## Verified in source
- The Google account chooser is Android Credential Manager; it obtains an ID token and POSTs to `https://spdecode.xyz/api/auth/sign-in/social`. After a bearer is issued, Android checks `GET /api/account`. The Python decoding worker is **not involved**.
- Both APK and Play AAB use the same auth implementation, but Google Play re-signs installed AAB-derived APKs with its **app signing** certificate. This may differ from the certificate stored in GitHub Secrets for APK/upload signing.
- Previously the Android UI silently discarded `GOOGLE_SIGN_IN_CANCELLED`. A provider that closes its picker after selecting an account can appear to do nothing. The user now sees the bounded diagnostic code, including cancellation.
- The client now parses top-level Better Auth error codes as well as nested SP-DECODE error codes, and requires explicit successful account confirmation during login. Normal background account refresh remains outage-tolerant.
- The new CI probe checks only **unauthenticated public** requests. Source reviews and CI builds **cannot** prove registration of a Google OAuth client or successful on-device sign-in.

## Google Cloud configuration: mandatory independent checks
1. Google Play Console > App integrity > **App signing key certificate**. Copy its **SHA-1** (not SHA-256, not upload certificate).
2. In the **same Google Cloud project** as the Web OAuth client served by `GET /api/auth/native-config`, register/verify an Android OAuth client with package `com.ghostdeveloper.spdecode` and this Play app-signing SHA-1.
3. Also register/verify a second Android OAuth client for the **standalone signed APK** using the certificate of its actual installed APK. A historical QA APK SHA-1 is `CF:4E:E9:F0:EE:DB:D3:D6:D9:60:D2:58:DE:3D:EF:58:30:49:81:16`; confirm against current APK before relying on it.
4. Keep the Web OAuth Client ID on the backend as `GOOGLE_CLIENT_ID`; this same public ID is used with `GetSignInWithGoogleOption.Builder(clientId)`. Never put the Google client secret into Android, a public response, or Git.
5. The pinned **SHA-256** app signing certificate in the AAB build checks distribution integrity, but cannot be substituted for the **SHA-1** required by Android OAuth client registration.

## Server triage
- Public `GET https://spdecode.xyz/api/auth/native-config`: expect 200 JSON, `enabled:true`, valid public `googleWebClientId`.
- Public `GET https://spdecode.xyz/api/account` without credentials: expect 200 JSON, `authEnabled:true`, `user:null`.
- If selecting Google fails and the VPS logs contain **no** `/api/auth/sign-in/social` request, suspect Android Credential Manager, Play Services or Android OAuth SHA-1 registration **before** the server.
- If POST reaches the server but returns 4xx/5xx, inspect web-service Better Auth and PostgreSQL logs, OAuth Web ID/secret, migrations, reverse proxy and CSRF origin contract. Never print real tokens, cookies, secrets or user data.
- Worker Python, VPN decoders, HPKE V2 and Play Integrity are separate from this commerce account sign-in route; they must not be modified to fix Google OAuth.

## Changes and verification
- Android login surfaces Google provider cancellation and server error codes rather than silently doing nothing.
- Authentication responses are parsed safely; session confirmation after Google and email login is strict, but periodic refresh is tolerant.
- New public probe: `python3 scripts/ci/probe_native_google_auth.py`; regression: `python3 -m unittest tests.test_native_google_auth_contract -v`. It never performs a real sign-in.
- Diagnostic build: 1.1.31, versionCode 46. Preserve both distribution builds, `spdecodePlayAab=true` only for Play AAB, Unity Ads, R8, 14 locales, GitHub persistent signing and existing security controls.
- Do not claim the issue fixed end to end until the correct Play signing SHA-1 is registered **and** an actual Play-installed Google account successfully signs in, session survives restart, and the APK path is separately tested. Do not automatically publish.
