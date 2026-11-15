# SP-DECODE Online — Android Google sign-in and streamlined legal UX

Branch: `ci/unity-ads-online-qa` (Unity Ads signed APK).
Do **not** change secrets, signing key, package ID, Unity Ads pacing or Google Play update configuration.

## Why web login may succeed while Android login fails

Web Google OAuth uses a Google **Web** OAuth client and a redirect/callback URL.
Android native Credential Manager also requires a matching Google **Android**
OAuth client in the same Google Cloud project, registered with both:
- Android package: `com.ghostdeveloper.spdecode`
- APK **production/QA signing certificate SHA-1**:
  `CF:4E:E9:F0:EE:DB:D3:D6:D9:60:D2:58:DE:3D:EF:58:30:49:81:16`
  (extracted from `META-INF/CERT.RSA` of the downloaded signed
  `SP-DECODE-Online-1.1.27-b42-Tienda-Cuenta-Login-UnityAds-FIRMADA.apk`).
- Google **Web** Client ID is still passed to `GetGoogleIdOption.setServerClientId`.
  Never put `GOOGLE_CLIENT_SECRET` in the app.
- Add a separate Google Play App Signing certificate fingerprint if the store
  signs AAB installs with a different certificate.

The actual registered Google Cloud credentials are not readable from this
repository; a working web login **does not verify** these Android settings.
Use Google Cloud Console > APIs & Services > Credentials > Create credentials >
OAuth client ID > Android, and check the SHA and package. Do not create a second
unrelated Google Cloud project.

## Server/API contract

Mobile GET `https://spdecode.xyz/api/auth/native-config` must return:
`{ "enabled": true, "googleWebClientId": "...apps.googleusercontent.com" }`.
The public client ID is not secret. Response should not expose the client
secret. The server must deploy the native auth route from this branch.
POST `/api/auth/sign-in/social` sends a signed Google ID token to Better Auth
and uses its returned bearer session token. The app stores the bearer token
encrypted with Android Keystore and requests `GET /api/account` afterward.
If the server returns `NATIVE_AUTH_NOT_DEPLOYED`, deploy the web service code;
do not disable CSRF, Google ID token verification, or secure cookies.

The Android app fixes the Credential Manager Activity context, exposes only
sanitized error **codes** after failure, ignores user-cancelled sign-in,
and preserves the distinction between a verified session and login UI.

## UX

Single consent row with checkbox and inline, individually clickable
`Terms of Service` and `Privacy Policy` words, localized with the app.
Each link still opens the official SP-DECODE policy page using existing
Android legal navigation. No duplicate buttons below the consent.
The screen uses a reduced SP-DECODE wordmark, compact Unity-like typography,
no giant fingerprint hero and no redundant footer paragraph.

## Validation on physical device

1. Install the newly signed APK over the existing build.
2. In login, click inline Terms and Privacy separately, return to the app and
   check the checkbox.
3. Tap Google and check Android account chooser; never enter a Google password
   into a custom app text field.
4. If a failure appears, record **only its diagnostic code**, not ID tokens,
   passwords, screenshots containing tokens, or session cookies.
5. Verify successful session via in-app Account > Overview, then Sign out.
6. Repeat after process restart, then with airplane mode and cancelled Google
   selection. Confirm no credentials are exposed.

## Outcome status

Code and signed CI build can be validated automatically. Actual login cannot
be claimed until: (1) Android OAuth client registration is confirmed in Google
Cloud; (2) native auth server routes are deployed to the VPS; (3) on-device
Google selection and signed-in account fetch pass.
