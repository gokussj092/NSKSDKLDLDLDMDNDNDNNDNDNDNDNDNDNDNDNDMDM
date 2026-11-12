# SP-DECODE Online — AdMob approved account, Android production readiness

Date: 2026-11-12 UTC. Source: developer's November 11 Google AdMob
account-approval email and implementation instructions, and repository audit.
This is a release checklist, **not evidence of app approval or deployment**.

## Verified from AdMob emails
- Account **approved and ready to use**. Publisher ID:
  `pub-6771239583897519`.
- SP-DECODE Android AdMob App ID:
  `ca-app-pub-6771239583897519~8354694124`.
- AdMob interstitial ad unit:
  `ca-app-pub-6771239583897519/1146947081`.
- No email demonstrated an approved public application or production ad serving.

## Repository audit
- Android Online currently uses Unity LevelPlay for one interstitial flow
  with Unity Ads adapter and Google UMP consent. The AdMob App ID is passed
  for consent; the AdMob interstitial ad unit is not connected as a live
  mediated network.
- Existing `cloud/web/public/app-ads.txt` contains Unity/LevelPlay entries
  and Google reseller accounts, but **not** the developer's own AdMob
  `pub-6771239583897519` DIRECT row. Do not overwrite this large list.
  Once the AdMob network is configured, add and validate the authorized
  Google entry in the source, serve it from the root site, and confirm
  AdMob dashboard verification. Check which automation updates the file.
- `ci/unity-ads-online-qa` produces a **signed QA APK**, uses the
  per-file advertising QA switch, and explicitly does not produce a Play AAB.
  This is not a production-upload candidate.

## Production release checklist (do not skip)
1. Test the saved Telegram decryption-credit states: blank > save > reload >
   edit > cancel > edit > save > remove > reload > share with default.
   Test copying V2Ray from a real successful decode and masks.
2. Confirm interstitial test delivery and return to app on physical Android;
   no excessive ads and no decoding-result loss. Preserve UMP opt-out and
   ads privacy settings.
3. In Unity LevelPlay, configure AdMob under Setup > Networks if the team
   chooses to mediate Google ad demand; install the version-compatible AdMob
   adapter for the **native Android** project. Do not independently show
   AdMob interstitials and LevelPlay interstitials for the same event.
   Use Google/Unity test ads before live serving.
4. Publish a supported store listing and link it in AdMob; pass per-app
   readiness review. **Account approval alone is insufficient**.
5. Add the authorized app-ads.txt publisher line (from the AdMob dashboard)
   to the existing sellers list; verify public domain/app-store contact.
6. Check Google Play Console developer eligibility. If a personal developer
   account created after 2023-11-13, obtain 12 opted-in closed testers for
   14 continuous days and apply for production access.
7. Finish Play declarations: Data safety, ads, content rating, target audience,
   account/trader status, privacy policy, permissions and support links.
   Google notified developer on 2026-11-04 of a trader-status declaration
   deadline of **2027-02-01**.
8. Produce **separate** Play AAB with Play In-App Updates compiled in, and
   external APK with Play updater absent. Keep a persistent signing identity;
   increment versionCode only for an authorized public release; validate
   compatibility with existing installation signatures.
9. Verify release CI, package contents, key attestation, public API and error
   reports, consent paths and real-device smoke tests. Only then promote
   release tags, store listing and production channels.

## Official references
- AdMob app setup: https://support.google.com/admob/answer/9989980
- App readiness: https://support.google.com/admob/answer/10564477
- LevelPlay AdMob adapter:
  https://docs.unity.com/en-us/grow/levelplay/sdk/android/networks/guides/google-admob
- Android networks: https://docs.unity.com/en-us/grow/levelplay/sdk/android/mediation-networks
- Google app-ads.txt: https://developers.google.com/admob/android/app-ads
- Play testing: https://support.google.com/googleplay/android-developer/answer/14151465

No keystore passwords, platform secrets, email addresses or private APK
configuration data belong in this file.
