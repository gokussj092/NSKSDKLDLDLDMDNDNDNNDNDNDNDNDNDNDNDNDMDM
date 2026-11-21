# SP-DECODE Android 17 Play-startup diagnostic (2026-11-20)

Branch: `ci/unity-ads-online-qa`. Candidate: **v1.1.31 / versionCode 46**.

## Hypothesis and isolated variable
Users report that the Telegram-signed APK opens on Android 17 but the Google Play-delivered install may close during launch. This build temporarily **omits Play In-App Updates from the AAB** to determine if the optional Play Core 2.1.0 startup host is involved. It is **not** a proven root cause.

## Build and what stays unchanged
The Play workflow runs `gradle -PspdecodeUnityAds=true -PspdecodePlayAab=true -PspdecodePlayUpdates=false -PspdecodeAdsEveryFileQa=false :app:testReleaseUnitTest :app:bundleRelease`.

- Omitted: `com.google.android.play:app-update:2.1.0`, updater-only lifecycle dependency, `PlayInAppUpdateHost.kt`, injected Compose updater UI and the Play-updates marker.
- Retained: Cloud decoders, Google authentication, Google Play Integrity verification, native signer verification, persistent upload keystore, Unity Ads, UMP, C++/JNI, R8, Firebase notices, 14-language support and standard AAB packaging.
- The older `play-beta-artifacts.yml` remains able to compile a Play AAB with updater enabled; only the production Play diagnostic workflow explicitly disables it. Do not confuse these artifacts.

## How to test
1. Upload the signed AAB from `SP-DECODE-ONLINE-PLAY-AAB-UNITYADS-SIGNED` to a **closed or internal Play testing track** (the workflow does not publish).
2. Install from **Google Play** on an affected Android 17 device; collect Android OS build, device model, package version and launch behavior.
3. Compare with previous Play build and external APK on the same device; do not change tester account or network conditions between comparisons.
4. If the new Play build still closes, inspect the native `ReleaseIntegrity.isTrusted` rejection (which invokes `finishAndRemoveTask()` silently) and the installed Play signing certificate; also capture `adb logcat -b crash` and system activity logs.
5. If the new Play build opens, Play In-App Updates becomes a strong suspect. A follow-up fix must make optional updater failures nonfatal before re-enabling it.

**No claim of Android 17 compatibility is made until device validation. No disabling of the app's native signer guard is performed.**
