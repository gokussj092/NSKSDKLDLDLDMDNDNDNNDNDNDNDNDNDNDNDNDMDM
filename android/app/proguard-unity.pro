# Only included by the explicit Online Unity build. Offline never reads this file.
-keep class com.ironsource.** { *; }
-keep class com.unity3d.** { *; }
-keep class com.iab.omid.** { *; }
-keepattributes JavascriptInterface
-keepclassmembers class * { @android.webkit.JavascriptInterface <methods>; }

# Constructed reflectively in Cloud builds; R8 must retain its binary name.
-keep class com.ghostdeveloper.spdecode.ads.UnityInterstitialHost { *; }
