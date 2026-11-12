# SP-DECODE R8 production rules.
# Release decoder algorithms are optimized/obfuscated; do NOT keep entire app
# packages because this would defeat the purpose of R8 hardening.

# Retain generic signatures and JSON annotations used by library adapters.
-keepattributes Signature,*Annotation*,InnerClasses,EnclosingMethod
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# Room loads <DatabaseClass>_Impl by reflection. Preserve its runtime name
# and generated members, otherwise a minified APK may open with a broken
# encrypted history provider. Entity retention preserves Room schema IDs.
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }

# Providers/Activities referenced by AndroidManifest are managed by AGP's
# manifest keep rules; no broad -keep com.ghostdeveloper.spdecode.**
# Signer public digest is not a secret. Bundled format keys remain reversible;
# R8 is defense in depth, not a cryptographic secret vault.

# JNI_OnLoad registers exactly this private bridge by name and descriptor.
-keepclasseswithmembers,includedescriptorclasses class com.ghostdeveloper.spdecode.cloud.CloudNativeTransport {
    native <methods>;
}

# Native Keystore orchestrator resolves these platform-only bridges by name.
# Keep the class and only the @JvmStatic API required by JNI reflection.
-keep class com.ghostdeveloper.spdecode.cloud.CloudKeystorePlatform {
    public static *;
}

# Native catalog HTTP receive loop resolves this Kotlin @JvmStatic callback by
# literal JNI name/signature. Prevent R8 from removing or renaming it in release.
-keepclassmembers class com.ghostdeveloper.spdecode.cloud.CloudNativeTransport {
    public static void onCatalogTransferProgress(long, long);
}

# Offline JNI bridge uses exported name-based symbols, even in R8 release.
-keepclasseswithmembers,includedescriptorclasses class com.ghostdeveloper.spdecode.offline.NativeOffline {
    native <methods>;
}

# JNI profile validator uses name-based symbols in all online release ABIs.
-keepclasseswithmembers,includedescriptorclasses class com.ghostdeveloper.spdecode.NativeProfileRules {
    native <methods>;
}

# Native ad-free projection validation; never keep broad commercial packages.
-keepclasseswithmembers,includedescriptorclasses class com.ghostdeveloper.spdecode.NativeAdsGate {
    native <methods>;
}
