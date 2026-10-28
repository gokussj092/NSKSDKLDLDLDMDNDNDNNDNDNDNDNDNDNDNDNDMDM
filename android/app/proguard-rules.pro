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
