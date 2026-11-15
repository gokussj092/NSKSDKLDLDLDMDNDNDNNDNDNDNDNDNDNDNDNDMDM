# JNI exports resolve these names after R8. Preserve only this boundary.
-keep class com.ghostdeveloper.spdecode.admin.NativeAdminRoutes { *; }
-keepclasseswithmembernames,includedescriptorclasses class * { native <methods>; }
-keepattributes Signature,InnerClasses,EnclosingMethod
