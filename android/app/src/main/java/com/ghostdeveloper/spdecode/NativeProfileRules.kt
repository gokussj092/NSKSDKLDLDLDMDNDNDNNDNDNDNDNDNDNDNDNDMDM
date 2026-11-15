package com.ghostdeveloper.spdecode

/** Profile input checks are C++/JNI; PostgreSQL still enforces canonical uniqueness. */
object NativeProfileRules {
    init { System.loadLibrary("spdecode_profile") }
    external fun validUsername(value:String):Boolean
    external fun validDisplayName(value:String):Boolean
}
