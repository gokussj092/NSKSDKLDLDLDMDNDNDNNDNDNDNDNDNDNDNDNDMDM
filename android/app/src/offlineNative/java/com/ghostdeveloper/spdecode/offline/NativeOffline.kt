package com.ghostdeveloper.spdecode.offline

/** Only a JNI boundary. All decryption and key generation occur in native C++. */
internal object NativeOffline {
    init { System.loadLibrary("offdecode") }
    external fun decodeNative(input: ByteArray, suffix: String, password: String, hwid: String, recipient: String): ByteArray
    external fun generateIdentityNative(): String
}
