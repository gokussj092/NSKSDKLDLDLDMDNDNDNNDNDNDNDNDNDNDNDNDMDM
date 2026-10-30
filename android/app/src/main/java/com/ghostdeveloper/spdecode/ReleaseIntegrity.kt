package com.ghostdeveloper.spdecode

import android.content.Context
import com.ghostdeveloper.spdecode.cloud.CloudNativeTransport

/**
 * JNI adapter only: package identity, debugger and signing-certificate
 * evaluation execute inside libspdecode.so through Android system APIs.
 * Backend Play Integrity and hardware attestation remain independent.
 */
internal object ReleaseIntegrity {
    fun isTrusted(context: Context): Boolean = CloudNativeTransport.verifyReleaseSigner(
        context, BuildConfig.APPLICATION_ID, BuildConfig.TRUSTED_SIGNER_SHA256,
        BuildConfig.PLAY_APP_SIGNER_SHA256, BuildConfig.DEBUG
    )
}
