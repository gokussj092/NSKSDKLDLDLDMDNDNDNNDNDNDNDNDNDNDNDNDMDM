package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import com.ghostdeveloper.spdecode.BuildConfig
import com.ghostdeveloper.spdecode.R
import java.io.IOException

/**
 * Friendly, localized classification of Cloud failures.
 * Never include URLs, routes, request bodies, provider secrets, exception
 * messages or stack traces in user-visible text. Codes are shown only in QA.
 */
internal object CloudUserErrors {
    private fun resource(cause:Throwable):Int {
        if(cause is CloudDecodeClient.Failure) {
            return when(cause.code) {
                "NPVS_PROTECTION_UNSUPPORTED" -> R.string.npvs_private_key_unsupported
                "PASSWORD_REQUIRED" -> R.string.cloud_failure_password
                "HWID_REQUIRED" -> R.string.cloud_failure_hwid
                "HWID_PASSWORD_REQUIRED" -> R.string.cloud_failure_both
                "AUTH_FAILED", "INVALID_CREDENTIALS" -> R.string.cloud_failure_credentials
                "LEGAL_CONSENT_REQUIRED","USER_CONSENT_REQUIRED" -> R.string.cloud_failure_consent
                "QA_DISABLED","QA_ACCESS_DENIED" -> R.string.cloud_failure_qa
                "INTEGRITY_REJECTED" -> R.string.cloud_failure_integrity
                "UNAUTHORIZED","EXPIRED_CHALLENGE" -> R.string.cloud_failure_session
                "RATE_LIMITED" -> R.string.cloud_failure_rate
                "INPUT_TOO_LARGE","OUTPUT_TOO_LARGE","REMOTE_TOO_LARGE" -> R.string.cloud_failure_large
                "INVALID_INPUT","INVALID_BASE64","INVALID_REQUEST","INVALID_REFERENCE" -> R.string.cloud_failure_invalid
                "UNSUPPORTED_FORMAT" -> R.string.cloud_failure_unsupported
                "DECODE_FAILED","REMOTE_DECODER_FAILED","OUTPUT_INVALID","OUTPUT_INVALID_UTF8" ->
                    R.string.cloud_failure_decode
                "ENGINE_TIMEOUT" -> R.string.cloud_failure_timeout
                "SERVICE_MAINTENANCE" -> R.string.cloud_failure_maintenance
                "REMOTE_CONFIG_UNAVAILABLE" -> R.string.cloud_failure_config_unavailable
                "ENGINE_UNAVAILABLE","REMOTE_NOT_CONFIGURED","REMOTE_PROVIDER_UNAVAILABLE" ->
                    R.string.cloud_failure_unavailable
                "REMOTE_INTEGRITY_FAILED","REMOTE_RESPONSE_INVALID","REMOTE_NETWORK_DENIED" ->
                    R.string.cloud_failure_remote
                else -> when(cause.httpStatus) {
                    400,422 -> R.string.cloud_failure_invalid
                    401 -> R.string.cloud_failure_session
                    403 -> R.string.cloud_failure_forbidden
                    404 -> R.string.cloud_failure_not_found
                    408,504 -> R.string.cloud_failure_timeout
                    409 -> R.string.cloud_failure_conflict
                    413 -> R.string.cloud_failure_large
                    429 -> R.string.cloud_failure_rate
                    500,502,503 -> R.string.cloud_failure_unavailable
                    else -> R.string.cloud_failure_general
                }
            }
        }
        if(cause is IOException) return when(cause.message) {
            "CLOUD_QA_CODE_REQUIRED" -> R.string.cloud_failure_qa_code
            "CLOUD_INTEGRITY_UNAVAILABLE" -> R.string.cloud_failure_integrity
            "CLOUD_INVALID_NONCE","CLOUD_INVALID_SESSION" -> R.string.cloud_failure_session
            "CLOUD_NATIVE_REQUEST_REJECTED","CLOUD_INVALID_INPUT","CLOUD_INVALID_FORMAT",
            "CLOUD_CREDENTIALS_NOT_ALLOWED" -> R.string.cloud_failure_invalid
            "CLOUD_NATIVE_RESPONSE_TOO_LARGE","CLOUD_RESULT_TOO_LARGE" -> R.string.cloud_failure_large
            "CLOUD_PARTIAL_RESULT_REJECTED","CLOUD_MISSING_RESULT","CLOUD_EMPTY_RESULT" ->
                R.string.cloud_failure_partial
            "CLOUD_NATIVE_TLS_REQUIRED","CLOUD_NATIVE_URL_REJECTED" -> R.string.cloud_failure_tls
            "CLOUD_NATIVE_NETWORK_UNAVAILABLE","CLOUD_NATIVE_CONNECT_FAILED",
            "CLOUD_NATIVE_UPLOAD_FAILED","CLOUD_NATIVE_READ_FAILED",
            "CLOUD_NATIVE_RESPONSE_UNAVAILABLE","CLOUD_NATIVE_EMPTY_RESPONSE" ->
                R.string.cloud_failure_network
            "CLOUD_INVALID_JSON","CLOUD_INVALID_HTTP_ENVELOPE","CLOUD_INVALID_HTTP_STATUS" ->
                R.string.cloud_failure_remote
            else -> R.string.cloud_failure_general
        }
        return R.string.cloud_failure_general
    }

    fun message(context:Context,cause:Throwable):String {
        val disconnected=cause is IOException &&
            cause !is CloudDecodeClient.Failure &&
            cause.message=="CLOUD_NATIVE_NETWORK_UNAVAILABLE"
        val id=if(disconnected) R.string.cloud_failure_offline else resource(cause)
        val text=context.getString(id)
        if(!BuildConfig.SPDECODE_QA_BUILD)return text
        // QA diagnostics contain only bounded, local enum-like values.
        val code=when(cause) {
            is CloudDecodeClient.Failure -> cause.code
            is IOException -> cause.message.orEmpty()
            else -> ""
        }
        val safe=code.takeIf { it.matches(Regex("[A-Z][A-Z0-9_]{2,63}")) }
            ?: "CLIENT_ERROR"
        val status=(cause as? CloudDecodeClient.Failure)?.httpStatus
        val detail=if(status!=null && status in 100..599) "$safe / HTTP $status" else safe
        return "$text\nQA: $detail"
    }
}
