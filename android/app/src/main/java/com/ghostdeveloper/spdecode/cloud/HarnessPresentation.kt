package com.ghostdeveloper.spdecode.cloud

/** Display/transfer rules shared by the screen and durable upload worker. */
internal object HarnessPresentation {
    const val TRANSFER_PREFS = "spdecode-catalog-sync"
    const val TRANSFER_KEY = "download-by-chunks"

    fun text(value: String?): String? = value?.trim()?.takeUnless {
        it.isEmpty() || it.equals("null", ignoreCase = true)
    }

    fun name(appName: String?, filename: String?, packageName: String?): String =
        text(appName) ?: text(filename)?.substringAfterLast('/')
            ?.replace(Regex("(?i)\\.apks?$"), "")?.takeIf { it.isNotBlank() }
            ?: text(packageName) ?: "APK"

    // Normal transfers send the next encrypted frame immediately. The V2
    // protocol still limits each frame to 2 MiB; both modes keep checkpoints.
    fun pauseMillis(chunked: Boolean): Long = if (chunked) 4_500L else 0L

    fun stage(status: String?, phase: String?): String = when (status) {
        "COMPLETED", "COMPLETED_PARTIAL", "FAILED", "REJECTED", "EXPIRED" -> status
        "UPLOADING" -> "UPLOADING"
        "UPLOADED" -> "VALIDATING"
        "QUEUED_FOR_ANALYSIS" -> "QUEUED"
        "AWAITING_HUMAN" -> "REVIEW"
        else -> when (phase) {
            "APK_METADATA_INSPECTION" -> "METADATA"
            "DEX_BYTECODE_INSPECTION", "DEX_RECOVERY", "CODE_DECOMPILATION" -> "CODE"
            "BINARY_ANALYSIS", "NATIVE_LIBRARY_INSPECTION" -> "NATIVE"
            "CRYPTO_EVIDENCE_CORRELATION", "METHOD_DECODING" -> "METHODS"
            "CATALOG_BUILDING", "CATALOG_CANDIDATE_FOUND" -> "CATALOG"
            "REPORT_PREPARATION", "REPORT_READY", "RESULT_PREPARATION" -> "RESULTS"
            "COMPONENT_INSPECTION", "COMPONENTS_INSPECTED", "PACKAGE_VALIDATION", "PACKAGE_VALIDATED" -> "VALIDATING"
            else -> if (status == "ANALYZING") "ANALYZING" else "PREPARING"
        }
    }
}
