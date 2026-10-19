package com.ghostdeveloper.spdecode.cloud

/**
 * Ephemeral QA enrollment. Deliberately never stored in SharedPreferences,
 * Room, Android backup, logs, source assets or BuildConfig.
 */
internal object CloudQaMemory {
    private var credential = ""

    @Synchronized fun set(value:String) {
        require(value.isEmpty() ||
            value.matches(Regex("spqa-[A-Za-z0-9_-]{40,64}"))) { "CLOUD_INVALID_QA_CODE" }
        credential = value
    }

    @Synchronized fun get():String = credential
    @Synchronized fun clear() { credential = "" }
}
