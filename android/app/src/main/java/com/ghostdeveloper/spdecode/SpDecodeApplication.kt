package com.ghostdeveloper.spdecode

import android.app.Application
import android.content.Context

/** A small explicit composition root. No reflection, networking or secret logs. */
interface HistoryServices {
    val records: HistoryRepository
    val preferences: HistoryPreferences
}

class OfflineHistoryServices(context:Context):HistoryServices {
    private val app=context.applicationContext
    override val records:HistoryRepository by lazy { HistoryRepository.create(app) }
    override val preferences:HistoryPreferences by lazy { HistoryPreferences(app) }
}

class SpDecodeApplication:Application() {
    val services:HistoryServices by lazy { OfflineHistoryServices(this) }
    override fun onCreate() {
        super.onCreate()
        // No Firebase initialization or token registration without prior opt-in.
        if(BuildConfig.SPDECODE_CLOUD_ENABLED)
            com.ghostdeveloper.spdecode.cloud.CloudCatalogUpdates.restoreOnProcessStart(this)
    }
}
